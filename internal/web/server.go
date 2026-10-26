// Package web contiene el servidor HTTP y la interfaz de la consola.
package web

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/subtle"
	"embed"
	"encoding/hex"
	"html/template"
	"io"
	"io/fs"
	"log"
	"mime/multipart"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"consola/internal/config"
	"consola/internal/modules/balanceador"
	"consola/internal/modules/preparacion"
	"consola/internal/modules/servicios"
	"consola/internal/modules/usuarios"
	"consola/internal/oplog"
)

//go:embed templates/*.html static/*
var assets embed.FS

const (
	mainTarget = "main"
	balTarget  = "haproxy" // VM del balanceador (opcional en config.json)
	maxUpload  = 300 << 20 // tamaño máximo de los archivos subidos en un despliegue
)

// Backend es lo que la interfaz necesita del gestor de canales.
type Backend interface {
	preparacion.KeyBackend
	Status(target string) (channel string, sshReady bool)
}

type Server struct {
	cfg   *config.Config
	back  Backend
	log   *oplog.Logger
	prep  *preparacion.Service
	usr   *usuarios.Service
	svc   *servicios.Service
	bal   *balanceador.Service // nil si config.json no define el objetivo «haproxy»
	pages map[string]*template.Template
	csrf  string
}

// PageData es lo que reciben las plantillas.
type PageData struct {
	Title    string
	CSRF     string
	Authors  string
	VMName   string
	IP       string
	Channel  string
	SSHReady bool

	Result         *preparacion.Outcome
	Package        string
	Hostname       string
	Logs           []oplog.Entry
	KeyExists      bool
	KeyFingerprint string
	Issue          preparacion.IssueOptions
	NewUser        usuarios.CreateOptions
	DelName        string
	DelFiles       bool
	UserKeys       []usuarios.KeyInfo
	Services       []servicios.Info
	ServicesError  string
	Deploy         servicios.DeployOptions
	DeployFile     string
	Actions        []string
	BalConfigured  bool
	BalChannel     string
	BalSSHReady    bool
	BalView        balanceador.View
	BalError       string
	BalIP          string
	Backend        struct {
		Name, IP string
		Port     int
	}
}

func New(cfg *config.Config, back Backend, log *oplog.Logger) (*Server, error) {
	token := make([]byte, 16)
	if _, err := rand.Read(token); err != nil {
		return nil, err
	}
	s := &Server{
		cfg:  cfg,
		back: back,
		log:  log,
		prep: preparacion.New(back, log, mainTarget, preparacion.Options{
			KeyDir:       filepath.Join(cfg.DataDir, "keys"),
			RootPassword: cfg.Targets[mainTarget].GuestPassword,
		}),
		usr:   usuarios.New(back, log, mainTarget, usuarios.Options{KeyDir: filepath.Join(cfg.DataDir, "keys")}),
		svc:   servicios.New(back, log, mainTarget),
		pages: map[string]*template.Template{},
		csrf:  hex.EncodeToString(token),
	}
	funcs := template.FuncMap{"fmtTime": func(t time.Time) string { return t.Format("15:04:05") }}
	if bt, ok := cfg.Targets[balTarget]; ok {
		s.bal = balanceador.New(back, log, balTarget, balanceador.Options{
			KeyPath:    filepath.Join(cfg.DataDir, "keys", mainTarget+"_root_ed25519"),
			BalancerIP: bt.IP,
			FrontPort:  80,
		})
	}
	for _, p := range []string{"home", "preparacion", "usuarios", "servicios", "balanceador", "pendiente"} {
		t, err := template.New("").Funcs(funcs).ParseFS(assets, "templates/layout.html", "templates/"+p+".html")
		if err != nil {
			return nil, err
		}
		s.pages[p] = t
	}
	return s, nil
}

func (s *Server) Handler() http.Handler {
	static, _ := fs.Sub(assets, "static")
	mux := http.NewServeMux()
	mux.HandleFunc("GET /{$}", s.handleHome)
	mux.HandleFunc("GET /preparacion", s.handlePrep)
	mux.HandleFunc("POST /preparacion/paquete", s.handlePackage)
	mux.HandleFunc("POST /preparacion/hostname", s.handleHostname)
	mux.HandleFunc("POST /preparacion/issue", s.handleIssue)
	mux.HandleFunc("POST /preparacion/llaves", s.handleKeys)
	mux.HandleFunc("POST /preparacion/llaves/descargar", s.handleKeyDownload)
	mux.HandleFunc("GET /usuarios", s.handleUsers)
	mux.HandleFunc("POST /usuarios/crear", s.handleUserCreate)
	mux.HandleFunc("POST /usuarios/eliminar", s.handleUserDelete)
	mux.HandleFunc("POST /usuarios/llaves/descargar", s.handleUserKeyDownload)
	mux.HandleFunc("GET /servicios", s.handleServices)
	mux.HandleFunc("POST /servicios/desplegar", s.handleDeploy)
	mux.HandleFunc("POST /servicios/accion", s.handleServiceAction)
	mux.HandleFunc("POST /servicios/eliminar", s.handleServiceRemove)
	mux.HandleFunc("GET /balanceador", s.handleBalancer)
	mux.HandleFunc("POST /balanceador/conectar", s.handleBalConnect)
	mux.HandleFunc("POST /balanceador/agregar", s.handleBalAdd)
	mux.HandleFunc("POST /balanceador/eliminar", s.handleBalRemove)
	mux.Handle("GET /static/", http.StripPrefix("/static/", http.FileServerFS(static)))
	return s.guard(mux)
}

// guard protege la consola: solo acepta Host local (anti DNS-rebinding),
// exige token CSRF en los POST y fija cabeceras de seguridad.
func (s *Server) guard(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !hostAllowed(r.Host) {
			http.Error(w, "host no permitido", http.StatusForbidden)
			return
		}
		h := w.Header()
		h.Set("X-Frame-Options", "DENY")
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Content-Security-Policy", "default-src 'none'; style-src 'self'; script-src 'self'; img-src 'self' data:; form-action 'self'; frame-ancestors 'none'; base-uri 'none'")
		if r.Method == http.MethodPost {
			if r.URL.Path == "/servicios/desplegar" {
				// Subida de archivos: el ejecutable puede pesar decenas de MB.
				r.Body = http.MaxBytesReader(w, r.Body, maxUpload)
				if err := r.ParseMultipartForm(8 << 20); err != nil {
					http.Error(w, "no se pudo leer el formulario: los archivos superan el máximo permitido ("+strconv.Itoa(maxUpload>>20)+" MB) o el envío está dañado", http.StatusRequestEntityTooLarge)
					return
				}
			} else {
				r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
				if err := r.ParseForm(); err != nil {
					http.Error(w, "formulario inválido", http.StatusBadRequest)
					return
				}
			}
			if subtle.ConstantTimeCompare([]byte(r.PostFormValue("csrf")), []byte(s.csrf)) != 1 {
				http.Error(w, "token CSRF inválido: recargue la página e intente de nuevo", http.StatusForbidden)
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}

func hostAllowed(hostport string) bool {
	host := hostport
	if h, _, err := net.SplitHostPort(hostport); err == nil {
		host = h
	}
	host = strings.Trim(host, "[]")
	return host == "localhost" || host == "127.0.0.1" || host == "::1"
}

func (s *Server) base(title string) PageData {
	ch, ready := s.back.Status(mainTarget)
	t := s.cfg.Targets[mainTarget]
	return PageData{Title: title, CSRF: s.csrf, Authors: s.cfg.Authors, VMName: t.VMName, IP: t.IP, Channel: ch, SSHReady: ready}
}

func (s *Server) render(w http.ResponseWriter, page string, d PageData) {
	var buf bytes.Buffer
	if err := s.pages[page].ExecuteTemplate(&buf, "layout.html", d); err != nil {
		log.Printf("plantilla %s: %v", page, err)
		http.Error(w, "error interno al generar la página", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	_, _ = buf.WriteTo(w)
}

func (s *Server) handleHome(w http.ResponseWriter, r *http.Request) {
	s.render(w, "home", s.base("Inicio"))
}

func (s *Server) handlePending(title string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		s.render(w, "pendiente", s.base(title))
	}
}

func (s *Server) prepPage(out *preparacion.Outcome, pkg, host string) PageData {
	d := s.base("Preparación del sistema")
	d.Result, d.Package, d.Hostname = out, pkg, host
	d.Issue = preparacion.DefaultIssueOptions()
	d.Logs = s.log.Recent(8)
	ks := s.prep.KeyStatus()
	d.KeyExists, d.KeyFingerprint = ks.Exists, ks.Fingerprint
	return d
}

func (s *Server) handlePrep(w http.ResponseWriter, r *http.Request) {
	s.render(w, "preparacion", s.prepPage(nil, "", ""))
}

// Las operaciones no se cancelan si el navegador se cierra: interrumpir apt a
// medias dejaría la VM con dpkg a medio configurar.
func detached(r *http.Request) context.Context { return context.WithoutCancel(r.Context()) }

func (s *Server) handlePackage(w http.ResponseWriter, r *http.Request) {
	name := strings.TrimSpace(r.PostFormValue("name"))
	var out preparacion.Outcome
	switch r.PostFormValue("action") {
	case "install":
		out = s.prep.InstallPackage(detached(r), name)
	case "remove":
		out = s.prep.RemovePackage(detached(r), name)
	default:
		http.Error(w, "acción no válida", http.StatusBadRequest)
		return
	}
	s.render(w, "preparacion", s.prepPage(&out, name, ""))
}

// handleKeys ejecuta 3.1.2: crear la llave de root, instalarla y bloquear la contraseña.
func (s *Server) handleKeys(w http.ResponseWriter, r *http.Request) {
	out := s.prep.ConfigureRootKey(detached(r))
	s.render(w, "preparacion", s.prepPage(&out, "", ""))
}

// handleKeyDownload entrega la llave privada como archivo. Es POST con token
// CSRF para que otra página no pueda provocar la descarga.
func (s *Server) handleKeyDownload(w http.ResponseWriter, r *http.Request) {
	name, data, err := s.prep.PrivateKeyForDownload()
	if err != nil {
		out := preparacion.Outcome{Title: "No se pudo descargar la llave", Message: err.Error()}
		s.render(w, "preparacion", s.prepPage(&out, "", ""))
		return
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", `attachment; filename="`+name+`"`)
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write(data)
}

func (s *Server) handleHostname(w http.ResponseWriter, r *http.Request) {
	host := strings.TrimSpace(r.PostFormValue("hostname"))
	out := s.prep.SetHostname(detached(r), host)
	s.render(w, "preparacion", s.prepPage(&out, "", host))
}

// handleIssue ejecuta 3.1.3: escribe /etc/issue según las casillas y el mensaje.
// Tras el envío se conservan los valores del formulario.
func (s *Server) handleIssue(w http.ResponseWriter, r *http.Request) {
	on := func(name string) bool { return r.PostFormValue(name) == "1" }
	o := preparacion.IssueOptions{
		Host: on("host"), Date: on("date"), Time: on("time"), IP: on("ip"),
		OS: on("os"), Kernel: on("kernel"), Arch: on("arch"), TTY: on("tty"), Users: on("users"),
		Message: strings.TrimSpace(r.PostFormValue("message")),
	}
	out := s.prep.ApplyIssue(detached(r), o)
	d := s.prepPage(&out, "", "")
	d.Issue = o
	s.render(w, "preparacion", d)
}

func (s *Server) usersPage(out *preparacion.Outcome) PageData {
	d := s.base("Gestión de usuarios")
	d.Result = out
	d.Logs = s.log.Recent(8)
	d.UserKeys = s.usr.Keys()
	d.DelFiles = true // por omisión se elimina también el home (indicación del profesor)
	return d
}

func (s *Server) handleUsers(w http.ResponseWriter, r *http.Request) {
	s.render(w, "usuarios", s.usersPage(nil))
}

// handleUserCreate ejecuta 3.2.1.
func (s *Server) handleUserCreate(w http.ResponseWriter, r *http.Request) {
	o := usuarios.CreateOptions{
		Name:   strings.TrimSpace(r.PostFormValue("name")),
		Sudo:   r.PostFormValue("sudo") == "1",
		GenKey: r.PostFormValue("genkey") == "1",
		// Sin TrimSpace: los espacios son parte válida de una contraseña.
		Password: r.PostFormValue("password"),
	}
	out := s.usr.CreateUser(detached(r), o)
	d := s.usersPage(&out)
	if !out.OK {
		o.Password = "" // nunca se devuelve la contraseña al navegador
		d.NewUser = o   // conserva el formulario para corregirlo
	}
	s.render(w, "usuarios", d)
}

// handleUserDelete ejecuta 3.2.2.
func (s *Server) handleUserDelete(w http.ResponseWriter, r *http.Request) {
	name := strings.TrimSpace(r.PostFormValue("name"))
	files := r.PostFormValue("rmfiles") == "1"
	out := s.usr.DeleteUser(detached(r), name, files)
	d := s.usersPage(&out)
	if !out.OK {
		d.DelName, d.DelFiles = name, files
	}
	s.render(w, "usuarios", d)
}

// handleUserKeyDownload entrega la llave privada de un usuario (POST + CSRF).
func (s *Server) handleUserKeyDownload(w http.ResponseWriter, r *http.Request) {
	name, data, err := s.usr.PrivateKeyForDownload(strings.TrimSpace(r.PostFormValue("name")))
	if err != nil {
		out := preparacion.Outcome{Title: "No se pudo descargar la llave", Message: err.Error()}
		s.render(w, "usuarios", s.usersPage(&out))
		return
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", `attachment; filename="`+name+`"`)
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write(data)
}

func (s *Server) servicesPage(out *preparacion.Outcome) PageData {
	d := s.base("Gestión de servicios")
	d.Result = out
	d.Logs = s.log.Recent(8)
	d.Actions = servicios.Actions
	d.Deploy.Kind = servicios.KindSimple
	list, err := s.svc.List(context.Background())
	if err != nil {
		d.ServicesError = err.Error()
	}
	d.Services = list
	return d
}

func (s *Server) handleServices(w http.ResponseWriter, r *http.Request) {
	s.render(w, "servicios", s.servicesPage(nil))
}

// saveUpload copia un archivo subido a un temporal del host y devuelve su ruta.
func saveUpload(dir, pattern string, fh *multipart.FileHeader) (string, error) {
	src, err := fh.Open()
	if err != nil {
		return "", err
	}
	defer src.Close()
	dst, err := os.CreateTemp(dir, pattern)
	if err != nil {
		return "", err
	}
	if _, err := io.Copy(dst, src); err != nil {
		dst.Close()
		os.Remove(dst.Name())
		return "", err
	}
	return dst.Name(), dst.Close()
}

func firstFile(r *http.Request, field string) *multipart.FileHeader {
	if r.MultipartForm == nil {
		return nil
	}
	if fs := r.MultipartForm.File[field]; len(fs) > 0 && fs[0].Filename != "" {
		return fs[0]
	}
	return nil
}

// handleDeploy ejecuta 3.3: sube el ejecutable (y archivos extra) y crea el servicio.
func (s *Server) handleDeploy(w http.ResponseWriter, r *http.Request) {
	o := servicios.DeployOptions{
		Name: strings.TrimSpace(r.PostFormValue("name")),
		Kind: r.PostFormValue("kind"),
		Args: strings.TrimSpace(r.PostFormValue("args")),
	}
	show := func(out preparacion.Outcome) {
		d := s.servicesPage(&out)
		if !out.OK {
			d.Deploy = o
			d.Deploy.ExecPath, d.Deploy.ExtraPath = "", ""
		}
		s.render(w, "servicios", d)
	}
	tmp, err := os.MkdirTemp(filepath.Join(s.cfg.DataDir), "subida-")
	if err != nil {
		show(preparacion.Outcome{Title: "No se pudo recibir el archivo", Message: "No se pudo crear una carpeta temporal en data/.", Detail: err.Error()})
		return
	}
	defer os.RemoveAll(tmp)

	fh := firstFile(r, "exec")
	if fh == nil {
		show(preparacion.Outcome{Title: "Datos no válidos", Message: "Seleccione el archivo ejecutable de la aplicación."})
		return
	}
	o.ExecName = filepath.Base(fh.Filename)
	if o.ExecPath, err = saveUpload(tmp, "exec-*", fh); err != nil {
		show(preparacion.Outcome{Title: "No se pudo recibir el archivo", Message: "Falló la lectura del ejecutable subido.", Detail: err.Error()})
		return
	}
	if ef := firstFile(r, "extra"); ef != nil {
		raw, err := saveUpload(tmp, "extra-*", ef)
		if err != nil {
			show(preparacion.Outcome{Title: "No se pudo recibir el archivo", Message: "Falló la lectura de los archivos adicionales.", Detail: err.Error()})
			return
		}
		o.ExtraPath = filepath.Join(tmp, "extra.tgz")
		if err := servicios.PackExtras(raw, ef.Filename, o.ExtraPath); err != nil {
			show(preparacion.Outcome{Title: "Archivos adicionales no válidos", Message: err.Error()})
			return
		}
	}
	show(s.svc.Deploy(detached(r), o))
}

func (s *Server) handleServiceAction(w http.ResponseWriter, r *http.Request) {
	out := s.svc.Act(detached(r), r.PostFormValue("name"), r.PostFormValue("action"))
	s.render(w, "servicios", s.servicesPage(&out))
}

func (s *Server) handleServiceRemove(w http.ResponseWriter, r *http.Request) {
	out := s.svc.Remove(detached(r), r.PostFormValue("name"), r.PostFormValue("rmfiles") == "1")
	s.render(w, "servicios", s.servicesPage(&out))
}

func (s *Server) balancerPage(out *preparacion.Outcome) PageData {
	d := s.base("Balanceador de carga")
	d.Result = out
	d.Logs = s.log.Recent(8)
	d.Backend.Port = 80
	if s.bal == nil {
		return d
	}
	d.BalConfigured = true
	d.BalIP = s.cfg.Targets[balTarget].IP
	d.BalChannel, d.BalSSHReady = s.back.Status(balTarget)
	v, err := s.bal.State(context.Background())
	if err != nil {
		d.BalError = err.Error()
	}
	d.BalView = v
	return d
}

func (s *Server) handleBalancer(w http.ResponseWriter, r *http.Request) {
	s.render(w, "balanceador", s.balancerPage(nil))
}

func (s *Server) balNotConfigured(w http.ResponseWriter) bool {
	if s.bal != nil {
		return false
	}
	out := preparacion.Outcome{Title: "Balanceador no configurado", Message: "Agregue el objetivo «haproxy» en la sección targets de config.json (vmName, ip, sshPort, guestUser, guestPassword) y reinicie la consola."}
	s.render(w, "balanceador", s.balancerPage(&out))
	return true
}

func (s *Server) handleBalConnect(w http.ResponseWriter, r *http.Request) {
	if s.balNotConfigured(w) {
		return
	}
	out := s.bal.ConnectSSH(detached(r))
	s.render(w, "balanceador", s.balancerPage(&out))
}

func (s *Server) handleBalAdd(w http.ResponseWriter, r *http.Request) {
	if s.balNotConfigured(w) {
		return
	}
	name := strings.TrimSpace(r.PostFormValue("name"))
	ip := strings.TrimSpace(r.PostFormValue("ip"))
	port, err := strconv.Atoi(strings.TrimSpace(r.PostFormValue("port")))
	var out preparacion.Outcome
	if err != nil {
		out = preparacion.Outcome{Title: "Datos no válidos", Message: "El puerto debe ser un número entre 1 y 65535."}
	} else {
		out = s.bal.AddServer(detached(r), name, ip, port)
	}
	d := s.balancerPage(&out)
	if !out.OK {
		d.Backend.Name, d.Backend.IP = name, ip
		if err == nil {
			d.Backend.Port = port
		}
	}
	s.render(w, "balanceador", d)
}

func (s *Server) handleBalRemove(w http.ResponseWriter, r *http.Request) {
	if s.balNotConfigured(w) {
		return
	}
	out := s.bal.RemoveServer(detached(r), r.PostFormValue("name"))
	s.render(w, "balanceador", s.balancerPage(&out))
}
