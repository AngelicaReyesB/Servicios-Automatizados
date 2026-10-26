package web

import (
	"context"
	"errors"
	"html"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"consola/internal/config"
	"consola/internal/oplog"
	"consola/internal/runner"
	"consola/internal/sshkey"
)

type fakeRunner struct {
	scripts []string
	uploads []string
	stdout  string
	respond func(script string) runner.Result
}

func (f *fakeRunner) Name() string { return "Guest Additions (fake)" }
func (f *fakeRunner) Run(_ context.Context, s string) (runner.Result, error) {
	f.scripts = append(f.scripts, s)
	if f.respond != nil {
		return f.respond(s), nil
	}
	return runner.Result{Stdout: f.stdout}, nil
}
func (f *fakeRunner) RunInput(context.Context, string, string) (runner.Result, error) {
	return runner.Result{}, runner.ErrNotSupported
}
func (f *fakeRunner) Upload(_ context.Context, local, remote string, _ os.FileMode) error {
	b, _ := os.ReadFile(local)
	f.uploads = append(f.uploads, remote+":"+string(b))
	return nil
}

type fakeBackend struct{ r *fakeRunner }

func (b fakeBackend) Get(string) (runner.Runner, error) { return b.r, nil }
func (b fakeBackend) Status(string) (string, bool)      { return runner.ChannelGuest, false }
func (b fakeBackend) SSHFor(string, string) (runner.KeyProber, error) {
	return nil, errors.New("no hay SSH en esta prueba")
}
func (b fakeBackend) MarkSSHReady(string, string) error { return nil }

func newTestServer(t *testing.T) (*Server, *fakeRunner) { return newTestServerBal(t, true) }

func newTestServerBal(t *testing.T, withBal bool) (*Server, *fakeRunner) {
	t.Helper()
	log, err := oplog.New(filepath.Join(t.TempDir(), "ops.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { log.Close() })
	fr := &fakeRunner{}
	cfg := &config.Config{DataDir: t.TempDir(), Authors: "Autor Uno - Autor Dos", Targets: map[string]config.Target{"main": {VMName: "vm-test", IP: "192.168.1.10"}}}
	if withBal {
		cfg.Targets["haproxy"] = config.Target{VMName: "vm-lb", IP: "192.168.1.6"}
	}
	s, err := New(cfg, fakeBackend{fr}, log)
	if err != nil {
		t.Fatal(err)
	}
	return s, fr
}

func do(s *Server, method, path, host string, form url.Values) *httptest.ResponseRecorder {
	var req *http.Request
	if form != nil {
		req = httptest.NewRequest(method, path, strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	} else {
		req = httptest.NewRequest(method, path, nil)
	}
	req.Host = host
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, req)
	return rec
}

func TestPagesRender(t *testing.T) {
	s, _ := newTestServer(t)
	for path, want := range map[string]string{
		"/":                 "Preparación del sistema",
		"/preparacion":      "Asignar nombre de host",
		"/usuarios":         "Gestión de usuarios",
		"/static/style.css": "--green",
	} {
		rec := do(s, "GET", path, "localhost:8080", nil)
		if rec.Code != 200 || !strings.Contains(rec.Body.String(), want) {
			t.Errorf("GET %s: código %d, esperaba %q", path, rec.Code, want)
		}
	}
	if rec := do(s, "GET", "/", "localhost:8080", nil); !strings.Contains(rec.Body.String(), "Autor Uno - Autor Dos") {
		t.Error("el pie debe mostrar los autores de config.json")
	}
}

func TestForeignHostRejected(t *testing.T) {
	s, _ := newTestServer(t)
	if rec := do(s, "GET", "/", "evil.example.com", nil); rec.Code != http.StatusForbidden {
		t.Errorf("host ajeno debía dar 403, dio %d", rec.Code)
	}
}

func TestPostWithoutCSRFRejected(t *testing.T) {
	s, fr := newTestServer(t)
	rec := do(s, "POST", "/preparacion/paquete", "localhost:8080", url.Values{"name": {"htop"}, "action": {"install"}})
	if rec.Code != http.StatusForbidden || len(fr.scripts) != 0 {
		t.Errorf("sin CSRF debía dar 403 y no ejecutar nada (código %d, scripts %d)", rec.Code, len(fr.scripts))
	}
}

func TestInvalidInputShowsMessageAndDoesNotExecute(t *testing.T) {
	s, fr := newTestServer(t)
	rec := do(s, "POST", "/preparacion/hostname", "localhost:8080", url.Values{"csrf": {s.csrf}, "hostname": {"app_web1"}})
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), "guion bajo") || len(fr.scripts) != 0 {
		t.Errorf("código %d, scripts %d", rec.Code, len(fr.scripts))
	}
}

func TestValidInstallExecutesAndReportsSuccess(t *testing.T) {
	s, fr := newTestServer(t)
	rec := do(s, "POST", "/preparacion/paquete", "localhost:8080", url.Values{"csrf": {s.csrf}, "name": {"htop"}, "action": {"install"}})
	body := rec.Body.String()
	if rec.Code != 200 || len(fr.scripts) != 1 || !strings.Contains(body, "instalado correctamente") {
		t.Errorf("código %d, scripts %d", rec.Code, len(fr.scripts))
	}
	if !strings.Contains(body, "Registro de operaciones") || !strings.Contains(body, "Instalar paquete htop") {
		t.Error("la operación debe aparecer en el registro")
	}
}

func TestKeyPanelShowsAdviceAndDisablesDownloadWithoutKey(t *testing.T) {
	s, _ := newTestServer(t)
	body := do(s, "GET", "/preparacion", "localhost:8080", nil).Body.String()
	for _, want := range []string{
		"Generar y configurar llaves SSH",
		"Uso correcto de la llave privada",
		"ssh -i id_ed25519_root root@192.168.1.10",
		"chmod 600",
		"icacls",
		"disabled>Descargar",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("la página no contiene %q", want)
		}
	}
	if strings.Contains(body, "Llave configurada") {
		t.Error("sin llave no debe decir que está configurada")
	}
}

// writeKey simula una llave ya configurada en el host.
func writeKey(t *testing.T, s *Server) (priv string, fingerprint string) {
	t.Helper()
	pair, err := sshkey.Generate("consola-root")
	if err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(s.cfg.DataDir, "keys")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "main_root_ed25519")
	if err := os.WriteFile(path, pair.PrivatePEM, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path+".pub", []byte(pair.Authorized+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	return string(pair.PrivatePEM), pair.Fingerprint
}

func TestKeyDownload(t *testing.T) {
	s, _ := newTestServer(t)
	priv, fp := writeKey(t, s)

	if rec := do(s, "POST", "/preparacion/llaves/descargar", "localhost:8080", url.Values{}); rec.Code != http.StatusForbidden {
		t.Errorf("sin token CSRF debía dar 403, dio %d", rec.Code)
	}
	if rec := do(s, "GET", "/preparacion/llaves/descargar", "localhost:8080", nil); rec.Code == http.StatusOK && strings.Contains(rec.Body.String(), "BEGIN OPENSSH") {
		t.Error("la llave no debe poder descargarse con GET")
	}

	rec := do(s, "POST", "/preparacion/llaves/descargar", "localhost:8080", url.Values{"csrf": {s.csrf}})
	if rec.Code != 200 || rec.Body.String() != priv {
		t.Fatalf("descarga incorrecta: código %d", rec.Code)
	}
	if cd := rec.Header().Get("Content-Disposition"); cd != `attachment; filename="id_ed25519_root"` {
		t.Errorf("Content-Disposition = %q", cd)
	}
	if rec.Header().Get("Cache-Control") != "no-store" {
		t.Error("la llave no debe guardarse en caché")
	}

	body := do(s, "GET", "/preparacion", "localhost:8080", nil).Body.String()
	if !strings.Contains(body, "Llave configurada") {
		t.Error("con llave, la página debe decir que está configurada")
	}
	// html/template escribe algunos caracteres de la huella como entidades (p. ej. "+" → &#43;);
	// el navegador los muestra normales, así que se compara contra el HTML des-escapado.
	if !strings.Contains(html.UnescapeString(body), fp) {
		t.Errorf("la página debe mostrar la huella %s", fp)
	}
	if strings.Contains(body, "disabled>Descargar") {
		t.Error("con llave, la descarga debe estar habilitada")
	}
	if !strings.Contains(body, "Si genera otra, la anterior dejará de funcionar") {
		t.Error("debe pedir confirmación antes de regenerar una llave existente")
	}
}

func TestKeyDownloadWithoutKeyShowsMessage(t *testing.T) {
	s, _ := newTestServer(t)
	rec := do(s, "POST", "/preparacion/llaves/descargar", "localhost:8080", url.Values{"csrf": {s.csrf}})
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), "todavía no se ha generado la llave") {
		t.Errorf("código %d", rec.Code)
	}
}

func TestKeyGenerationRouteIsWired(t *testing.T) {
	s, fr := newTestServer(t)
	if rec := do(s, "POST", "/preparacion/llaves", "localhost:8080", url.Values{}); rec.Code != http.StatusForbidden {
		t.Errorf("sin token CSRF debía dar 403, dio %d", rec.Code)
	}
	if len(fr.scripts) != 0 {
		t.Fatal("sin CSRF no debe ejecutarse nada")
	}

	// Con el SSH de prueba caído, el flujo debe ejecutar el primer paso y detenerse con un mensaje claro.
	rec := do(s, "POST", "/preparacion/llaves", "localhost:8080", url.Values{"csrf": {s.csrf}})
	body := rec.Body.String()
	if rec.Code != 200 || len(fr.scripts) != 1 || !strings.Contains(fr.scripts[0], "PermitRootLogin prohibit-password") {
		t.Fatalf("código %d, scripts %d", rec.Code, len(fr.scripts))
	}
	if !strings.Contains(body, "No se pudo preparar la conexión SSH") {
		t.Error("debe informar el fallo de forma comprensible")
	}
	if strings.Contains(body, "PRIVATE KEY") {
		t.Error("la página nunca debe mostrar la llave privada")
	}
}

func TestIssuePanelDefaults(t *testing.T) {
	s, _ := newTestServer(t)
	body := do(s, "GET", "/preparacion", "localhost:8080", nil).Body.String()
	if !strings.Contains(body, `action="/preparacion/issue"`) || strings.Contains(body, "Pendiente de implementar (3.1.3)") {
		t.Fatal("el panel 3.1.3 debe estar habilitado")
	}
	for _, n := range []string{"host", "date", "time", "ip"} {
		if !strings.Contains(body, `name="`+n+`" value="1" checked`) {
			t.Errorf("la casilla %s debe venir marcada", n)
		}
	}
	if strings.Contains(body, `name="kernel" value="1" checked`) {
		t.Error("kernel no debe venir marcada")
	}
}

func TestIssueRequiresCSRF(t *testing.T) {
	s, fr := newTestServer(t)
	rec := do(s, "POST", "/preparacion/issue", "localhost:8080", url.Values{"host": {"1"}})
	if rec.Code != http.StatusForbidden || len(fr.scripts) != 0 {
		t.Errorf("código %d, scripts %d", rec.Code, len(fr.scripts))
	}
}

func TestIssueValidExecutesAndKeepsForm(t *testing.T) {
	s, fr := newTestServer(t)
	rec := do(s, "POST", "/preparacion/issue", "localhost:8080", url.Values{
		"csrf": {s.csrf}, "host": {"1"}, "kernel": {"1"}, "message": {"Solo personal autorizado"}})
	body := rec.Body.String()
	if rec.Code != 200 || len(fr.scripts) != 1 || !strings.Contains(body, "Operación completada") {
		t.Fatalf("código %d, scripts %d", rec.Code, len(fr.scripts))
	}
	if !strings.Contains(body, `name="kernel" value="1" checked`) || strings.Contains(body, `name="date" value="1" checked`) ||
		!strings.Contains(body, `value="Solo personal autorizado"`) {
		t.Error("el formulario debe conservar lo enviado")
	}
}

func TestIssueInvalidDoesNotExecute(t *testing.T) {
	s, fr := newTestServer(t)
	for _, f := range []url.Values{
		{"csrf": {s.csrf}},
		{"csrf": {s.csrf}, "host": {"1"}, "message": {"a\x1b[31m"}},
		{"csrf": {s.csrf}, "host": {"1"}, "message": {strings.Repeat("x", 300)}},
	} {
		rec := do(s, "POST", "/preparacion/issue", "localhost:8080", f)
		if rec.Code != 200 || !strings.Contains(rec.Body.String(), "Datos no válidos") {
			t.Errorf("%v → código %d", f, rec.Code)
		}
	}
	if len(fr.scripts) != 0 {
		t.Fatal("no debía ejecutarse nada")
	}
}

func TestUsersPageHasForms(t *testing.T) {
	s, _ := newTestServer(t)
	body := do(s, "GET", "/usuarios", "localhost:8080", nil).Body.String()
	for _, want := range []string{`action="/usuarios/crear"`, `action="/usuarios/eliminar"`, `name="sudo"`, `name="genkey"`, `name="rmfiles"`, `type="password" name="password"`, "Aún no hay llaves de usuarios"} {
		if !strings.Contains(body, want) {
			t.Errorf("falta %q", want)
		}
	}
}

func TestDeleteFilesCheckedByDefault(t *testing.T) {
	s, _ := newTestServer(t)
	body := do(s, "GET", "/usuarios", "localhost:8080", nil).Body.String()
	if !strings.Contains(body, `name="rmfiles" value="1" checked`) {
		t.Error("la casilla de eliminar archivos debe venir marcada")
	}
}

func TestUserRoutesRequireCSRF(t *testing.T) {
	s, fr := newTestServer(t)
	for _, p := range []string{"/usuarios/crear", "/usuarios/eliminar", "/usuarios/llaves/descargar"} {
		if rec := do(s, "POST", p, "localhost:8080", url.Values{"name": {"ana"}}); rec.Code != http.StatusForbidden {
			t.Errorf("%s sin CSRF → %d", p, rec.Code)
		}
	}
	if len(fr.scripts) != 0 {
		t.Fatal("no debía ejecutarse nada")
	}
}

func TestUserCreateWithKeyOffersDownloadAndListsKey(t *testing.T) {
	s, fr := newTestServer(t)
	rec := do(s, "POST", "/usuarios/crear", "localhost:8080", url.Values{"csrf": {s.csrf}, "name": {"ana"}, "sudo": {"1"}, "genkey": {"1"}})
	body := rec.Body.String()
	if rec.Code != 200 || len(fr.scripts) != 1 || !strings.Contains(body, "Operación completada") {
		t.Fatalf("código %d scripts %d", rec.Code, len(fr.scripts))
	}
	if !strings.Contains(body, "Descargar llave privada de ana") || !strings.Contains(body, `<code>SHA256:`) {
		t.Error("debe ofrecer la descarga y listar la llave")
	}
	dl := do(s, "POST", "/usuarios/llaves/descargar", "localhost:8080", url.Values{"csrf": {s.csrf}, "name": {"ana"}})
	if dl.Code != 200 || !strings.Contains(dl.Header().Get("Content-Disposition"), "id_ed25519_ana") || !strings.Contains(dl.Body.String(), "OPENSSH PRIVATE KEY") {
		t.Errorf("descarga: %d %v", dl.Code, dl.Header())
	}
	del := do(s, "POST", "/usuarios/eliminar", "localhost:8080", url.Values{"csrf": {s.csrf}, "name": {"ana"}, "rmfiles": {"1"}})
	if !strings.Contains(del.Body.String(), "eliminado") || strings.Contains(del.Body.String(), `<code>SHA256:`) {
		t.Error("al eliminar, la llave local debe desaparecer del listado")
	}
}

func TestUserInvalidInputAndDownloadErrors(t *testing.T) {
	s, fr := newTestServer(t)
	rec := do(s, "POST", "/usuarios/crear", "localhost:8080", url.Values{"csrf": {s.csrf}, "name": {"Mal Nombre"}, "sudo": {"1"}})
	if !strings.Contains(rec.Body.String(), "Datos no válidos") || !strings.Contains(rec.Body.String(), `value="Mal Nombre"`) {
		t.Error("debe rechazar y conservar el formulario")
	}
	rec = do(s, "POST", "/usuarios/eliminar", "localhost:8080", url.Values{"csrf": {s.csrf}, "name": {"root"}})
	if !strings.Contains(rec.Body.String(), "bloqueada") {
		t.Error("root no se elimina")
	}
	rec = do(s, "POST", "/usuarios/llaves/descargar", "localhost:8080", url.Values{"csrf": {s.csrf}, "name": {"nadie"}})
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), "No se pudo descargar") {
		t.Error("sin llave debe explicar")
	}
	if len(fr.scripts) != 0 {
		t.Fatal("no debía ejecutarse nada")
	}
}

func multipartBody(t *testing.T, fields map[string]string, files map[string][2]string) (string, *strings.Reader) {
	t.Helper()
	var b strings.Builder
	w := multipart.NewWriter(&b)
	for k, v := range fields {
		_ = w.WriteField(k, v)
	}
	for field, nf := range files {
		fw, _ := w.CreateFormFile(field, nf[0])
		_, _ = fw.Write([]byte(nf[1]))
	}
	w.Close()
	return w.FormDataContentType(), strings.NewReader(b.String())
}

func postMultipart(s *Server, path string, fields map[string]string, files map[string][2]string, t *testing.T) *httptest.ResponseRecorder {
	ct, body := multipartBody(t, fields, files)
	req := httptest.NewRequest("POST", path, body)
	req.Header.Set("Content-Type", ct)
	req.Host = "localhost:8080"
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, req)
	return rec
}

func TestServicesPageRendersAndListsManaged(t *testing.T) {
	s, fr := newTestServer(t)
	fr.stdout = "SVC\tcatalogo\tactive\tenabled\n"
	body := do(s, "GET", "/servicios", "localhost:8080", nil).Body.String()
	for _, want := range []string{`action="/servicios/desplegar"`, `enctype="multipart/form-data"`, "catalogo", `value="restart"`, `value="status"`, `value="enable"`, `value="disable"`, `value="start"`, `value="stop"`, `action="/servicios/eliminar"`} {
		if !strings.Contains(body, want) {
			t.Errorf("falta %q", want)
		}
	}
}

func TestServiceRoutesRequireCSRF(t *testing.T) {
	s, fr := newTestServer(t)
	for _, p := range []string{"/servicios/accion", "/servicios/eliminar"} {
		if rec := do(s, "POST", p, "localhost:8080", url.Values{"name": {"x"}, "action": {"start"}}); rec.Code != http.StatusForbidden {
			t.Errorf("%s → %d", p, rec.Code)
		}
	}
	rec := postMultipart(s, "/servicios/desplegar", map[string]string{"name": "catalogo"}, map[string][2]string{"exec": {"catalogo", "\x7fELFxxxx"}}, t)
	if rec.Code != http.StatusForbidden {
		t.Errorf("desplegar sin CSRF → %d", rec.Code)
	}
	if len(fr.scripts) != 0 || len(fr.uploads) != 0 {
		t.Fatal("no debía tocarse la VM (ni siquiera para listar)")
	}
}

func TestDeployThroughWeb(t *testing.T) {
	s, fr := newTestServer(t)
	rec := postMultipart(s, "/servicios/desplegar",
		map[string]string{"csrf": s.csrf, "name": "catalogo", "kind": "simple", "args": "-port 8080"},
		map[string][2]string{"exec": {"catalogo", "\x7fELFxxxx"}}, t)
	body := rec.Body.String()
	if rec.Code != 200 || !strings.Contains(body, "desplegado") {
		t.Fatalf("código %d\n%s", rec.Code, body)
	}
	if len(fr.uploads) != 1 || fr.uploads[0] != "/tmp/consola-catalogo.bin:\x7fELFxxxx" {
		t.Errorf("subidas: %v", fr.uploads)
	}
	if ents, _ := os.ReadDir(s.cfg.DataDir); len(ents) != 0 {
		t.Errorf("deben limpiarse los temporales de subida: %v", ents)
	}
}

func TestDeployRejectsBadInputsWithoutTouchingVM(t *testing.T) {
	s, fr := newTestServer(t)
	cases := []struct {
		name   string
		fields map[string]string
		files  map[string][2]string
		want   string
	}{
		{"sin archivo", map[string]string{"name": "catalogo", "kind": "simple"}, nil, "Seleccione el archivo"},
		{"exe de Windows", map[string]string{"name": "catalogo", "kind": "simple"}, map[string][2]string{"exec": {"app.exe", "MZ\x90"}}, "Windows"},
		{"nombre inválido", map[string]string{"name": "Mi App", "kind": "simple"}, map[string][2]string{"exec": {"a", "#!/bin/sh"}}, "nombre de servicio inválido"},
		{"extra inválido", map[string]string{"name": "catalogo", "kind": "simple"}, map[string][2]string{"exec": {"a", "#!/bin/sh"}, "extra": {"x.rar", "Rar!"}}, "deben subirse como"},
		{"extra no es zip", map[string]string{"name": "catalogo", "kind": "simple"}, map[string][2]string{"exec": {"a", "#!/bin/sh"}, "extra": {"x.zip", "no zip"}}, "Archivos adicionales no válidos"},
	}
	for _, c := range cases {
		c.fields["csrf"] = s.csrf
		rec := postMultipart(s, "/servicios/desplegar", c.fields, c.files, t)
		if rec.Code != 200 || !strings.Contains(rec.Body.String(), c.want) {
			t.Errorf("%s: código %d, falta %q", c.name, rec.Code, c.want)
		}
	}
	// La página sí consulta la lista de servicios; lo que no debe ocurrir es desplegar.
	for _, sc := range fr.scripts {
		if strings.Contains(sc, "useradd") {
			t.Fatal("no debía desplegarse nada")
		}
	}
	if len(fr.uploads) != 0 {
		t.Fatal("no debía subirse nada")
	}
}

func TestServiceActionAndRemoveThroughWeb(t *testing.T) {
	s, fr := newTestServer(t)
	rec := do(s, "POST", "/servicios/accion", "localhost:8080", url.Values{"csrf": {s.csrf}, "name": {"catalogo"}, "action": {"restart"}})
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), "reiniciado") {
		t.Errorf("acción: %d", rec.Code)
	}
	rec = do(s, "POST", "/servicios/accion", "localhost:8080", url.Values{"csrf": {s.csrf}, "name": {"catalogo"}, "action": {"mask"}})
	if !strings.Contains(rec.Body.String(), "Datos no válidos") {
		t.Error("una acción desconocida debe rechazarse")
	}
	rec = do(s, "POST", "/servicios/eliminar", "localhost:8080", url.Values{"csrf": {s.csrf}, "name": {"catalogo"}, "rmfiles": {"1"}})
	if !strings.Contains(rec.Body.String(), "eliminado de systemd") {
		t.Error("eliminar")
	}
	_ = fr
}

const lbBase = "global\n    daemon\n\ndefaults\n    mode http\n"

func lbResponder(cfg string) func(string) runner.Result {
	return func(script string) runner.Result {
		if strings.Contains(script, "EXPECT=") {
			return runner.Result{Stdout: "--- verificación ---\nestado: active\n"}
		}
		return runner.Result{Stdout: "estado: active\nversión: HAProxy version 3.0.11\n--- configuración ---\n" + cfg}
	}
}

func TestBalancerPageShowsServersAndForms(t *testing.T) {
	s, fr := newTestServer(t)
	fr.respond = lbResponder(lbBase + "# BEGIN consola-automatizacion (no editar a mano)\nfrontend consola_front\n    bind *:80\n    default_backend consola_back\n\nbackend consola_back\n    balance roundrobin\n    server web1 192.168.1.20:80 check\n# END consola-automatizacion\n")
	body := do(s, "GET", "/balanceador", "localhost:8080", nil).Body.String()
	for _, want := range []string{`action="/balanceador/agregar"`, `action="/balanceador/eliminar"`, `action="/balanceador/conectar"`, "web1", "192.168.1.20:80", "HAProxy version 3.0.11", "192.168.1.6"} {
		if !strings.Contains(body, want) {
			t.Errorf("falta %q", want)
		}
	}
}

func TestBalancerNotConfigured(t *testing.T) {
	s, fr := newTestServerBal(t, false)
	if body := do(s, "GET", "/balanceador", "localhost:8080", nil).Body.String(); !strings.Contains(body, "necesita el objetivo") {
		t.Error("debe explicar cómo configurarlo")
	}
	for _, p := range []string{"/balanceador/agregar", "/balanceador/eliminar", "/balanceador/conectar"} {
		rec := do(s, "POST", p, "localhost:8080", url.Values{"csrf": {s.csrf}, "name": {"w"}, "ip": {"10.0.0.1"}, "port": {"80"}})
		if rec.Code != 200 || !strings.Contains(rec.Body.String(), "Balanceador no configurado") {
			t.Errorf("%s → %d", p, rec.Code)
		}
	}
	if len(fr.scripts) != 0 {
		t.Fatal("no debía tocarse ninguna VM")
	}
}

func TestBalancerRoutesRequireCSRF(t *testing.T) {
	s, fr := newTestServer(t)
	for _, p := range []string{"/balanceador/agregar", "/balanceador/eliminar", "/balanceador/conectar"} {
		if rec := do(s, "POST", p, "localhost:8080", url.Values{"name": {"w"}, "ip": {"10.0.0.1"}, "port": {"80"}}); rec.Code != http.StatusForbidden {
			t.Errorf("%s sin CSRF → %d", p, rec.Code)
		}
	}
	if len(fr.scripts) != 0 {
		t.Fatal("no debía ejecutarse nada")
	}
}

func TestBalancerAddAndRemoveThroughWeb(t *testing.T) {
	s, fr := newTestServer(t)
	fr.respond = lbResponder(lbBase)
	rec := do(s, "POST", "/balanceador/agregar", "localhost:8080", url.Values{"csrf": {s.csrf}, "name": {"web1"}, "ip": {"192.168.1.20"}, "port": {"80"}})
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), "agregado al back-end") {
		t.Fatalf("agregar: %d\n%s", rec.Code, rec.Body.String())
	}
	applied := 0
	for _, sc := range fr.scripts {
		if strings.Contains(sc, "EXPECT=") {
			applied++
		}
	}
	if applied != 1 {
		t.Errorf("debía aplicarse una vez, fue %d", applied)
	}
	fr.respond = lbResponder(lbBase + "# BEGIN consola-automatizacion (no editar a mano)\nfrontend consola_front\n    bind *:80\n    default_backend consola_back\n\nbackend consola_back\n    balance roundrobin\n    server web1 192.168.1.20:80 check\n# END consola-automatizacion\n")
	rec = do(s, "POST", "/balanceador/eliminar", "localhost:8080", url.Values{"csrf": {s.csrf}, "name": {"web1"}})
	if !strings.Contains(rec.Body.String(), "eliminado del back-end") {
		t.Errorf("eliminar: %s", rec.Body.String())
	}
}

func TestBalancerRejectsBadInputAndKeepsForm(t *testing.T) {
	s, fr := newTestServer(t)
	fr.respond = lbResponder(lbBase)
	for _, f := range []url.Values{
		{"name": {"web1"}, "ip": {"no-es-ip"}, "port": {"80"}},
		{"name": {"web1"}, "ip": {"192.168.1.20"}, "port": {"abc"}},
		{"name": {"web1"}, "ip": {"192.168.1.20"}, "port": {"0"}},
		{"name": {"Web 1"}, "ip": {"192.168.1.20"}, "port": {"80"}},
	} {
		f.Set("csrf", s.csrf)
		rec := do(s, "POST", "/balanceador/agregar", "localhost:8080", f)
		if rec.Code != 200 || !strings.Contains(rec.Body.String(), "Datos no válidos") {
			t.Errorf("%v → %d", f, rec.Code)
		}
	}
	for _, sc := range fr.scripts {
		if strings.Contains(sc, "EXPECT=") {
			t.Fatal("no debía aplicarse nada")
		}
	}
}

func TestUserCreateWithPasswordSendsFileAndNeverEchoesIt(t *testing.T) {
	s, fr := newTestServer(t)
	pw := "S3creta larga!"
	rec := do(s, "POST", "/usuarios/crear", "localhost:8080", url.Values{"csrf": {s.csrf}, "name": {"ana"}, "password": {pw}})
	body := rec.Body.String()
	if rec.Code != 200 || len(fr.scripts) != 1 || len(fr.uploads) != 1 || !strings.Contains(fr.uploads[0], ":ana:"+pw) {
		t.Fatalf("código %d scripts %d uploads %v", rec.Code, len(fr.scripts), fr.uploads)
	}
	if strings.Contains(body, pw) || strings.Contains(fr.scripts[0], pw) {
		t.Error("la contraseña no debe aparecer en la página ni en el script")
	}
	// Contraseña demasiado corta: se rechaza sin tocar la VM y no se devuelve en el formulario.
	rec = do(s, "POST", "/usuarios/crear", "localhost:8080", url.Values{"csrf": {s.csrf}, "name": {"bob"}, "password": {"corta"}})
	if !strings.Contains(rec.Body.String(), "Datos no válidos") || strings.Contains(rec.Body.String(), `value="corta"`) || len(fr.scripts) != 1 {
		t.Error("contraseña corta mal manejada")
	}
}
