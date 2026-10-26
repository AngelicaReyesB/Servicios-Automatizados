// Package balanceador implementa el módulo "Balanceador de carga" (3.4):
// agregar y quitar servidores del back-end de HAProxy, validando la
// configuración antes de recargar y restaurándola si algo falla.
package balanceador

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	"consola/internal/modules/common"
	"consola/internal/oplog"
	"consola/internal/runner"
	"consola/internal/validate"
)

const (
	module     = "Balanceador de carga"
	opTimeout  = 3 * time.Minute
	cfgMarker  = "--- configuración ---"
	verMarker  = "--- verificación ---"
	DefaultCfg = "/etc/haproxy/haproxy.cfg"
)

type Outcome = common.Outcome

// Backend es lo que el módulo necesita del gestor de canales.
type Backend interface {
	common.Provider
	SSHFor(target, keyPath string) (runner.KeyProber, error)
	MarkSSHReady(target, keyPath string) error
}

// Options configura el módulo.
type Options struct {
	KeyPath    string // llave privada de root que se reutiliza para entrar por SSH
	BalancerIP string // IP de la VM del balanceador
	FrontPort  int    // puerto del frontend (80 por omisión)
}

type Service struct {
	back   Backend
	log    *oplog.Logger
	target string
	opts   Options
	mu     sync.Mutex
}

func New(b Backend, log *oplog.Logger, target string, opts Options) *Service {
	if opts.FrontPort == 0 {
		opts.FrontPort = 80
	}
	return &Service{back: b, log: log, target: target, opts: opts}
}

type scriptPaths struct{ Cfg, Tmp, Wait string }

var prodPaths = scriptPaths{Cfg: DefaultCfg, Tmp: "/tmp", Wait: "1"}

func (p scriptPaths) render(tpl string, kv ...string) string {
	return strings.NewReplacer(append([]string{"{{CFG}}", p.Cfg, "{{TMP}}", p.Tmp, "{{WAIT}}", p.Wait}, kv...)...).Replace(tpl)
}

const (
	exitNoHAProxy = 41
	exitNoCfg     = 43
	exitChanged   = 44
	exitInvalid   = 45
	exitReload    = 46
)

const readScript = `export LC_ALL=C
CFG={{CFG}}
if ! command -v haproxy >/dev/null 2>&1; then echo "HAProxy no está instalado en la VM" >&2; exit 41; fi
if [ ! -f "$CFG" ]; then echo "No existe $CFG" >&2; exit 43; fi
echo "estado: $(systemctl is-active haproxy 2>/dev/null || true)"
echo "versión: $(haproxy -v 2>&1 | head -1)"
echo "` + cfgMarker + `"
cat "$CFG"
`

const applyScript = `export LC_ALL=C
CFG={{CFG}}
TMP={{TMP}}
EXPECT={{EXPECT}}
PORT={{PORT}}
WORK=$(mktemp -d "$TMP/consola-haproxy.XXXXXX")
trap 'rm -rf "$WORK"' EXIT
if ! command -v haproxy >/dev/null 2>&1; then echo "HAProxy no está instalado en la VM" >&2; exit 41; fi
if [ ! -f "$CFG" ]; then echo "No existe $CFG" >&2; exit 43; fi
echo "--- estado previo ---"
echo "estado: $(systemctl is-active haproxy 2>/dev/null || true)"
CUR=$(sha256sum "$CFG" | cut -d' ' -f1)
if [ "$CUR" != "$EXPECT" ]; then echo "haproxy.cfg cambió mientras se preparaba la operación; no se aplicó nada. Vuelva a intentarlo." >&2; exit 44; fi
printf '%s' '{{B64}}' | base64 -d > "$WORK/new.cfg"
if ! haproxy -c -f "$WORK/new.cfg" > "$WORK/check.txt" 2>&1; then
  cat "$WORK/check.txt" >&2
  echo "HAProxy rechazó la configuración generada; no se aplicó ningún cambio" >&2
  exit 45
fi
echo "validación previa: $(tail -1 "$WORK/check.txt")"
if [ ! -f "$CFG.consola.bak" ]; then cp -p "$CFG" "$CFG.consola.bak"; fi
cp -p "$CFG" "$WORK/previous.cfg"
install -m 644 "$WORK/new.cfg" "$CFG"
restore() {
  install -m 644 "$WORK/previous.cfg" "$CFG"
  if systemctl is-active --quiet haproxy; then systemctl reload haproxy || systemctl restart haproxy || true; fi
}
fail() {
  echo "$1" >&2
  systemctl status haproxy --no-pager -l >&2 || true
  journalctl -u haproxy -n 15 --no-pager >&2 || true
  restore
  echo "Se restauró la configuración anterior de HAProxy" >&2
  exit 46
}
if systemctl is-active --quiet haproxy; then
  systemctl reload haproxy || fail "systemctl reload haproxy falló"
else
  systemctl start haproxy || fail "systemctl start haproxy falló"
fi
sleep {{WAIT}}
systemctl is-active --quiet haproxy || fail "HAProxy no quedó activo tras aplicar la configuración"
if ! ss -H -ltnp "sport = :$PORT" 2>/dev/null | grep -q haproxy; then
  fail "HAProxy no está escuchando en el puerto $PORT (¿otro programa usa ese puerto?)"
fi
echo "` + verMarker + `"
echo "validación: $(haproxy -c -f "$CFG" 2>&1 | tail -1)"
echo "estado: $(systemctl is-active haproxy)"
echo "escuchando: $(ss -H -ltn "sport = :$PORT" | head -1 | tr -s ' ')"
grep -E '^    server ' "$CFG" || echo "(sin servidores en el back-end)"
`

// View es el estado actual leído de la VM.
type View struct {
	Servers []Server
	Managed bool   // ya existe el bloque de la consola
	Active  string // estado de systemd de haproxy
	Version string
	cfg     string
	parsed  parsed
}

// cfgError distingue los problemas del CONTENIDO de haproxy.cfg de los de comunicación.
type cfgError struct{ error }

func (e *cfgError) Unwrap() error { return e.error }

func (s *Service) read(ctx context.Context, op string) (View, runner.Result, error) {
	r, err := s.back.Get(s.target)
	if err != nil {
		s.log.Record(oplog.Entry{Module: module, Operation: op, Target: s.target, Error: err.Error()})
		return View{}, runner.Result{}, err
	}
	res, err := common.Run(ctx, s.log, module, s.target, r, op, prodPaths.render(readScript))
	if err != nil || !res.OK() {
		return View{}, res, err
	}
	i := strings.Index(res.Stdout, cfgMarker+"\n")
	if i < 0 {
		return View{}, res, &cfgError{errors.New("respuesta inesperada de la VM al leer haproxy.cfg")}
	}
	head, cfg := res.Stdout[:i], res.Stdout[i+len(cfgMarker)+1:]
	v := View{cfg: cfg}
	for _, l := range strings.Split(head, "\n") {
		switch {
		case strings.HasPrefix(l, "estado: "):
			v.Active = strings.TrimPrefix(l, "estado: ")
		case strings.HasPrefix(l, "versión: "):
			v.Version = strings.TrimPrefix(l, "versión: ")
		}
	}
	p, perr := parseConfig(cfg, s.opts.FrontPort)
	if perr != nil {
		return v, res, &cfgError{perr}
	}
	v.parsed, v.Servers, v.Managed = p, p.servers, p.found
	return v, res, nil
}

// State lee el estado de HAProxy y los servidores del back-end.
func (s *Service) State(ctx context.Context) (View, error) {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	v, res, err := s.read(ctx, "Leer configuración de HAProxy")
	if err == nil && !res.OK() {
		return v, errors.New(diagnose(res))
	}
	return v, err
}

func (s *Service) readFailure(res runner.Result, err error) Outcome {
	var ce *cfgError
	switch {
	case errors.As(err, &ce):
		return Outcome{Title: "No se puede modificar la configuración", Message: ce.Error(), Detail: common.Detail(res)}
	case err != nil:
		return common.TransportFailure(res, err)
	}
	return Outcome{Title: "No se pudo leer la configuración de HAProxy", Message: diagnose(res), Detail: common.Detail(res)}
}

func (s *Service) apply(ctx context.Context, v View, servers []Server, op string) (runner.Result, error) {
	content := v.parsed.render(buildBlock(s.opts.FrontPort, servers))
	sum := sha256.Sum256([]byte(v.cfg))
	script := prodPaths.render(applyScript,
		"{{EXPECT}}", hex.EncodeToString(sum[:]),
		"{{PORT}}", fmt.Sprint(s.opts.FrontPort),
		"{{B64}}", base64.StdEncoding.EncodeToString([]byte(content)))
	return common.RunOn(ctx, s.log, s.back, module, s.target, op, script)
}

// AddServer agrega un servidor al back-end.
func (s *Service) AddServer(ctx context.Context, name, ip string, port int) Outcome {
	name, ip = strings.TrimSpace(name), strings.TrimSpace(ip)
	for _, err := range []error{validate.ServerName(name), validate.BackendIPv4(ip), validate.Port(port)} {
		if err != nil {
			return common.Invalid(err)
		}
	}
	if ip == s.opts.BalancerIP && port == s.opts.FrontPort {
		return common.Invalid(errors.New("ese servidor es el propio balanceador: el tráfico se enviaría a sí mismo en un ciclo"))
	}
	if !s.mu.TryLock() {
		return common.Busy()
	}
	defer s.mu.Unlock()
	ctx, cancel := context.WithTimeout(ctx, opTimeout)
	defer cancel()

	v, res, err := s.read(ctx, "Leer configuración de HAProxy")
	if err != nil || !res.OK() {
		return s.readFailure(res, err)
	}
	if err := v.parsed.checkOutside(s.opts.FrontPort); err != nil {
		return Outcome{Title: "No se puede modificar la configuración", Message: err.Error()}
	}
	for _, x := range v.Servers {
		switch {
		case x.Name == name:
			return Outcome{Title: "El servidor ya existe", Message: fmt.Sprintf("Ya hay un servidor llamado «%s» (%s) en el back-end.", name, x.Addr())}
		case x.IP == ip && x.Port == port:
			return Outcome{Title: "El servidor ya existe", Message: fmt.Sprintf("%s:%d ya está en el back-end con el nombre «%s».", ip, port, x.Name)}
		}
	}
	servers := append(append([]Server{}, v.Servers...), Server{Name: name, IP: ip, Port: port})
	ares, err := s.apply(ctx, v, servers, fmt.Sprintf("Agregar servidor %s (%s:%d) al back-end", name, ip, port))
	if err != nil {
		return common.TransportFailure(ares, err)
	}
	if !ares.OK() {
		return Outcome{Title: fmt.Sprintf("No se pudo agregar el servidor «%s»", name), Message: diagnose(ares), Detail: common.Detail(ares)}
	}
	return Outcome{
		OK: true, Title: "Operación completada",
		Message: fmt.Sprintf("Servidor «%s» (%s:%d) agregado al back-end. HAProxy validó la configuración y se recargó sin cortar conexiones. El back-end tiene %d servidor(es).", name, ip, port, len(servers)),
		Detail:  common.Detail(ares),
	}
}

// RemoveServer quita un servidor del back-end.
func (s *Service) RemoveServer(ctx context.Context, name string) Outcome {
	name = strings.TrimSpace(name)
	if err := validate.ServerName(name); err != nil {
		return common.Invalid(err)
	}
	if !s.mu.TryLock() {
		return common.Busy()
	}
	defer s.mu.Unlock()
	ctx, cancel := context.WithTimeout(ctx, opTimeout)
	defer cancel()

	v, res, err := s.read(ctx, "Leer configuración de HAProxy")
	if err != nil || !res.OK() {
		return s.readFailure(res, err)
	}
	var servers []Server
	found := false
	for _, x := range v.Servers {
		if x.Name == name {
			found = true
			continue
		}
		servers = append(servers, x)
	}
	if !found {
		return Outcome{Title: "El servidor no existe", Message: fmt.Sprintf("No hay ningún servidor llamado «%s» en el back-end administrado por la consola.", name)}
	}
	ares, err := s.apply(ctx, v, servers, fmt.Sprintf("Eliminar servidor %s del back-end", name))
	if err != nil {
		return common.TransportFailure(ares, err)
	}
	if !ares.OK() {
		return Outcome{Title: fmt.Sprintf("No se pudo eliminar el servidor «%s»", name), Message: diagnose(ares), Detail: common.Detail(ares)}
	}
	msg := fmt.Sprintf("Servidor «%s» eliminado del back-end. HAProxy validó la configuración y se recargó. Quedan %d servidor(es).", name, len(servers))
	if len(servers) == 0 {
		msg += " Con el back-end vacío, HAProxy responde 503 hasta que agregue uno."
	}
	return Outcome{OK: true, Title: "Operación completada", Message: msg, Detail: common.Detail(ares)}
}

// ConnectSSH hace que la consola use SSH con la llave de root para esta VM
// (la VM se clonó de una que ya tenía esa llave autorizada).
func (s *Service) ConnectSSH(ctx context.Context) Outcome {
	if s.opts.KeyPath == "" {
		return common.Invalid(errors.New("no hay llave configurada"))
	}
	if _, err := os.Stat(s.opts.KeyPath); err != nil {
		return Outcome{
			Title:   "Falta la llave de root",
			Message: "Primero configure la llave de root en «Preparación del sistema» (Generar y configurar llaves SSH): esa misma llave se reutiliza aquí.",
		}
	}
	if !s.mu.TryLock() {
		return common.Busy()
	}
	defer s.mu.Unlock()
	ctx, cancel := context.WithTimeout(ctx, opTimeout)
	defer cancel()

	probe, err := s.back.SSHFor(s.target, s.opts.KeyPath)
	if err != nil {
		return Outcome{Title: "No se pudo preparar la conexión SSH", Message: err.Error()}
	}
	res, err := common.Run(ctx, s.log, module, s.target, probe, "Comprobar acceso SSH con la llave de root",
		"id -un; (/usr/sbin/sshd -T 2>/dev/null | grep -E '^(permitrootlogin|passwordauthentication) ') || true")
	if err != nil || !res.OK() || strings.Fields(res.Stdout + " ")[0] != "root" {
		d := common.Detail(res)
		if err != nil {
			d = "Error de comunicación: " + err.Error()
		}
		return Outcome{
			Title: "No se pudo entrar por SSH con la llave de root",
			Message: "La consola sigue usando Guest Additions para esta VM. Verifique que la IP de «haproxy» en config.json sea la actual, que la VM tenga el mismo usuario root con la llave autorizada " +
				"(clonada después de configurarla) y que el firewall no bloquee el puerto 22.",
			Detail: d,
		}
	}
	if err := s.back.MarkSSHReady(s.target, s.opts.KeyPath); err != nil {
		return Outcome{Title: "No se pudo registrar el cambio de canal", Message: "El acceso funciona, pero no se pudo recordar el cambio de canal.", Detail: err.Error()}
	}
	msg := "La consola ya se comunica con la VM del balanceador solo por SSH con la llave de root."
	if strings.Contains(res.Stdout, "passwordauthentication yes") {
		msg += " Aviso: esa VM todavía acepta usuario y contraseña por SSH; clónela de una VM con la contraseña ya bloqueada o bloquéela manualmente."
	}
	return Outcome{OK: true, Title: "Operación completada", Message: msg, Detail: common.Detail(res)}
}

func diagnose(res runner.Result) string {
	out := res.Stdout + "\n" + res.Stderr
	switch res.ExitCode {
	case exitNoHAProxy:
		return "HAProxy no está instalado en la VM del balanceador. Instálelo con apt install haproxy."
	case exitNoCfg:
		return "No existe /etc/haproxy/haproxy.cfg en la VM del balanceador."
	case exitChanged:
		return "El archivo haproxy.cfg cambió mientras se preparaba la operación. No se aplicó nada; vuelva a intentarlo."
	case exitInvalid:
		return "HAProxy rechazó la configuración generada (haproxy -c). No se aplicó ningún cambio; revise el detalle técnico."
	case exitReload:
		return "HAProxy no pudo recargar la nueva configuración o no quedó escuchando. Se restauró la configuración anterior; revise el detalle técnico (incluye journalctl)."
	}
	if strings.Contains(out, "No space left") {
		return "No hay espacio en disco en la VM."
	}
	return "La operación terminó con error. Revise el detalle técnico para el diagnóstico."
}
