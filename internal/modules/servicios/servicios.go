// Package servicios implementa el módulo "Gestión de servicios" (3.3):
// despliega una aplicación como servicio de systemd (archivos, usuario,
// permisos y unidad) y ofrece start, stop, restart, status, enable y disable.
package servicios

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"

	"consola/internal/modules/common"
	"consola/internal/oplog"
	"consola/internal/runner"
	"consola/internal/validate"
)

const (
	module       = "Gestión de servicios"
	opTimeout    = 10 * time.Minute
	verifyMarker = "--- verificación ---"
	statusMarker = "--- estado ---"
	marker       = "# Gestionado por la consola de automatizacion (no editar a mano)"

	KindSimple  = "simple"  // permanece en ejecución (p. ej. el catálogo de libros)
	KindOneshot = "oneshot" // se ejecuta y termina (p. ej. el script que escribe fecha y hora)
)

type Outcome = common.Outcome

type Service struct {
	provider common.Provider
	log      *oplog.Logger
	target   string
	mu       sync.Mutex
}

func New(p common.Provider, log *oplog.Logger, target string) *Service {
	return &Service{provider: p, log: log, target: target}
}

// scriptPaths son rutas de los scripts; las pruebas las sustituyen.
type scriptPaths struct{ Opt, UnitDir, Tmp, Wait string }

var prodPaths = scriptPaths{Opt: "/opt", UnitDir: "/etc/systemd/system", Tmp: "/tmp", Wait: "1"}

func (p scriptPaths) render(tpl string, kv ...string) string {
	pairs := []string{"{{OPT}}", p.Opt, "{{UNITDIR}}", p.UnitDir, "{{TMP}}", p.Tmp, "{{WAIT}}", p.Wait}
	return strings.NewReplacer(append(pairs, kv...)...).Replace(tpl)
}

const (
	exitConflict   = 30
	exitNoUpload   = 31
	exitUnitBad    = 32
	exitNotManaged = 33
	exitFailed     = 34
	exitUserClash  = 35
)

var (
	reExec = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`)
	reArgs = regexp.MustCompile(`^[A-Za-z0-9 ._:/=,@+-]{0,200}$`)
)

// DeployOptions son los datos del formulario de despliegue.
type DeployOptions struct {
	Name      string // nombre del servicio, usuario y carpeta /opt/<nombre>
	Kind      string // KindSimple o KindOneshot
	Args      string // argumentos de la línea de comandos
	ExecName  string // nombre del ejecutable dentro de /opt/<nombre>
	ExecPath  string // archivo local con el ejecutable
	ExtraPath string // .tar.gz local (ya normalizado) con archivos adicionales; opcional
}

// ValidateExecutable comprueba que el archivo sea un ejecutable de Linux (ELF)
// o un script con «#!».
func ValidateExecutable(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("no se puede leer el archivo: %w", err)
	}
	defer f.Close()
	head := make([]byte, 4)
	n, _ := f.Read(head)
	head = head[:n]
	switch {
	case len(head) >= 4 && string(head) == "\x7fELF":
		return nil
	case len(head) >= 2 && string(head[:2]) == "#!":
		return nil
	case len(head) >= 2 && string(head[:2]) == "MZ":
		return errors.New("el archivo es un ejecutable de Windows (.exe). Compile para Linux, por ejemplo: GOOS=linux GOARCH=amd64 go build")
	}
	return errors.New("el archivo no parece un ejecutable de Linux: debe ser un binario ELF o un script que empiece con #! (por ejemplo #!/bin/bash)")
}

// Validate revisa los datos del formulario (sin tocar la VM).
func (o DeployOptions) Validate() error {
	if err := validate.ServiceName(o.Name); err != nil {
		return err
	}
	if o.Kind != KindSimple && o.Kind != KindOneshot {
		return errors.New("tipo de servicio no válido")
	}
	if !reExec.MatchString(o.ExecName) {
		return errors.New("el nombre del archivo ejecutable no es válido: use letras, dígitos, punto, guion y guion bajo (sin espacios)")
	}
	if !reArgs.MatchString(o.Args) {
		return errors.New("los argumentos solo pueden tener letras, dígitos, espacios y los símbolos . _ : / = , @ + - (máximo 200 caracteres)")
	}
	if o.ExecPath == "" {
		return errors.New("seleccione el archivo ejecutable")
	}
	return ValidateExecutable(o.ExecPath)
}

// BuildUnit genera el archivo de unidad de systemd.
func BuildUnit(o DeployOptions) string {
	exe := "/opt/" + o.Name + "/" + o.ExecName
	if a := strings.TrimSpace(o.Args); a != "" {
		exe += " " + strings.Join(strings.Fields(a), " ")
	}
	var b strings.Builder
	b.WriteString(marker + "\n[Unit]\n")
	fmt.Fprintf(&b, "Description=Servicio %s (consola de automatización)\nAfter=network.target\n\n[Service]\n", o.Name)
	if o.Kind == KindOneshot {
		b.WriteString("Type=oneshot\nRemainAfterExit=yes\n")
	} else {
		b.WriteString("Type=simple\nRestart=on-failure\nRestartSec=2\n")
	}
	fmt.Fprintf(&b, "User=%s\nGroup=%s\nWorkingDirectory=/opt/%s\nExecStart=%s\n", o.Name, o.Name, o.Name, exe)
	b.WriteString("NoNewPrivileges=true\nAmbientCapabilities=CAP_NET_BIND_SERVICE\n\n[Install]\nWantedBy=multi-user.target\n")
	return b.String()
}

const deployScript = `export LC_ALL=C
N={{NAME}}
EXE={{EXEC}}
OPT={{OPT}}
UNITDIR={{UNITDIR}}
TMP={{TMP}}
DIR="$OPT/$N"
UNIT="$UNITDIR/$N.service"
TMPBIN="$TMP/consola-$N.bin"
TMPTGZ="$TMP/consola-$N.tgz"
VDIR="$TMP/consola-verify-$N"
trap 'rm -rf "$TMPBIN" "$TMPTGZ" "$VDIR"' EXIT
echo "--- estado previo ---"
if [ -f "$UNIT" ]; then
  if grep -qF 'Gestionado por la consola' "$UNIT"; then echo "el servicio ya existe (se actualizará): $(systemctl is-active "$N" 2>/dev/null || true)"; else echo "Ya existe una unidad $N.service que no gestiona esta consola" >&2; exit 30; fi
elif systemctl cat "$N.service" >/dev/null 2>&1; then
  echo "Ya existe un servicio del sistema llamado $N" >&2; exit 30
else
  echo "el servicio $N no existe"
fi
if id -u "$N" >/dev/null 2>&1; then
  HOME_OF=$(getent passwd "$N" | cut -d: -f6)
  if [ "$HOME_OF" != "$DIR" ]; then echo "Ya existe un usuario del sistema llamado $N que no pertenece a esta consola" >&2; exit 35; fi
fi
if [ ! -f "$TMPBIN" ]; then echo "No llegó el archivo ejecutable a la VM" >&2; exit 31; fi
set -e
id -u "$N" >/dev/null 2>&1 || useradd --system --no-create-home --home-dir "$DIR" --shell /usr/sbin/nologin "$N"
WAS_ACTIVE=0
if systemctl is-active --quiet "$N"; then WAS_ACTIVE=1; systemctl stop "$N"; fi
mkdir -p "$DIR"
if [ -f "$TMPTGZ" ]; then tar -xzf "$TMPTGZ" -C "$DIR" --no-same-owner; fi
install -m 755 "$TMPBIN" "$DIR/$EXE"
chown -R "$N:$N" "$DIR"
mkdir -p "$VDIR"
printf '%s' '{{UNIT_B64}}' | base64 -d > "$VDIR/$N.service"
if command -v systemd-analyze >/dev/null 2>&1; then
  if ! systemd-analyze verify "$VDIR/$N.service" >"$VDIR/verify.txt" 2>&1; then
    cat "$VDIR/verify.txt" >&2
    echo "systemd rechazó la unidad generada" >&2
    exit 32
  fi
fi
install -m 644 "$VDIR/$N.service" "$UNIT"
systemctl daemon-reload
if [ "$WAS_ACTIVE" = 1 ]; then systemctl start "$N"; fi
echo "` + verifyMarker + `"
ls -ld "$DIR" "$DIR/$EXE"
echo "usuario: $(id "$N")"
echo "unidad: $UNIT"
echo "estado: $(systemctl is-active "$N" 2>/dev/null || true) · arranque: $(systemctl is-enabled "$N" 2>/dev/null || true)"
`

// Deploy sube los archivos a la VM y deja el servicio instalado (sin iniciarlo).
func (s *Service) Deploy(ctx context.Context, o DeployOptions) Outcome {
	o.Name = strings.TrimSpace(o.Name)
	o.Args = strings.TrimSpace(o.Args)
	if err := o.Validate(); err != nil {
		return common.Invalid(err)
	}
	if !s.mu.TryLock() {
		return common.Busy()
	}
	defer s.mu.Unlock()
	ctx, cancel := context.WithTimeout(ctx, opTimeout)
	defer cancel()

	p := prodPaths
	r, err := s.provider.Get(s.target)
	if err != nil {
		return common.TransportFailure(runner.Result{}, err)
	}
	var detail strings.Builder
	up := func(local, remote string) error {
		start := time.Now()
		err := r.Upload(ctx, local, remote, 0o600)
		e := oplog.Entry{Module: module, Operation: "Transferir " + remote, Target: s.target, Channel: r.Name(), OK: err == nil, DurationMS: time.Since(start).Milliseconds()}
		if err != nil {
			e.Error = err.Error()
		}
		s.log.Record(e)
		fmt.Fprintf(&detail, "Transferencia a %s (%s): ", remote, r.Name())
		if err != nil {
			fmt.Fprintf(&detail, "ERROR: %v\n", err)
		} else {
			detail.WriteString("OK\n")
		}
		return err
	}
	fail := func(err error) Outcome {
		return Outcome{
			Title:   "No se pudieron transferir los archivos a la VM",
			Message: "Verifique que la VM esté encendida, que haya espacio en /tmp y que la conexión funcione.",
			Detail:  detail.String() + "Error: " + err.Error(),
		}
	}
	if err := up(o.ExecPath, p.Tmp+"/consola-"+o.Name+".bin"); err != nil {
		return fail(err)
	}
	if o.ExtraPath != "" {
		if err := up(o.ExtraPath, p.Tmp+"/consola-"+o.Name+".tgz"); err != nil {
			return fail(err)
		}
	}

	script := p.render(deployScript, "{{NAME}}", o.Name, "{{EXEC}}", o.ExecName,
		"{{UNIT_B64}}", base64.StdEncoding.EncodeToString([]byte(BuildUnit(o))))
	res, err := common.Run(ctx, s.log, module, s.target, r, "Desplegar servicio "+o.Name, script)
	if err != nil {
		out := common.TransportFailure(res, err)
		out.Detail = detail.String() + out.Detail
		return out
	}
	if !res.OK() {
		return Outcome{
			Title:   fmt.Sprintf("No se pudo desplegar el servicio «%s»", o.Name),
			Message: diagnose(res),
			Detail:  detail.String() + "\n" + common.Detail(res),
		}
	}
	msg := fmt.Sprintf("Servicio «%s» desplegado en /opt/%s y registrado en systemd. Todavía no está iniciado: use los botones Iniciar y Habilitar.", o.Name, o.Name)
	if strings.Contains(res.Stdout, "el servicio ya existe") {
		msg = fmt.Sprintf("Servicio «%s» actualizado (se reemplazaron sus archivos y su unidad; si estaba en ejecución se volvió a iniciar).", o.Name)
	}
	return Outcome{OK: true, Title: "Operación completada", Message: msg, Detail: detail.String() + "\n" + common.Detail(res)}
}

// Actions son las acciones disponibles sobre un servicio administrado.
var Actions = []string{"start", "stop", "restart", "status", "enable", "disable"}

const actionScript = `export LC_ALL=C
N={{NAME}}
ACT={{ACTION}}
UNIT={{UNITDIR}}/$N.service
echo "--- estado previo ---"
if ! grep -qF 'Gestionado por la consola' "$UNIT" 2>/dev/null; then echo "«$N» no es un servicio administrado por esta consola" >&2; exit 33; fi
echo "estado: $(systemctl is-active "$N" 2>/dev/null || true) · arranque: $(systemctl is-enabled "$N" 2>/dev/null || true)"
if [ "$ACT" = status ]; then
  echo "` + statusMarker + `"
  systemctl status "$N" --no-pager -l 2>&1 || true
  echo
  echo "--- últimas líneas del registro (journalctl) ---"
  journalctl -u "$N" -n 15 --no-pager 2>&1 || true
  exit 0
fi
if ! systemctl "$ACT" "$N"; then
  echo "systemctl $ACT falló" >&2
  journalctl -u "$N" -n 15 --no-pager >&2 || true
  exit 34
fi
case "$ACT" in
  start|restart)
    sleep {{WAIT}}
    if ! systemctl is-active --quiet "$N"; then
      echo "El servicio no quedó activo tras $ACT" >&2
      systemctl status "$N" --no-pager -l >&2 || true
      journalctl -u "$N" -n 15 --no-pager >&2 || true
      exit 34
    fi;;
esac
echo "` + verifyMarker + `"
echo "estado: $(systemctl is-active "$N" 2>/dev/null || true) · arranque: $(systemctl is-enabled "$N" 2>/dev/null || true)"
`

var actionDone = map[string]string{
	"start": "iniciado", "stop": "detenido", "restart": "reiniciado",
	"enable": "habilitado para el arranque", "disable": "deshabilitado para el arranque",
}

// Act ejecuta start, stop, restart, status, enable o disable.
func (s *Service) Act(ctx context.Context, name, action string) Outcome {
	name = strings.TrimSpace(name)
	if err := validate.ServiceName(name); err != nil {
		return common.Invalid(err)
	}
	known := false
	for _, a := range Actions {
		known = known || a == action
	}
	if !known {
		return common.Invalid(errors.New("acción no válida"))
	}
	if !s.mu.TryLock() {
		return common.Busy()
	}
	defer s.mu.Unlock()
	ctx, cancel := context.WithTimeout(ctx, opTimeout)
	defer cancel()

	script := prodPaths.render(actionScript, "{{NAME}}", name, "{{ACTION}}", action)
	res, err := common.RunOn(ctx, s.log, s.provider, module, s.target, fmt.Sprintf("systemctl %s %s", action, name), script)
	if err != nil {
		return common.TransportFailure(res, err)
	}
	if !res.OK() {
		return Outcome{
			Title:   fmt.Sprintf("No se pudo ejecutar «%s» sobre «%s»", action, name),
			Message: diagnose(res),
			Detail:  common.Detail(res),
		}
	}
	if action == "status" {
		return Outcome{OK: true, Title: "Estado de «" + name + "»", Message: "Respuesta de systemctl status.", Preview: after(res.Stdout, statusMarker), Detail: common.Detail(res)}
	}
	msg := fmt.Sprintf("Servicio «%s» %s.", name, actionDone[action])
	if v := after(res.Stdout, verifyMarker); v != "" {
		msg += " " + v
	}
	return Outcome{OK: true, Title: "Operación completada", Message: msg, Detail: common.Detail(res)}
}

const removeScript = `export LC_ALL=C
N={{NAME}}
RM_FILES={{FLAG}}
OPT={{OPT}}
UNIT={{UNITDIR}}/$N.service
echo "--- estado previo ---"
if ! grep -qF 'Gestionado por la consola' "$UNIT" 2>/dev/null; then echo "«$N» no es un servicio administrado por esta consola" >&2; exit 33; fi
echo "estado: $(systemctl is-active "$N" 2>/dev/null || true) · arranque: $(systemctl is-enabled "$N" 2>/dev/null || true)"
set -e
systemctl stop "$N" || true
systemctl disable "$N" >/dev/null 2>&1 || true
rm -f "$UNIT"
systemctl daemon-reload
systemctl reset-failed "$N" >/dev/null 2>&1 || true
if [ "$RM_FILES" = 1 ] && [ -n "$N" ]; then
  rm -rf "$OPT/$N"
  if id -u "$N" >/dev/null 2>&1 && [ "$(getent passwd "$N" | cut -d: -f6)" = "$OPT/$N" ]; then userdel "$N"; fi
fi
echo "` + verifyMarker + `"
if [ -f "$UNIT" ]; then echo "la unidad TODAVÍA existe"; else echo "unidad eliminada"; fi
if [ -d "$OPT/$N" ]; then echo "archivos conservados en $OPT/$N"; else echo "archivos eliminados"; fi
`

// Remove elimina el servicio (y, opcionalmente, sus archivos y su usuario).
func (s *Service) Remove(ctx context.Context, name string, removeFiles bool) Outcome {
	name = strings.TrimSpace(name)
	if err := validate.ServiceName(name); err != nil {
		return common.Invalid(err)
	}
	if !s.mu.TryLock() {
		return common.Busy()
	}
	defer s.mu.Unlock()
	ctx, cancel := context.WithTimeout(ctx, opTimeout)
	defer cancel()
	flag := "0"
	if removeFiles {
		flag = "1"
	}
	script := prodPaths.render(removeScript, "{{NAME}}", name, "{{FLAG}}", flag)
	res, err := common.RunOn(ctx, s.log, s.provider, module, s.target, "Eliminar servicio "+name, script)
	if err != nil {
		return common.TransportFailure(res, err)
	}
	if !res.OK() {
		return Outcome{Title: fmt.Sprintf("No se pudo eliminar el servicio «%s»", name), Message: diagnose(res), Detail: common.Detail(res)}
	}
	msg := fmt.Sprintf("Servicio «%s» detenido y eliminado de systemd.", name)
	if removeFiles {
		msg += " También se eliminaron /opt/" + name + " y su usuario."
	} else {
		msg += " Sus archivos en /opt/" + name + " se conservaron."
	}
	return Outcome{OK: true, Title: "Operación completada", Message: msg, Detail: common.Detail(res)}
}

// Info describe un servicio administrado.
type Info struct{ Name, Active, Enabled string }

const listScript = `export LC_ALL=C
for f in {{UNITDIR}}/*.service; do
  [ -f "$f" ] || continue
  grep -qF 'Gestionado por la consola' "$f" || continue
  n=$(basename "$f" .service)
  printf 'SVC\t%s\t%s\t%s\n' "$n" "$(systemctl is-active "$n" 2>/dev/null || true)" "$(systemctl is-enabled "$n" 2>/dev/null || true)"
done
true
`

// List devuelve los servicios que administra la consola en la VM.
func (s *Service) List(ctx context.Context) ([]Info, error) {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	res, err := common.RunOn(ctx, s.log, s.provider, module, s.target, "Listar servicios administrados", prodPaths.render(listScript))
	if err != nil {
		return nil, err
	}
	if !res.OK() {
		return nil, fmt.Errorf("el script terminó con código %d: %s", res.ExitCode, strings.TrimSpace(res.Stderr))
	}
	return parseList(res.Stdout), nil
}

func parseList(out string) []Info {
	var list []Info
	for _, line := range strings.Split(out, "\n") {
		f := strings.Split(strings.TrimRight(line, "\r"), "\t")
		if len(f) != 4 || f[0] != "SVC" || validate.ServiceName(f[1]) != nil {
			continue
		}
		list = append(list, Info{Name: f[1], Active: f[2], Enabled: f[3]})
	}
	return list
}

func after(out, mark string) string {
	i := strings.LastIndex(out, mark)
	if i < 0 {
		return ""
	}
	return strings.TrimSpace(out[i+len(mark):])
}

func diagnose(res runner.Result) string {
	out := res.Stdout + "\n" + res.Stderr
	switch res.ExitCode {
	case exitConflict:
		return "Ya existe en la VM un servicio con ese nombre que no pertenece a esta consola. Elija otro nombre."
	case exitUserClash:
		return "Ya existe en la VM un usuario del sistema con ese nombre. Elija otro nombre de servicio."
	case exitNoUpload:
		return "El ejecutable no llegó a la VM. Vuelva a intentarlo."
	case exitUnitBad:
		return "systemd rechazó la unidad generada. Revise el detalle técnico."
	case exitNotManaged:
		return "Ese servicio no es administrado por esta consola (solo se gestionan los que ella despliega)."
	case exitFailed:
		return "systemd no pudo completar la acción o el servicio no quedó activo. Revise el detalle técnico (incluye el registro de journalctl)."
	}
	switch {
	case strings.Contains(out, "No space left"):
		return "No hay espacio en disco en la VM."
	case strings.Contains(out, "tar:"):
		return "No se pudieron extraer los archivos adicionales en la VM. Revise el detalle técnico."
	}
	return "La operación terminó con error. Revise el detalle técnico para el diagnóstico."
}
