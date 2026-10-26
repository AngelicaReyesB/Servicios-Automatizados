// Package preparacion implementa el módulo "Preparación del sistema" (3.1).
// Incluye: 3.1.1 instalar/eliminar aplicaciones, 3.1.2 llave SSH de root
// (llaves.go), 3.1.3 mensaje de entrada /etc/issue (issue.go) y 3.1.4 nombre
// de host.
package preparacion

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"consola/internal/modules/common"
	"consola/internal/oplog"
	"consola/internal/runner"
	"consola/internal/validate"
)

const (
	module          = "Preparación del sistema"
	opTimeout       = 10 * time.Minute
	verifyMarker    = "--- verificación ---"
	hostsBackup     = "/etc/hosts.consola.bak"
	statusFormat    = `'${Package} ${Version} (${db:Status-Status})\n'`
	hostPlaceholder = "{{HOST}}"
	pkgPlaceholder  = "{{PKG}}"
)

// Provider y Outcome son los tipos compartidos de internal/modules/common.
type Provider = common.Provider

type Outcome = common.Outcome

// Options configura el módulo.
type Options struct {
	KeyDir       string // carpeta donde se guarda la llave privada de root
	RootPassword string // contraseña de root: solo se usa para comprobar que SSH ya no la acepta
}

type Service struct {
	provider KeyBackend
	log      *oplog.Logger
	target   string
	opts     Options
	mu       sync.Mutex // una operación a la vez por VM (apt usa bloqueos)
}

func New(p KeyBackend, log *oplog.Logger, target string, opts Options) *Service {
	return &Service{provider: p, log: log, target: target, opts: opts}
}

// Paquetes que esta consola nunca elimina: romperían la propia automatización.
var protectedPackages = map[string]string{
	"openssh-server":         "es el servidor SSH que usa esta consola",
	"openssh-sftp-server":    "lo usa SSH para transferir archivos",
	"ssh":                    "es el metapaquete de SSH",
	"sudo":                   "los usuarios administradores dependen de él",
	"virtualbox-guest-utils": "es el canal de comunicación (Guest Additions) previo a SSH",
	"virtualbox-guest-dkms":  "es parte de las Guest Additions",
}

const installScript = `export LC_ALL=C DEBIAN_FRONTEND=noninteractive
echo "--- estado previo ---"
dpkg-query -W -f=` + statusFormat + ` {{PKG}} 2>/dev/null || echo "{{PKG}}: no instalado"
apt-get install -y {{PKG}} || exit $?
echo "` + verifyMarker + `"
dpkg-query -W -f=` + statusFormat + ` {{PKG}} 2>/dev/null || echo "{{PKG}}: sin registro dpkg (paquete virtual)"
`

const removeScript = `export LC_ALL=C DEBIAN_FRONTEND=noninteractive
echo "--- estado previo ---"
dpkg-query -W -f=` + statusFormat + ` {{PKG}} 2>/dev/null || echo "{{PKG}}: no instalado"
apt-get remove -y {{PKG}} || exit $?
echo "` + verifyMarker + `"
dpkg-query -W -f=` + statusFormat + ` {{PKG}} 2>/dev/null || echo "{{PKG}}: ya no está en el sistema"
`

const hostnameScript = `export LC_ALL=C
NEW={{HOST}}
echo "--- estado previo ---"
echo "hostname: $(hostname)"
grep -E '^127\.' /etc/hosts
set -e
[ -f ` + hostsBackup + ` ] || cp -p /etc/hosts ` + hostsBackup + `
hostnamectl set-hostname "$NEW"
if grep -qE '^127\.0\.1\.1[[:space:]]' /etc/hosts; then
  sed -i -E "s/^127\.0\.1\.1[[:space:]].*/127.0.1.1\t$NEW/" /etc/hosts
else
  printf '127.0.1.1\t%s\n' "$NEW" >> /etc/hosts
fi
echo "` + verifyMarker + `"
echo "hostname: $(hostname)"
grep -E '^127\.' /etc/hosts
`

func (s *Service) InstallPackage(ctx context.Context, pkg string) Outcome {
	return s.packageOp(ctx, true, strings.TrimSpace(pkg))
}

func (s *Service) RemovePackage(ctx context.Context, pkg string) Outcome {
	return s.packageOp(ctx, false, strings.TrimSpace(pkg))
}

func (s *Service) packageOp(ctx context.Context, install bool, pkg string) Outcome {
	if err := validate.Package(pkg); err != nil {
		return invalid(err)
	}
	if !install {
		if why, bad := protectedPackages[pkg]; bad {
			return Outcome{
				Title:   fmt.Sprintf("Eliminación de «%s» bloqueada", pkg),
				Message: fmt.Sprintf("Esta consola no elimina «%s» porque %s.", pkg, why),
			}
		}
	}
	if !s.mu.TryLock() {
		return busy()
	}
	defer s.mu.Unlock()
	ctx, cancel := context.WithTimeout(ctx, opTimeout)
	defer cancel()

	verb, tpl, op := "instalar", installScript, "Instalar paquete "+pkg
	if !install {
		verb, tpl, op = "eliminar", removeScript, "Eliminar paquete "+pkg
	}
	res, err := s.exec(ctx, op, strings.ReplaceAll(tpl, pkgPlaceholder, pkg))
	if err != nil {
		return transportFailure(res, err)
	}
	if !res.OK() {
		return Outcome{
			Title:   fmt.Sprintf("No se pudo %s «%s»", verb, pkg),
			Message: diagnoseApt(res.Stdout + "\n" + res.Stderr),
			Detail:  detail(res),
		}
	}

	msg := fmt.Sprintf("Paquete «%s» instalado correctamente.", pkg)
	if !install {
		msg = fmt.Sprintf("Paquete «%s» eliminado correctamente.", pkg)
		if strings.Contains(res.Stdout, "is not installed, so not removed") {
			msg = fmt.Sprintf("El paquete «%s» no estaba instalado; no hubo cambios.", pkg)
		}
	}
	if v := verification(res.Stdout); v != "" {
		msg += " Estado final: " + v
	}
	return Outcome{OK: true, Title: "Operación completada", Message: msg, Detail: detail(res)}
}

// SetHostname asigna el nombre de host y actualiza /etc/hosts (3.1.4).
func (s *Service) SetHostname(ctx context.Context, host string) Outcome {
	host = strings.TrimSpace(host)
	if err := validate.Hostname(host); err != nil {
		return invalid(err)
	}
	if !s.mu.TryLock() {
		return busy()
	}
	defer s.mu.Unlock()
	ctx, cancel := context.WithTimeout(ctx, opTimeout)
	defer cancel()

	res, err := s.exec(ctx, "Asignar nombre de host "+host, strings.ReplaceAll(hostnameScript, hostPlaceholder, host))
	if err != nil {
		return transportFailure(res, err)
	}
	if !res.OK() {
		return Outcome{
			Title:   "No se pudo cambiar el nombre de host",
			Message: "El sistema rechazó el cambio. Si /etc/hosts quedó modificado, hay una copia en " + hostsBackup + ".",
			Detail:  detail(res),
		}
	}
	return Outcome{
		OK:      true,
		Title:   "Operación completada",
		Message: fmt.Sprintf("El nombre de host ahora es «%s» y /etc/hosts fue actualizado. Las sesiones abiertas muestran el cambio al reconectarse.", host),
		Detail:  detail(res),
	}
}

// exec ejecuta el script por el canal vigente y deja el registro técnico.
func (s *Service) exec(ctx context.Context, op, script string) (runner.Result, error) {
	return common.RunOn(ctx, s.log, s.provider, module, s.target, op, script)
}

// execOn ejecuta el script en un canal concreto y deja el registro técnico.
func (s *Service) execOn(ctx context.Context, r runner.Runner, op, script string) (runner.Result, error) {
	return common.Run(ctx, s.log, module, s.target, r, op, script)
}

func invalid(err error) Outcome { return common.Invalid(err) }

func busy() Outcome { return common.Busy() }

func transportFailure(res runner.Result, err error) Outcome { return common.TransportFailure(res, err) }

func detail(res runner.Result) string { return common.Detail(res) }

func verification(stdout string) string {
	i := strings.LastIndex(stdout, verifyMarker)
	if i < 0 {
		return ""
	}
	return strings.TrimSpace(stdout[i+len(verifyMarker):])
}

func diagnoseApt(out string) string {
	switch {
	case strings.Contains(out, "Unable to locate package"):
		return "El paquete no existe en los repositorios configurados. Revise el nombre o actualice los índices con apt update."
	case strings.Contains(out, "Could not get lock"), strings.Contains(out, "Unable to acquire the dpkg"):
		return "Otro proceso está usando apt/dpkg en la VM. Espere a que termine e intente de nuevo."
	case strings.Contains(out, "Temporary failure resolving"), strings.Contains(out, "Could not resolve"):
		return "La VM no resuelve nombres (sin Internet o DNS). Revise la red en modo puente."
	case strings.Contains(out, "Unable to correct problems"), strings.Contains(out, "unmet dependencies"):
		return "apt no pudo resolver las dependencias del paquete. Revise el detalle técnico."
	}
	return "apt-get terminó con error. Revise el detalle técnico para el diagnóstico."
}
