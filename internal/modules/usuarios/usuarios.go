// Package usuarios implementa el módulo "Gestión de usuarios" (3.2):
// 3.2.1 crear usuarios (sudo y llave SSH opcionales) y 3.2.2 eliminarlos.
package usuarios

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"
	"unicode"
	"unicode/utf8"

	"consola/internal/modules/common"
	"consola/internal/oplog"
	"consola/internal/runner"
	"consola/internal/sshkey"
	"consola/internal/validate"
)

const (
	module       = "Gestión de usuarios"
	opTimeout    = 5 * time.Minute
	verifyMarker = "--- verificación ---"
)

type Outcome = common.Outcome

// Options configura el módulo.
type Options struct {
	KeyDir string // carpeta del host donde se guardan las llaves privadas
}

type Service struct {
	provider common.Provider
	log      *oplog.Logger
	target   string
	opts     Options
	mu       sync.Mutex
}

func New(p common.Provider, log *oplog.Logger, target string, opts Options) *Service {
	return &Service{provider: p, log: log, target: target, opts: opts}
}

// CreateOptions son los datos del formulario de creación.
type CreateOptions struct {
	Name   string
	Sudo   bool // casilla «privilegios de sudo»
	GenKey bool // casilla «generar llaves de autenticación»
	// Password es opcional: sirve para la consola de la VM, su y sudo. No se
	// registra en ningún log ni se escribe en el script (viaja en un archivo 0600).
	Password string
}

const (
	minPassword = 8
	maxPassword = 128
)

// validatePassword comprueba la contraseña opcional (vacía = sin contraseña).
func validatePassword(pw string) error {
	if pw == "" {
		return nil
	}
	if !utf8.ValidString(pw) {
		return errors.New("la contraseña contiene caracteres no válidos")
	}
	n := utf8.RuneCountInString(pw)
	if n < minPassword || n > maxPassword {
		return fmt.Errorf("la contraseña debe tener entre %d y %d caracteres", minPassword, maxPassword)
	}
	for _, r := range pw {
		if unicode.IsControl(r) {
			return errors.New("la contraseña no puede contener saltos de línea ni caracteres de control")
		}
	}
	return nil
}

// scriptPaths son las rutas que usan los scripts; las pruebas las sustituyen.
type scriptPaths struct{ SSHDir, Sudoers, Sshd, Systemctl, HomeBase string }

var prodPaths = scriptPaths{SSHDir: "/etc/ssh/sshd_config.d", Sudoers: "/etc/sudoers.d", Sshd: "/usr/sbin/sshd", Systemctl: "systemctl", HomeBase: "/home"}

func render(tpl string, p scriptPaths, user string, flag bool, pub string) string {
	return renderWith(tpl, p, user, flag, pub, "")
}

// renderWith además indica el archivo (en la VM) con la contraseña a aplicar.
func renderWith(tpl string, p scriptPaths, user string, flag bool, pub, pwfile string) string {
	f := "0"
	if flag {
		f = "1"
	}
	return strings.NewReplacer(
		"{{USER}}", user, "{{FLAG}}", f, "{{PUB}}", pub,
		"{{PWFILE}}", pwfile, "{{HOMEBASE}}", p.HomeBase,
		"{{SSHDIR}}", p.SSHDir, "{{SUDOERS}}", p.Sudoers, "{{SSHD}}", p.Sshd, "{{SYSTEMCTL}}", p.Systemctl,
	).Replace(tpl)
}

// Códigos de salida propios de los scripts (se traducen a mensajes).
const (
	exitExists    = 20
	exitNoSudo    = 21
	exitSSHPolicy = 22
	exitNotFound  = 23
	exitProtected = 24
	exitNoPwFile  = 25
	exitHomeLeft  = 26
)

// Crea el usuario sin contraseña (campo '*': ninguna contraseña lo acepta) o,
// si se indicó, con la contraseña del archivo PWFILE (que el script borra), y,
// si se pidió, configura sudo y la llave. Si algo falla después de crear la
// cuenta, la deshace.
const createScript = `export LC_ALL=C
U={{USER}}
WANT_SUDO={{FLAG}}
PUB='{{PUB}}'
PWFILE='{{PWFILE}}'
SSHD_DIR={{SSHDIR}}
SUDOERS={{SUDOERS}}
SSHD={{SSHD}}
SYSTEMCTL={{SYSTEMCTL}}
HOMEBASE={{HOMEBASE}}
DROP="$SSHD_DIR/10-consola-user-$U.conf"
SUDOF="$SUDOERS/consola-$U"
echo "--- estado previo ---"
CREATED=0
OK=0
undo() {
  [ -z "$PWFILE" ] || rm -f "$PWFILE"
  if [ "$OK" != 1 ] && [ "$CREATED" = 1 ]; then
    echo "Se deshacen los cambios: se elimina la cuenta «$U» recién creada" >&2
    rm -f "$SUDOF" "$SUDOF.tmp"
    if [ -f "$DROP" ]; then rm -f "$DROP"; if $SYSTEMCTL is-active --quiet ssh; then $SYSTEMCTL reload ssh; fi; fi
    userdel -r "$U" >/dev/null 2>&1 || userdel "$U" >/dev/null 2>&1 || true
  fi
}
trap undo EXIT
if [ -n "$PWFILE" ] && [ ! -f "$PWFILE" ]; then
  echo "No llegó el archivo con la contraseña a la VM" >&2
  exit 25
fi
if id -u "$U" >/dev/null 2>&1; then
  echo "El usuario «$U» ya existe: $(id "$U")" >&2
  exit 20
fi
echo "el usuario «$U» no existe"
if [ -e "$HOMEBASE/$U" ] || [ -L "$HOMEBASE/$U" ]; then
  # Un usuario nuevo con el mismo nombre heredaría los archivos del anterior.
  echo "Ya existe $HOMEBASE/$U: es el directorio personal de un usuario eliminado antes sin sus archivos" >&2
  exit 26
fi
if [ "$WANT_SUDO" = 1 ]; then
  if ! getent group sudo >/dev/null 2>&1 || ! command -v visudo >/dev/null 2>&1; then
    echo "sudo no está instalado en la VM (falta el grupo sudo o visudo)" >&2
    exit 21
  fi
fi
set -e
useradd -m -s /bin/bash "$U"
CREATED=1
if [ -n "$PWFILE" ]; then chpasswd < "$PWFILE"; rm -f "$PWFILE"; else usermod -p '*' "$U"; fi
HOME_DIR=$(getent passwd "$U" | cut -d: -f6)
if [ "$WANT_SUDO" = 1 ]; then
  usermod -aG sudo "$U"
  if [ -n "$PWFILE" ]; then RULE='ALL=(ALL) ALL'; else RULE='ALL=(ALL) NOPASSWD:ALL'; fi
  printf '%s %s\n' "$U" "$RULE" > "$SUDOF.tmp"
  chmod 440 "$SUDOF.tmp"
  if ! visudo -cf "$SUDOF.tmp" >/dev/null; then echo "visudo rechazó la regla de sudo" >&2; rm -f "$SUDOF.tmp"; exit 1; fi
  mv -f "$SUDOF.tmp" "$SUDOF"
fi
if [ -n "$PUB" ]; then
  mkdir -p "$HOME_DIR/.ssh"
  chmod 700 "$HOME_DIR/.ssh"
  printf '%s\n' "$PUB" > "$HOME_DIR/.ssh/authorized_keys"
  chmod 600 "$HOME_DIR/.ssh/authorized_keys"
  chown -R "$U:$U" "$HOME_DIR/.ssh"
  # Este usuario no debe poder entrar con usuario y contraseña. Si la
  # configuración global ya lo impide (3.1.2) no se agrega nada.
  eff() { $SSHD -T -C "user=$U,host=localhost,addr=127.0.0.1"; }
  good() { local e; e=$(eff) || return 1; for w in 'passwordauthentication no' 'kbdinteractiveauthentication no' 'pubkeyauthentication yes'; do printf '%s\n' "$e" | grep -qx "$w" || return 1; done; }
  if ! good; then
    printf '%s\n' '# Gestionado por la consola de automatizacion (no editar a mano)' "Match User $U" \
      '    PasswordAuthentication no' '    KbdInteractiveAuthentication no' '    PubkeyAuthentication yes' > "$DROP"
    if ! $SSHD -t; then echo "sshd rechazó la configuración (sshd -t)" >&2; exit 22; fi
    if $SYSTEMCTL is-active --quiet ssh; then $SYSTEMCTL reload ssh; fi
    if ! good; then echo "La configuración efectiva de sshd no bloquea la contraseña de «$U»: otro archivo de configuración la contradice" >&2; exit 22; fi
  fi
fi
OK=1
echo "` + verifyMarker + `"
id "$U"
echo "home: $HOME_DIR"
if [ -n "$PWFILE" ]; then echo "contraseña: definida"; else echo "contraseña: bloqueada"; fi
if [ "$WANT_SUDO" = 1 ]; then echo "sudo: $(id -nG "$U" | tr ' ' '\n' | grep -cx sudo) grupo sudo; regla: $(cat "$SUDOF")"; else echo "sudo: no"; fi
if [ -n "$PUB" ]; then
  ls -ld "$HOME_DIR/.ssh" "$HOME_DIR/.ssh/authorized_keys"
  eff | grep -E '^(passwordauthentication|kbdinteractiveauthentication|pubkeyauthentication) '
else
  if [ -n "$PWFILE" ]; then
    echo "ssh: sin llave; contraseña por SSH según la configuración global: $($SSHD -T -C "user=$U,host=localhost,addr=127.0.0.1" 2>/dev/null | grep -E '^passwordauthentication ' || echo desconocida)"
  else
    echo "ssh: sin llave; la cuenta no tiene ninguna credencial para iniciar sesión"
  fi
fi
`

const deleteScript = `export LC_ALL=C
U={{USER}}
RM_FILES={{FLAG}}
SSHD_DIR={{SSHDIR}}
SUDOERS={{SUDOERS}}
SYSTEMCTL={{SYSTEMCTL}}
HOMEBASE={{HOMEBASE}}
echo "--- estado previo ---"
if ! id -u "$U" >/dev/null 2>&1; then
  # La cuenta ya no existe, pero puede haber quedado su directorio personal
  # (se eliminó antes sin marcar «eliminar archivos»). Solo se limpia si es un
  # directorio real, de un UID de usuario normal que ninguna cuenta usa hoy.
  ORPHAN="$HOMEBASE/$U"
  if [ "$RM_FILES" = 1 ] && [ -n "$U" ] && [ -d "$ORPHAN" ] && [ ! -L "$ORPHAN" ]; then
    OUID=$(stat -c %u "$ORPHAN")
    if [ "$OUID" -ge 1000 ] && ! getent passwd "$OUID" >/dev/null 2>&1; then
      echo "«$U» ya no existe como usuario, pero queda su directorio personal huérfano: $ORPHAN (UID $OUID)"
      set -e
      rm -rf --one-file-system "$ORPHAN"
      find /tmp /var/tmp -xdev -uid "$OUID" -delete 2>/dev/null || true
      rm -f "$SUDOERS/consola-$U"
      DROP="$SSHD_DIR/10-consola-user-$U.conf"
      if [ -f "$DROP" ]; then rm -f "$DROP"; if $SYSTEMCTL is-active --quiet ssh; then $SYSTEMCTL reload ssh; fi; fi
      echo "` + verifyMarker + `"
      if [ -d "$ORPHAN" ]; then echo "el directorio TODAVÍA existe"; else echo "directorio huérfano eliminado: $ORPHAN"; fi
      exit 0
    fi
  fi
  echo "El usuario «$U» no existe" >&2
  exit 23
fi
UID_N=$(id -u "$U")
if [ "$U" = root ] || [ "$UID_N" -lt 1000 ]; then
  echo "«$U» es una cuenta del sistema (UID $UID_N)" >&2
  exit 24
fi
HOME_DIR=$(getent passwd "$U" | cut -d: -f6)
id "$U"
echo "home: $HOME_DIR"
set -e
userdel $([ "$RM_FILES" = 1 ] && echo -r) "$U"
if [ "$RM_FILES" = 1 ]; then
  find /tmp /var/tmp -xdev -uid "$UID_N" -delete 2>/dev/null || true
fi
rm -f "$SUDOERS/consola-$U"
DROP="$SSHD_DIR/10-consola-user-$U.conf"
if [ -f "$DROP" ]; then rm -f "$DROP"; if $SYSTEMCTL is-active --quiet ssh; then $SYSTEMCTL reload ssh; fi; fi
echo "` + verifyMarker + `"
if id -u "$U" >/dev/null 2>&1; then echo "el usuario TODAVÍA existe"; else echo "el usuario ya no existe"; fi
if [ -n "$HOME_DIR" ] && [ -d "$HOME_DIR" ]; then echo "home conservado: $HOME_DIR"; else echo "home eliminado: $HOME_DIR"; fi
`

var reUserKey = func(name string) *regexp.Regexp {
	return regexp.MustCompile(`^ssh-ed25519 [A-Za-z0-9+/]+=* ` + regexp.QuoteMeta(keyComment(name)) + `$`)
}

func keyComment(name string) string { return "consola-user-" + name }

func (s *Service) keyPath(name string) string {
	return filepath.Join(s.opts.KeyDir, s.target+"_user_"+name+"_ed25519")
}

// DownloadName es el nombre con el que se entrega la llave privada.
func DownloadName(name string) string { return "id_ed25519_" + name }

// ErrNoKey indica que ese usuario no tiene llave guardada en este equipo.
var ErrNoKey = errors.New("ese usuario no tiene una llave guardada: créelo con la casilla «generar llaves» marcada")

// KeyInfo describe una llave de usuario guardada en el host.
type KeyInfo struct{ User, Fingerprint string }

// Keys lista las llaves de usuario guardadas en este equipo.
func (s *Service) Keys() []KeyInfo {
	prefix := s.target + "_user_"
	files, _ := filepath.Glob(filepath.Join(s.opts.KeyDir, prefix+"*_ed25519.pub"))
	var out []KeyInfo
	for _, f := range files {
		name := strings.TrimSuffix(strings.TrimPrefix(filepath.Base(f), prefix), "_ed25519.pub")
		if validate.Username(name) != nil {
			continue
		}
		pub, err := os.ReadFile(f)
		if err != nil {
			continue
		}
		if _, err := os.Stat(s.keyPath(name)); err != nil {
			continue
		}
		if fp, err := sshkey.Fingerprint(string(pub)); err == nil {
			out = append(out, KeyInfo{User: name, Fingerprint: fp})
		}
	}
	return out
}

// PrivateKeyForDownload entrega la llave privada del usuario.
func (s *Service) PrivateKeyForDownload(name string) (string, []byte, error) {
	if err := validate.Username(name); err != nil {
		return "", nil, err
	}
	data, err := os.ReadFile(s.keyPath(name))
	if errors.Is(err, fs.ErrNotExist) {
		return "", nil, ErrNoKey
	}
	if err != nil {
		return "", nil, fmt.Errorf("no se pudo leer la llave: %w", err)
	}
	s.log.Record(oplog.Entry{
		Module: module, Operation: "Descargar llave privada de " + name, Target: s.target,
		Channel: "host", OK: true, Stdout: "Se entregó la llave privada al usuario (el contenido no se registra).",
	})
	return DownloadName(name), data, nil
}

// CreateUser ejecuta 3.2.1.
func (s *Service) CreateUser(ctx context.Context, o CreateOptions) Outcome {
	o.Name = strings.TrimSpace(o.Name)
	if err := validate.Username(o.Name); err != nil {
		return common.Invalid(err)
	}
	if err := validatePassword(o.Password); err != nil {
		return common.Invalid(err)
	}
	if !s.mu.TryLock() {
		return common.Busy()
	}
	defer s.mu.Unlock()
	ctx, cancel := context.WithTimeout(ctx, opTimeout)
	defer cancel()

	pub, newPath := "", ""
	var pair sshkey.Pair
	if o.GenKey {
		var err error
		pair, err = sshkey.Generate(keyComment(o.Name))
		if err != nil || !reUserKey(o.Name).MatchString(pair.Authorized) {
			return Outcome{Title: "No se pudo generar la llave", Message: "Error interno al crear el par de llaves.", Detail: fmt.Sprint(err)}
		}
		pub = pair.Authorized
		newPath = s.keyPath(o.Name) + ".new"
		if err := writePair(newPath, pair); err != nil {
			return Outcome{
				Title:   "No se pudo guardar la llave en este equipo",
				Message: fmt.Sprintf("No se pudo escribir en %s. Verifique los permisos de esa carpeta.", s.opts.KeyDir),
				Detail:  err.Error(),
			}
		}
		defer removePair(newPath)
	}

	pwRemote := ""
	r, err := s.provider.Get(s.target)
	if err != nil {
		return common.TransportFailure(runner.Result{}, err)
	}
	if o.Password != "" {
		var out *Outcome
		if pwRemote, out = s.uploadPassword(ctx, r, o.Name, o.Password); out != nil {
			return *out
		}
	}

	res, err := common.Run(ctx, s.log, module, s.target, r, "Crear usuario "+o.Name, renderWith(createScript, prodPaths, o.Name, o.Sudo, pub, pwRemote))
	if err != nil {
		if pwRemote != "" { // el script no llegó a correr: no dejar la contraseña en /tmp
			_, _ = r.Run(context.WithoutCancel(ctx), "rm -f "+pwRemote)
		}
		return common.TransportFailure(res, err)
	}
	if !res.OK() {
		return Outcome{
			Title:   fmt.Sprintf("No se pudo crear el usuario «%s»", o.Name),
			Message: diagnose(res),
			Detail:  common.Detail(res),
		}
	}

	if o.GenKey {
		if err := commitPair(newPath, s.keyPath(o.Name)); err != nil {
			return Outcome{
				Title:   "El usuario se creó, pero no se pudo guardar su llave",
				Message: "La llave pública quedó instalada en la VM, pero la privada no se pudo guardar en este equipo. Elimine el usuario y créelo de nuevo.",
				Detail:  err.Error() + "\n\n" + common.Detail(res),
			}
		}
	}

	msg := fmt.Sprintf("Usuario «%s» creado.", o.Name)
	if o.Sudo && o.Password != "" {
		msg += " Tiene privilegios de sudo (grupo sudo y regla en /etc/sudoers.d); sudo le pide su contraseña."
	} else if o.Sudo {
		msg += " Tiene privilegios de sudo (grupo sudo y regla en /etc/sudoers.d, sin pedir contraseña porque la cuenta no tiene)."
	}
	if o.Password != "" {
		msg += " Se le asignó la contraseña indicada: sirve en la consola de la VM, con su y con sudo. Si el acceso por contraseña a SSH está deshabilitado (3.1.2), por SSH no la acepta."
	}
	out := Outcome{OK: true, Title: "Operación completada", Detail: common.Detail(res)}
	if o.GenKey {
		msg += fmt.Sprintf(" Se generó su llave SSH ed25519 (huella %s) y se instaló la pública. El acceso por usuario y contraseña está deshabilitado para esta cuenta: solo entra con la llave. Descargue la llave privada y guárdela en un lugar seguro.", pair.Fingerprint)
		out.DownloadUser = o.Name
	} else if o.Password == "" {
		msg += " No se generó llave ni se indicó contraseña: la cuenta no tiene ninguna credencial, así que todavía no puede iniciar sesión."
	}
	out.Message = msg
	return out
}

// DeleteUser ejecuta 3.2.2.
func (s *Service) DeleteUser(ctx context.Context, name string, removeFiles bool) Outcome {
	name = strings.TrimSpace(name)
	if err := validate.Username(name); err != nil {
		return common.Invalid(err)
	}
	if name == "root" {
		return Outcome{Title: "Eliminación bloqueada", Message: "Esta consola no elimina al usuario root: es el que usa para administrar la VM."}
	}
	if !s.mu.TryLock() {
		return common.Busy()
	}
	defer s.mu.Unlock()
	ctx, cancel := context.WithTimeout(ctx, opTimeout)
	defer cancel()

	res, err := common.RunOn(ctx, s.log, s.provider, module, s.target, "Eliminar usuario "+name, render(deleteScript, prodPaths, name, removeFiles, ""))
	if err != nil {
		return common.TransportFailure(res, err)
	}
	if !res.OK() {
		return Outcome{
			Title:   fmt.Sprintf("No se pudo eliminar el usuario «%s»", name),
			Message: diagnose(res),
			Detail:  common.Detail(res),
		}
	}
	msg := fmt.Sprintf("Usuario «%s» eliminado.", name)
	if strings.Contains(res.Stdout, "directorio personal huérfano") {
		msg = fmt.Sprintf("El usuario «%s» ya no existía, pero se eliminó el directorio personal que había quedado (y sus archivos temporales).", name)
	} else if removeFiles {
		msg += " También se eliminaron su directorio personal y sus archivos temporales."
	} else {
		msg += " Su directorio personal se conservó."
	}
	if hadKey := s.removeLocalKey(name); hadKey {
		msg += " Se borró su llave guardada en este equipo."
	}
	return Outcome{OK: true, Title: "Operación completada", Message: msg, Detail: common.Detail(res)}
}

func (s *Service) removeLocalKey(name string) bool {
	_, err := os.Stat(s.keyPath(name))
	removePair(s.keyPath(name))
	if err == nil {
		s.log.Record(oplog.Entry{Module: module, Operation: "Borrar llave local de " + name, Target: s.target, Channel: "host", OK: true})
	}
	return err == nil
}

func diagnose(res runner.Result) string {
	out := res.Stdout + "\n" + res.Stderr
	switch res.ExitCode {
	case exitExists:
		return "Ya existe un usuario con ese nombre en la VM. Elija otro nombre."
	case exitNoSudo:
		return "No se puede dar privilegios de sudo porque sudo no está instalado en la VM. Instálelo en «Preparación del sistema» o desmarque la casilla."
	case exitSSHPolicy:
		return "La configuración de SSH no permite bloquear la contraseña de este usuario. Se deshizo la creación; revise el detalle técnico."
	case exitNotFound:
		return "Ese usuario no existe en la VM. Si se eliminó antes conservando su directorio personal, marque «Eliminar también todos sus archivos» para limpiarlo."
	case exitHomeLeft:
		return "Quedó el directorio personal de un usuario anterior con ese nombre; si lo crea de nuevo heredaría esos archivos. Elimínelo primero: en «Eliminar usuario» envíe ese mismo nombre con la casilla «Eliminar también todos sus archivos» marcada y luego cree la cuenta."
	case exitNoPwFile:
		return "La contraseña no llegó a la VM. Intente de nuevo."
	case exitProtected:
		return "Es una cuenta del sistema (root o UID menor a 1000): esta consola no la elimina."
	}
	switch {
	case strings.Contains(out, "is currently used by process"):
		return "El usuario tiene procesos o una sesión abierta. Ciérrelos e intente de nuevo."
	case strings.Contains(out, "visudo"):
		return "visudo rechazó la regla de sudo. Se deshizo la creación."
	case strings.Contains(out, "No space left"):
		return "No hay espacio en disco en la VM."
	}
	return "La operación terminó con error. Revise el detalle técnico para el diagnóstico."
}

func writePair(path string, p sshkey.Pair) error { return sshkey.WritePair(path, p) }
func removePair(path string)                     { sshkey.RemovePair(path) }
func commitPair(from, to string) error           { return sshkey.CommitPair(from, to) }

// uploadPassword deja la contraseña en un archivo 0600 de la VM (no en el
// script, que se registra) y devuelve su ruta. El script la borra al terminar.
func (s *Service) uploadPassword(ctx context.Context, r runner.Runner, name, pw string) (string, *Outcome) {
	fail := func(detail string) (string, *Outcome) {
		return "", &Outcome{
			Title:   "No se pudo enviar la contraseña a la VM",
			Message: "Verifique que la VM esté encendida y que haya espacio en /tmp. No se creó el usuario.",
			Detail:  detail,
		}
	}
	var rnd [8]byte
	if _, err := rand.Read(rnd[:]); err != nil {
		return fail(err.Error())
	}
	f, err := os.CreateTemp("", "consola-pw-*")
	if err != nil {
		return fail(err.Error())
	}
	local := f.Name()
	defer os.Remove(local)
	_, werr := f.WriteString(name + ":" + pw + "\n")
	if cerr := f.Close(); werr == nil {
		werr = cerr
	}
	if werr != nil {
		return fail(werr.Error())
	}
	remote := "/tmp/.consola-pw-" + hex.EncodeToString(rnd[:])
	start := time.Now()
	err = r.Upload(ctx, local, remote, 0o600)
	e := oplog.Entry{Module: module, Operation: "Enviar contraseña de " + name + " (el contenido no se registra)", Target: s.target, Channel: r.Name(), OK: err == nil, DurationMS: time.Since(start).Milliseconds()}
	if err != nil {
		e.Error = err.Error()
	}
	s.log.Record(e)
	if err != nil {
		return fail("Error: " + err.Error())
	}
	return remote, nil
}
