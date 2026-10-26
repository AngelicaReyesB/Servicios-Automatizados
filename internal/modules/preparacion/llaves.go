package preparacion

// 3.1.2 Configuración de la llave de acceso SSH para el usuario root.
//
// Orden de seguridad (nunca se bloquea la contraseña antes de comprobar que la
// llave funciona):
//
//  1. Se genera el par ed25519 en el host y se guarda con extensión .new.
//  2. Por el canal vigente (Guest Additions) se agrega la pública a
//     authorized_keys y se permite root solo con llave.
//  3. Desde el host se entra por SSH con la llave nueva. Si falla, se aborta
//     sin tocar nada más.
//  4. La llave pasa a ser la definitiva y el canal cambia a SSH.
//  5. Por SSH se desactiva la autenticación por contraseña, validando la
//     configuración (sshd -t y sshd -T) y restaurándola si algo no cuadra.
//  6. Se comprueba que un intento de entrar con contraseña es rechazado.

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"consola/internal/modules/common"
	"consola/internal/oplog"
	"consola/internal/runner"
	"consola/internal/sshkey"
)

const (
	keyComment   = "consola-root"
	downloadName = "id_ed25519_root"
)

// KeyBackend añade a Provider lo necesario para 3.1.2: comprobar la llave
// nueva antes de dar el cambio por hecho y registrar el cambio de canal.
type KeyBackend interface {
	Provider
	SSHFor(target, keyPath string) (runner.KeyProber, error)
	MarkSSHReady(target, keyPath string) error
}

// ErrNoKey indica que todavía no hay una llave que descargar.
var ErrNoKey = errors.New("todavía no se ha generado la llave: use «Generar y configurar llaves SSH»")

var (
	rePub = regexp.MustCompile(`^ssh-ed25519 [A-Za-z0-9+/]+=* ` + keyComment + `$`)

	// Ajustables en pruebas.
	verifyAttempts = 4
	retryDelay     = 1500 * time.Millisecond
)

// scriptPaths son las rutas que usan los scripts; en las pruebas se
// sustituyen por carpetas temporales y ejecutables falsos.
type scriptPaths struct{ Home, SSHDir, Sshd, Systemctl string }

var prodPaths = scriptPaths{Home: "/root", SSHDir: "/etc/ssh/sshd_config.d", Sshd: "/usr/sbin/sshd", Systemctl: "systemctl"}

func renderKeyScript(tpl string, p scriptPaths, pub string) string {
	return strings.NewReplacer(
		"{{HOME}}", p.Home, "{{SSHDIR}}", p.SSHDir, "{{SSHD}}", p.Sshd,
		"{{SYSTEMCTL}}", p.Systemctl, "{{PUB}}", pub,
	).Replace(tpl)
}

// Paso 2: autorizar la llave y permitir root solo con llave. Todavía NO toca
// PasswordAuthentication.
const installKeyScript = `export LC_ALL=C
HOME_DIR={{HOME}}
SSHD_DIR={{SSHDIR}}
SSHD={{SSHD}}
SYSTEMCTL={{SYSTEMCTL}}
PUB='{{PUB}}'
KEYS="$HOME_DIR/.ssh/authorized_keys"
DROP="$SSHD_DIR/00-consola-keys.conf"
echo "--- estado previo ---"
if [ -f "$KEYS" ]; then echo "authorized_keys: $(grep -c . "$KEYS") llave(s)"; else echo "authorized_keys: no existe"; fi
$SSHD -T 2>/dev/null | grep -E '^(permitrootlogin|passwordauthentication|pubkeyauthentication) ' || true
set -e
install -d -m 700 "$HOME_DIR/.ssh"
touch "$KEYS"
chmod 600 "$KEYS"
grep -qxF "$PUB" "$KEYS" || printf '%s\n' "$PUB" >> "$KEYS"
install -d -m 755 "$SSHD_DIR"
if [ -f "$DROP" ]; then cp -p "$DROP" "$DROP.bak"; fi
printf '%s\n' '# Gestionado por la consola de automatizacion (no editar a mano)' \
  'PermitRootLogin prohibit-password' 'PubkeyAuthentication yes' > "$DROP"
if ! $SSHD -t; then
  if [ -f "$DROP.bak" ]; then mv -f "$DROP.bak" "$DROP"; else rm -f "$DROP"; fi
  echo "sshd rechazó la configuración (sshd -t); se restauró el estado anterior" >&2
  exit 1
fi
rm -f "$DROP.bak"
if $SYSTEMCTL is-active --quiet ssh; then $SYSTEMCTL reload ssh; fi
echo "--- verificación ---"
echo "authorized_keys: $(grep -c . "$KEYS") llave(s)"
ls -ld "$HOME_DIR/.ssh" "$KEYS"
$SSHD -T | grep -E '^(permitrootlogin|pubkeyauthentication) '
`

// Paso 5: bloquear usuario y contraseña. Valida con sshd -t y con la
// configuración efectiva (sshd -T); si algo no cuadra, restaura.
const lockScript = `export LC_ALL=C
HOME_DIR={{HOME}}
SSHD_DIR={{SSHDIR}}
SSHD={{SSHD}}
SYSTEMCTL={{SYSTEMCTL}}
PUB='{{PUB}}'
KEYS="$HOME_DIR/.ssh/authorized_keys"
DROP="$SSHD_DIR/00-consola-keys.conf"
echo "--- estado previo ---"
$SSHD -T | grep -E '^(permitrootlogin|passwordauthentication|kbdinteractiveauthentication|pubkeyauthentication) ' || true
set -e
install -d -m 755 "$SSHD_DIR"
if [ -f "$DROP" ]; then cp -p "$DROP" "$DROP.bak"; fi
printf '%s\n' '# Gestionado por la consola de automatizacion (no editar a mano)' \
  'PermitRootLogin prohibit-password' 'PubkeyAuthentication yes' \
  'PasswordAuthentication no' 'KbdInteractiveAuthentication no' > "$DROP"
restore() { if [ -f "$DROP.bak" ]; then mv -f "$DROP.bak" "$DROP"; else rm -f "$DROP"; fi; }
if ! $SSHD -t; then
  restore
  echo "sshd rechazó la configuración (sshd -t); se restauró el estado anterior" >&2
  exit 1
fi
EFF=$($SSHD -T)
for want in 'passwordauthentication no' 'kbdinteractiveauthentication no' 'pubkeyauthentication yes'; do
  if ! printf '%s\n' "$EFF" | grep -qx "$want"; then
    restore
    echo "La configuración efectiva de sshd no cumple «$want»: otro archivo de configuración la contradice. Se restauró el estado anterior." >&2
    exit 1
  fi
done
if ! printf '%s\n' "$EFF" | grep -Eqx 'permitrootlogin (without-password|prohibit-password)'; then
  restore
  echo "La configuración efectiva de sshd no deja root solo con llave. Se restauró el estado anterior." >&2
  exit 1
fi
tmp=$(mktemp)
grep -v ' consola-root$' "$KEYS" > "$tmp" || true
printf '%s\n' "$PUB" >> "$tmp"
install -m 600 "$tmp" "$KEYS"
rm -f "$tmp" "$DROP.bak"
if $SYSTEMCTL is-active --quiet ssh; then $SYSTEMCTL reload ssh; fi
echo "--- verificación ---"
$SSHD -T | grep -E '^(permitrootlogin|passwordauthentication|kbdinteractiveauthentication|pubkeyauthentication) '
echo "authorized_keys: $(grep -c . "$KEYS") llave(s)"
`

// KeyStatus describe la llave de root guardada en el host.
type KeyStatus struct {
	Exists      bool
	Fingerprint string
}

func (s *Service) keyPath() string {
	return filepath.Join(s.opts.KeyDir, s.target+"_root_ed25519")
}

// KeyStatus informa si ya hay una llave configurada y su huella.
func (s *Service) KeyStatus() KeyStatus {
	pub, err := os.ReadFile(s.keyPath() + ".pub")
	if err != nil {
		return KeyStatus{}
	}
	if _, err := os.Stat(s.keyPath()); err != nil {
		return KeyStatus{}
	}
	fp, err := sshkey.Fingerprint(string(pub))
	if err != nil {
		return KeyStatus{}
	}
	return KeyStatus{Exists: true, Fingerprint: fp}
}

// PrivateKeyForDownload devuelve la llave privada para entregarla al usuario.
func (s *Service) PrivateKeyForDownload() (filename string, data []byte, err error) {
	data, err = os.ReadFile(s.keyPath())
	if errors.Is(err, fs.ErrNotExist) {
		return "", nil, ErrNoKey
	}
	if err != nil {
		return "", nil, fmt.Errorf("no se pudo leer la llave: %w", err)
	}
	s.log.Record(oplog.Entry{
		Module: module, Operation: "Descargar llave privada de root", Target: s.target,
		Channel: "host", OK: true, Stdout: "Se entregó la llave privada al usuario (el contenido no se registra).",
	})
	return downloadName, data, nil
}

// ConfigureRootKey ejecuta el flujo completo de 3.1.2.
func (s *Service) ConfigureRootKey(ctx context.Context) Outcome {
	if !s.mu.TryLock() {
		return busy()
	}
	defer s.mu.Unlock()
	ctx, cancel := context.WithTimeout(ctx, opTimeout)
	defer cancel()

	pair, err := sshkey.Generate(keyComment)
	if err != nil || !rePub.MatchString(pair.Authorized) {
		return Outcome{Title: "No se pudo generar la llave", Message: "Error interno al crear el par de llaves.", Detail: fmt.Sprint(err)}
	}
	finalPath := s.keyPath()
	newPath := finalPath + ".new"
	if err := writePair(newPath, pair); err != nil {
		return Outcome{
			Title:   "No se pudo guardar la llave en este equipo",
			Message: fmt.Sprintf("No se pudo escribir en %s. Verifique los permisos de esa carpeta.", filepath.Dir(finalPath)),
			Detail:  err.Error(),
		}
	}
	defer removePair(newPath) // si la llave se confirma, ya no existe con este nombre

	var detailB strings.Builder

	// Paso 1: autorizar la llave por el canal vigente.
	res, err := s.exec(ctx, "Instalar llave pública de root en authorized_keys", renderKeyScript(installKeyScript, prodPaths, pair.Authorized))
	addDetail(&detailB, "Paso 1: instalar la llave pública y permitir root solo con llave", res, err)
	if err != nil {
		o := transportFailure(res, err)
		o.Detail += "\n\n" + detailB.String()
		return o
	}
	if !res.OK() {
		return Outcome{Title: "No se pudo instalar la llave pública", Message: diagnoseKeys(res.Stdout + "\n" + res.Stderr), Detail: detailB.String()}
	}

	// Paso 2: entrar por SSH con la llave nueva ANTES de bloquear nada.
	probe, err := s.provider.SSHFor(s.target, newPath)
	if err != nil {
		return Outcome{Title: "No se pudo preparar la conexión SSH", Message: err.Error()}
	}
	verified := false
	var vres runner.Result
	var verr error
	for attempt := 1; attempt <= verifyAttempts; attempt++ {
		vres, verr = s.execOn(ctx, probe, "Comprobar acceso por SSH con la llave nueva", "id -un")
		if verr == nil && vres.OK() && strings.TrimSpace(vres.Stdout) == "root" {
			verified = true
			break
		}
		if attempt < verifyAttempts && !sleep(ctx, retryDelay) {
			break
		}
	}
	addDetail(&detailB, "Paso 2: comprobar el acceso por SSH con la llave nueva", vres, verr)
	if !verified {
		return Outcome{
			Title: "La llave quedó instalada, pero no se pudo entrar por SSH con ella",
			Message: "No se completó el bloqueo de contraseñas ni se cambió de canal: la consola sigue usando Guest Additions. " +
				"Verifique que la IP de config.json sea la de la VM, que el adaptador esté en modo puente, " +
				"que el servicio SSH esté activo y que el firewall de Windows no bloquee el puerto 22. Luego vuelva a intentarlo.",
			Detail: detailB.String(),
		}
	}

	// Paso 3: la llave pasa a ser la definitiva y el canal cambia a SSH.
	if err := commitPair(newPath, finalPath); err != nil {
		return Outcome{Title: "No se pudo guardar la llave definitiva", Message: "La llave funciona en la VM, pero no se pudo guardar en este equipo. Vuelva a intentarlo.", Detail: err.Error()}
	}
	if err := s.provider.MarkSSHReady(s.target, finalPath); err != nil {
		return Outcome{Title: "No se pudo registrar el cambio de canal", Message: "La llave se guardó, pero no se pudo recordar que la VM ya usa SSH.", Detail: err.Error()}
	}
	final, err := s.provider.SSHFor(s.target, finalPath)
	if err != nil {
		return Outcome{Title: "No se pudo preparar la conexión SSH", Message: err.Error()}
	}

	// Paso 4: bloquear usuario y contraseña (ya por SSH).
	lres, lerr := s.execOn(ctx, final, "Bloquear el acceso por usuario y contraseña en SSH", renderKeyScript(lockScript, prodPaths, pair.Authorized))
	addDetail(&detailB, "Paso 3: bloquear el acceso por usuario y contraseña", lres, lerr)
	const lockTitle = "La llave funciona, pero no se pudo bloquear el acceso por contraseña"
	if lerr != nil {
		return Outcome{Title: lockTitle, Message: "La consola ya usa SSH con la llave, pero la conexión falló al aplicar el bloqueo. Vuelva a pulsar «Generar y configurar llaves SSH».", Detail: detailB.String()}
	}
	if !lres.OK() {
		msg := "La consola ya usa SSH con la llave. sshd no aceptó el bloqueo y se restauró su configuración anterior."
		if e := strings.TrimSpace(lres.Stderr); e != "" {
			msg += " Motivo: " + firstLine(e)
		}
		return Outcome{Title: lockTitle, Message: msg, Detail: detailB.String()}
	}

	// Paso 5: comprobar desde fuera que la contraseña ya no sirve.
	note := ""
	switch {
	case s.opts.RootPassword == "":
		note = " No se comprobó el rechazo de contraseñas porque guestPassword no está configurado."
	default:
		accepted, perr := final.PasswordLoginAccepted(ctx, s.opts.RootPassword)
		s.recordProbe(accepted, perr)
		switch {
		case perr != nil:
			note = " No se pudo repetir la comprobación de rechazo de contraseñas (" + firstLine(perr.Error()) + "), pero la configuración efectiva de sshd sí la desactiva."
			fmt.Fprintf(&detailB, "\n=== Paso 4: intento de entrar con contraseña ===\nNo concluyente: %v\n", perr)
		case accepted:
			fmt.Fprintf(&detailB, "\n=== Paso 4: intento de entrar con contraseña ===\nEl servidor ACEPTÓ la contraseña.\n")
			return Outcome{
				Title: "El servidor SSH todavía acepta usuario y contraseña",
				Message: "La llave funciona y la consola ya usa SSH, pero un intento de entrar con contraseña tuvo éxito. " +
					"Revise /etc/ssh/sshd_config y los archivos de /etc/ssh/sshd_config.d: alguna directiva puede estar anulando el bloqueo.",
				Detail: detailB.String(),
			}
		default:
			note = " Se comprobó que un intento de entrar con usuario y contraseña es rechazado."
			fmt.Fprintf(&detailB, "\n=== Paso 4: intento de entrar con contraseña ===\nRechazado por el servidor (correcto).\n")
		}
	}

	return Outcome{
		OK:    true,
		Title: "Operación completada",
		Message: fmt.Sprintf("Llave SSH ed25519 creada e instalada para root (huella %s). SSH ya no admite usuario y contraseña.%s "+
			"Desde ahora la consola se comunica con la VM solo por SSH con llave. Descargue la llave privada y guárdela en un lugar seguro.",
			pair.Fingerprint, note),
		Detail: detailB.String(),
	}
}

func (s *Service) recordProbe(accepted bool, err error) {
	e := oplog.Entry{
		Module: module, Operation: "Comprobar que SSH rechaza usuario y contraseña", Target: s.target,
		Channel: runner.ChannelSSH, OK: err == nil && !accepted,
	}
	switch {
	case err != nil:
		e.Error = err.Error()
	case accepted:
		e.Stdout = "El servidor aceptó la contraseña (no debería)."
	default:
		e.Stdout = "El servidor rechazó el intento de entrar con contraseña (correcto)."
	}
	s.log.Record(e)
}

func diagnoseKeys(out string) string {
	switch {
	case strings.Contains(out, "sshd rechazó la configuración"):
		return "sshd rechazó la configuración (sshd -t); se restauró el estado anterior. Revise el detalle técnico."
	case strings.Contains(out, "No such file") || strings.Contains(out, "not found"):
		return "No se encontró el servidor SSH en la VM. Verifique que openssh-server esté instalado."
	}
	return "No se pudo instalar la llave pública de root. No se hizo ningún cambio definitivo; revise el detalle técnico."
}

func addDetail(b *strings.Builder, title string, res runner.Result, err error) {
	fmt.Fprintf(b, "=== %s ===\n", title)
	if err != nil {
		fmt.Fprintf(b, "Error de comunicación: %v\n", err)
		return
	}
	b.WriteString(detail(res))
}

func firstLine(s string) string { return common.FirstLine(s) }

func sleep(ctx context.Context, d time.Duration) bool {
	if d <= 0 {
		return ctx.Err() == nil
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-t.C:
		return true
	}
}

func writePair(path string, p sshkey.Pair) error { return sshkey.WritePair(path, p) }

func removePair(path string) { sshkey.RemovePair(path) }

func commitPair(from, to string) error { return sshkey.CommitPair(from, to) }
