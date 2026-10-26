package preparacion

// Ejecuta los scripts REALES de 3.1.2 con bash, apuntando a carpetas
// temporales y con "sshd" y "systemctl" falsos. Así se comprueba el
// comportamiento (idempotencia, permisos, restauración ante errores) sin una VM.

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"consola/internal/sshkey"
)

const fakeSshd = `#!/bin/bash
case "$1" in
  -t)
    if [ "${FAKE_T_FAIL:-0}" = 1 ]; then echo "sshd: error de configuración simulado" >&2; exit 255; fi
    exit 0 ;;
  -T)
    pw=""; kbd=""; prl=""; pk=""
    for f in "$FAKE_SSHD_DIR"/*.conf; do
      [ -f "$f" ] || continue
      while read -r k v; do
        case "$k" in
          PasswordAuthentication) [ -z "$pw" ] && pw=$v ;;
          KbdInteractiveAuthentication) [ -z "$kbd" ] && kbd=$v ;;
          PermitRootLogin) [ -z "$prl" ] && prl=$v ;;
          PubkeyAuthentication) [ -z "$pk" ] && pk=$v ;;
        esac
      done < "$f"
    done
    [ "${FAKE_FORCE_PW_YES:-0}" = 1 ] && pw=yes
    [ "$prl" = prohibit-password ] && prl=without-password
    echo "permitrootlogin ${prl:-without-password}"
    echo "passwordauthentication ${pw:-yes}"
    echo "kbdinteractiveauthentication ${kbd:-yes}"
    echo "pubkeyauthentication ${pk:-yes}"
    exit 0 ;;
esac
exit 64
`

const fakeSystemctl = `#!/bin/bash
case "$1" in
  is-active) exit 0 ;;
  reload) echo "$@" >> "$FAKE_LOG" ;;
esac
exit 0
`

type scriptEnv struct {
	t      *testing.T
	paths  scriptPaths
	logf   string
	sshDir string
	keys   string
}

func newScriptEnv(t *testing.T) *scriptEnv {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("estas pruebas ejecutan scripts de bash y solo corren en Linux/macOS")
	}
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skip("bash no está disponible")
	}
	dir := t.TempDir()
	bin := filepath.Join(dir, "bin")
	if err := os.MkdirAll(bin, 0o755); err != nil {
		t.Fatal(err)
	}
	for name, body := range map[string]string{"sshd": fakeSshd, "systemctl": fakeSystemctl} {
		if err := os.WriteFile(filepath.Join(bin, name), []byte(body), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	e := &scriptEnv{
		t: t,
		paths: scriptPaths{
			Home:      filepath.Join(dir, "home"),
			SSHDir:    filepath.Join(dir, "sshd_config.d"),
			Sshd:      filepath.Join(bin, "sshd"),
			Systemctl: filepath.Join(bin, "systemctl"),
		},
		logf: filepath.Join(dir, "systemctl.log"),
	}
	e.sshDir = e.paths.SSHDir
	e.keys = filepath.Join(e.paths.Home, ".ssh", "authorized_keys")
	return e
}

func (e *scriptEnv) run(tpl, pub string, env ...string) (stdout, stderr string, code int) {
	e.t.Helper()
	var out, errb bytes.Buffer
	cmd := exec.Command("bash", "-c", renderKeyScript(tpl, e.paths, pub))
	cmd.Env = append(os.Environ(), "FAKE_SSHD_DIR="+e.sshDir, "FAKE_LOG="+e.logf)
	cmd.Env = append(cmd.Env, env...)
	cmd.Stdout, cmd.Stderr = &out, &errb
	if err := cmd.Run(); err != nil {
		ee, ok := err.(*exec.ExitError)
		if !ok {
			e.t.Fatalf("no se pudo ejecutar bash: %v", err)
		}
		code = ee.ExitCode()
	}
	return out.String(), errb.String(), code
}

func (e *scriptEnv) read(path string) string {
	b, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	return string(b)
}

func (e *scriptEnv) reloads() int { return strings.Count(e.read(e.logf), "reload ssh") }
func (e *scriptEnv) dropin() string {
	return e.read(filepath.Join(e.sshDir, "00-consola-keys.conf"))
}

func newPub(t *testing.T) string {
	t.Helper()
	p, err := sshkey.Generate(keyComment)
	if err != nil {
		t.Fatal(err)
	}
	return p.Authorized
}

func TestInstallKeyScript(t *testing.T) {
	e := newScriptEnv(t)
	pub := newPub(t)

	stdout, stderr, code := e.run(installKeyScript, pub)
	if code != 0 {
		t.Fatalf("código %d\nstdout:\n%s\nstderr:\n%s", code, stdout, stderr)
	}
	if got := e.read(e.keys); got != pub+"\n" {
		t.Errorf("authorized_keys = %q", got)
	}
	for path, want := range map[string]os.FileMode{filepath.Dir(e.keys): 0o700, e.keys: 0o600} {
		if st, err := os.Stat(path); err != nil || st.Mode().Perm() != want {
			t.Errorf("permisos de %s = %v (%v), esperado %v", path, st.Mode().Perm(), err, want)
		}
	}
	d := e.dropin()
	if !strings.Contains(d, "PermitRootLogin prohibit-password") || !strings.Contains(d, "PubkeyAuthentication yes") {
		t.Errorf("drop-in inesperado:\n%s", d)
	}
	if strings.Contains(d, "PasswordAuthentication") {
		t.Error("el primer paso NO debe tocar PasswordAuthentication")
	}
	if !strings.Contains(stdout, "--- verificación ---") || !strings.Contains(stdout, "authorized_keys: 1 llave(s)") {
		t.Errorf("salida sin verificación:\n%s", stdout)
	}
	if e.reloads() != 1 {
		t.Errorf("sshd debía recargarse una vez, fue %d", e.reloads())
	}

	// Idempotente: repetir no duplica la llave.
	if _, _, code := e.run(installKeyScript, pub); code != 0 {
		t.Fatalf("segunda ejecución falló (%d)", code)
	}
	if n := strings.Count(e.read(e.keys), pub); n != 1 {
		t.Errorf("la llave aparece %d veces", n)
	}
}

func TestInstallKeyScriptRestoresWhenSshdRejectsConfig(t *testing.T) {
	e := newScriptEnv(t)
	_, stderr, code := e.run(installKeyScript, newPub(t), "FAKE_T_FAIL=1")
	if code != 1 || !strings.Contains(stderr, "sshd -t") {
		t.Fatalf("código %d, stderr %q", code, stderr)
	}
	if e.dropin() != "" {
		t.Errorf("debía eliminarse el drop-in inválido:\n%s", e.dropin())
	}
	if e.reloads() != 0 {
		t.Error("no debe recargarse sshd con una configuración rechazada")
	}
}

func TestLockScriptDisablesPasswordsAndKeepsOtherKeys(t *testing.T) {
	e := newScriptEnv(t)
	oldPub, pub := newPub(t), newPub(t)
	if _, stderr, code := e.run(installKeyScript, oldPub); code != 0 {
		t.Fatalf("instalación: %d %s", code, stderr)
	}
	other := "ssh-rsa AAAAOTHERKEY usuario@pc"
	if err := os.WriteFile(e.keys, []byte(other+"\n"+oldPub+"\n"+pub+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	stdout, stderr, code := e.run(lockScript, pub)
	if code != 0 {
		t.Fatalf("código %d\nstdout:\n%s\nstderr:\n%s", code, stdout, stderr)
	}
	// Se conserva la llave ajena, desaparece la anterior de la consola y queda solo la nueva.
	if got, want := e.read(e.keys), other+"\n"+pub+"\n"; got != want {
		t.Errorf("authorized_keys:\n%q\nesperado:\n%q", got, want)
	}
	if st, _ := os.Stat(e.keys); st == nil || st.Mode().Perm() != 0o600 {
		t.Error("authorized_keys debe quedar con permisos 600")
	}
	d := e.dropin()
	for _, want := range []string{"PasswordAuthentication no", "KbdInteractiveAuthentication no", "PermitRootLogin prohibit-password"} {
		if !strings.Contains(d, want) {
			t.Errorf("falta %q en el drop-in:\n%s", want, d)
		}
	}
	if !strings.Contains(stdout, "passwordauthentication no") || !strings.Contains(stdout, "authorized_keys: 2 llave(s)") {
		t.Errorf("la verificación debe mostrar la configuración efectiva:\n%s", stdout)
	}
	if _, err := os.Stat(filepath.Join(e.sshDir, "00-consola-keys.conf.bak")); err == nil {
		t.Error("no debe quedar el respaldo .bak")
	}
	if e.reloads() != 2 { // una de la instalación y otra del bloqueo
		t.Errorf("recargas = %d, esperadas 2", e.reloads())
	}
}

func TestLockScriptRestoresWhenAnotherFileOverridesIt(t *testing.T) {
	e := newScriptEnv(t)
	oldPub, pub := newPub(t), newPub(t)
	if _, _, code := e.run(installKeyScript, oldPub); code != 0 {
		t.Fatal("instalación falló")
	}
	beforeDropin, beforeKeys := e.dropin(), e.read(e.keys)
	reloadsBefore := e.reloads()

	_, stderr, code := e.run(lockScript, pub, "FAKE_FORCE_PW_YES=1") // simula otra directiva que gana
	if code != 1 || !strings.Contains(stderr, "passwordauthentication no") {
		t.Fatalf("código %d, stderr %q", code, stderr)
	}
	if e.dropin() != beforeDropin {
		t.Errorf("el drop-in debía restaurarse:\n%s", e.dropin())
	}
	if e.read(e.keys) != beforeKeys {
		t.Error("authorized_keys no debe cambiar si el bloqueo no se pudo aplicar")
	}
	if strings.Contains(e.read(e.keys), pub) {
		t.Error("la llave nueva no debía agregarse en el paso de bloqueo fallido")
	}
	if e.reloads() != reloadsBefore {
		t.Error("no debe recargarse sshd si se restauró")
	}
	if _, err := os.Stat(filepath.Join(e.sshDir, "00-consola-keys.conf.bak")); err == nil {
		t.Error("no debe quedar el respaldo .bak")
	}
}

func TestLockScriptRestoresWhenSshdRejectsConfig(t *testing.T) {
	e := newScriptEnv(t)
	oldPub := newPub(t)
	if _, _, code := e.run(installKeyScript, oldPub); code != 0 {
		t.Fatal("instalación falló")
	}
	before := e.dropin()

	_, stderr, code := e.run(lockScript, newPub(t), "FAKE_T_FAIL=1")
	if code != 1 || !strings.Contains(stderr, "sshd -t") {
		t.Fatalf("código %d, stderr %q", code, stderr)
	}
	if e.dropin() != before || strings.Contains(e.dropin(), "PasswordAuthentication") {
		t.Errorf("el drop-in debía quedar como estaba:\n%s", e.dropin())
	}
}
