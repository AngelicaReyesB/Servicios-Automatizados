package usuarios

// Ejecuta los scripts reales con bash contra comandos FALSOS (id, useradd,
// userdel, sshd...) que trabajan sobre una carpeta temporal: nunca tocan el
// sistema donde corren las pruebas.

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"consola/internal/sshtest"
)

const fakeID = `#!/bin/bash
S="$ST/users"
case "$1" in
  -u) [ -f "$S/$2" ] && { sed -n 1p "$S/$2"; exit 0; } || exit 1 ;;
  -nG) [ -f "$S/$2" ] && { echo "$2 $(grep -qx "$2" "$ST/sudo_members" 2>/dev/null && echo sudo)"; exit 0; } || exit 1 ;;
  *) [ -f "$S/$1" ] && { echo "uid=$(sed -n 1p "$S/$1")($1)"; exit 0; } || exit 1 ;;
esac
`
const fakeGetent = `#!/bin/bash
case "$1" in
  group) [ -f "$ST/hassudo" ] && echo "sudo:x:27:" || exit 2 ;;
  passwd) [ -f "$ST/users/$2" ] && echo "$2:x:$(sed -n 1p "$ST/users/$2"):$(sed -n 1p "$ST/users/$2")::$ST/home/$2:/bin/bash" || exit 2 ;;
esac
`
const fakeUseradd = `#!/bin/bash
echo "$@" >> "$ST/calls"
U="${@: -1}"
[ -n "$FAIL_USERADD" ] && { echo "useradd: fallo simulado" >&2; exit 9; }
echo 1001 > "$ST/users/$U"
mkdir -p "$ST/home/$U"
`
const fakeUsermod = `#!/bin/bash
echo "usermod $@" >> "$ST/calls"
if [ "$1" = "-aG" ]; then echo "$3" >> "$ST/sudo_members"; fi
`
const fakeUserdel = `#!/bin/bash
echo "userdel $@" >> "$ST/calls"
if [ "$1" = "-r" ]; then U="$2"; rm -rf "$ST/home/$U"; else U="$1"; fi
rm -f "$ST/users/$U"
`
const fakeVisudo = `#!/bin/bash
[ -n "$FAIL_VISUDO" ] && { echo "visudo: error de sintaxis" >&2; exit 1; }
exit 0
`
const fakeSshd = `#!/bin/bash
[ "$1" = "-t" ] && { [ -n "$FAIL_SSHD_T" ] && exit 1; exit 0; }
# sshd -T -C user=NAME,host=...,addr=...
U=$(printf '%s' "$3" | sed -E 's/^user=([^,]*),.*/\1/')
pw=$GLOBAL_PW
if [ -z "$IGNORE_DROP" ] && ls "$SSHDIR"/10-consola-user-"$U".conf >/dev/null 2>&1; then pw=no; fi
echo "pubkeyauthentication yes"
echo "passwordauthentication $pw"
echo "kbdinteractiveauthentication $pw"
`
const fakeChpasswd = `#!/bin/bash
[ -n "$FAIL_CHPASSWD" ] && { echo "chpasswd: fallo simulado" >&2; exit 1; }
echo "chpasswd: $(cat)" >> "$ST/calls"
`
const fakeStat = `#!/bin/bash
echo "${FAKE_UID:-1001}"
`
const fakeFind = `#!/bin/bash
echo "find $@" >> "$ST/calls"
`

type env struct {
	st, bin, sshd, sudoers string
	vars                   []string
}

func newEnv(t *testing.T) *env {
	t.Helper()
	sshtest.RequireBash(t)
	d := t.TempDir()
	e := &env{st: filepath.Join(d, "st"), bin: filepath.Join(d, "bin"), sshd: filepath.Join(d, "sshd.d"), sudoers: filepath.Join(d, "sudoers.d")}
	for _, p := range []string{e.st + "/users", e.st + "/home", e.bin, e.sshd, e.sudoers} {
		if err := os.MkdirAll(p, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	for name, body := range map[string]string{"id": fakeID, "getent": fakeGetent, "useradd": fakeUseradd, "usermod": fakeUsermod,
		"userdel": fakeUserdel, "visudo": fakeVisudo, "sshd": fakeSshd, "find": fakeFind, "chpasswd": fakeChpasswd, "stat": fakeStat, "chown": "#!/bin/bash\nexit 0\n",
		"systemctl": "#!/bin/bash\nexit 1\n"} {
		if err := os.WriteFile(filepath.Join(e.bin, name), []byte(body), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	e.set("hassudo", "1")
	e.vars = []string{"GLOBAL_PW=no"}
	return e
}

func (e *env) set(name, content string) {
	_ = os.WriteFile(filepath.Join(e.st, name), []byte(content), 0o644)
}
func (e *env) addUser(t *testing.T, name, uid string) {
	t.Helper()
	_ = os.WriteFile(filepath.Join(e.st, "users", name), []byte(uid+"\n"), 0o644)
	_ = os.MkdirAll(filepath.Join(e.st, "home", name), 0o755)
}
func (e *env) userExists(name string) bool {
	_, err := os.Stat(filepath.Join(e.st, "users", name))
	return err == nil
}
func (e *env) calls() string { b, _ := os.ReadFile(filepath.Join(e.st, "calls")); return string(b) }
func (e *env) exists(p string) bool {
	_, err := os.Stat(p)
	return err == nil
}

func (e *env) run(t *testing.T, script string) (stdout, stderr string, code int) {
	t.Helper()
	paths := scriptPaths{SSHDir: e.sshd, Sudoers: e.sudoers, Sshd: filepath.Join(e.bin, "sshd"), Systemctl: filepath.Join(e.bin, "systemctl")}
	_ = paths
	var out, errb bytes.Buffer
	cmd := exec.Command("bash", "-c", script)
	cmd.Env = append(os.Environ(), "PATH="+e.bin+":"+os.Getenv("PATH"), "ST="+e.st, "SSHDIR="+e.sshd)
	cmd.Env = append(cmd.Env, e.vars...)
	cmd.Stdout, cmd.Stderr = &out, &errb
	if err := cmd.Run(); err != nil {
		ee, ok := err.(*exec.ExitError)
		if !ok {
			t.Fatalf("no se pudo ejecutar bash: %v", err)
		}
		code = ee.ExitCode()
	}
	return out.String(), errb.String(), code
}

func (e *env) paths() scriptPaths {
	return scriptPaths{SSHDir: e.sshd, Sudoers: e.sudoers, Sshd: filepath.Join(e.bin, "sshd"), Systemctl: filepath.Join(e.bin, "systemctl"), HomeBase: filepath.Join(e.st, "home")}
}

const testPub = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFakeKeyForTests consola-user-ana"

func (e *env) create(t *testing.T, user string, sudo bool, pub string) (string, string, int) {
	return e.run(t, render(createScript, e.paths(), user, sudo, pub))
}
func (e *env) del(t *testing.T, user string, rm bool) (string, string, int) {
	return e.run(t, render(deleteScript, e.paths(), user, rm, ""))
}

func TestCreateScriptPlainUser(t *testing.T) {
	e := newEnv(t)
	out, errs, code := e.create(t, "ana", false, "")
	if code != 0 {
		t.Fatalf("código %d\n%s\n%s", code, out, errs)
	}
	if !e.userExists("ana") || !strings.Contains(e.calls(), "usermod -p * ana") {
		t.Errorf("el usuario debe crearse con contraseña inutilizable:\n%s", e.calls())
	}
	if e.exists(filepath.Join(e.sudoers, "consola-ana")) {
		t.Error("sin sudo no debe haber regla")
	}
	if !strings.Contains(out, "sin llave") || !strings.Contains(out, "--- verificación ---") {
		t.Errorf("salida:\n%s", out)
	}
}

func TestCreateScriptSudoAndKey(t *testing.T) {
	e := newEnv(t)
	out, errs, code := e.create(t, "ana", true, testPub)
	if code != 0 {
		t.Fatalf("código %d\n%s\n%s", code, out, errs)
	}
	rule, _ := os.ReadFile(filepath.Join(e.sudoers, "consola-ana"))
	if string(rule) != "ana ALL=(ALL) NOPASSWD:ALL\n" {
		t.Errorf("regla = %q", rule)
	}
	if st, _ := os.Stat(filepath.Join(e.sudoers, "consola-ana")); st.Mode().Perm() != 0o440 {
		t.Errorf("permisos de la regla = %v", st.Mode().Perm())
	}
	if !strings.Contains(e.calls(), "usermod -aG sudo ana") {
		t.Error("debe agregarse al grupo sudo")
	}
	ak := filepath.Join(e.st, "home", "ana", ".ssh", "authorized_keys")
	if b, _ := os.ReadFile(ak); string(b) != testPub+"\n" {
		t.Errorf("authorized_keys = %q", b)
	}
	if st, _ := os.Stat(ak); st.Mode().Perm() != 0o600 {
		t.Errorf("permisos authorized_keys = %v", st.Mode().Perm())
	}
	if st, _ := os.Stat(filepath.Dir(ak)); st.Mode().Perm() != 0o700 {
		t.Errorf("permisos .ssh = %v", st.Mode().Perm())
	}
	if e.exists(filepath.Join(e.sshd, "10-consola-user-ana.conf")) {
		t.Error("si la configuración global ya bloquea contraseñas no debe agregarse un Match")
	}
	if !strings.Contains(out, "passwordauthentication no") {
		t.Errorf("la salida debe mostrar la configuración efectiva:\n%s", out)
	}
}

func TestCreateScriptAddsMatchWhenGlobalAllowsPasswords(t *testing.T) {
	e := newEnv(t)
	e.vars = []string{"GLOBAL_PW=yes"}
	out, errs, code := e.create(t, "ana", false, testPub)
	if code != 0 {
		t.Fatalf("código %d\n%s\n%s", code, out, errs)
	}
	b, _ := os.ReadFile(filepath.Join(e.sshd, "10-consola-user-ana.conf"))
	if !strings.Contains(string(b), "Match User ana") || !strings.Contains(string(b), "PasswordAuthentication no") {
		t.Errorf("drop-in = %q", b)
	}
}

func TestCreateScriptRollsBackWhenPasswordCannotBeBlocked(t *testing.T) {
	e := newEnv(t)
	e.vars = []string{"GLOBAL_PW=yes", "IGNORE_DROP=1"}
	_, errs, code := e.create(t, "ana", true, testPub)
	if code != exitSSHPolicy {
		t.Fatalf("código %d, esperado %d\n%s", code, exitSSHPolicy, errs)
	}
	if e.userExists("ana") || e.exists(filepath.Join(e.sudoers, "consola-ana")) || e.exists(filepath.Join(e.sshd, "10-consola-user-ana.conf")) {
		t.Error("debe deshacerse todo: usuario, regla de sudo y drop-in")
	}
	if !strings.Contains(errs, "contradice") {
		t.Errorf("stderr:\n%s", errs)
	}
}

func TestCreateScriptRollsBackWhenSshdRejectsConfig(t *testing.T) {
	e := newEnv(t)
	e.vars = []string{"GLOBAL_PW=yes", "FAIL_SSHD_T=1"}
	_, _, code := e.create(t, "ana", false, testPub)
	if code != exitSSHPolicy || e.userExists("ana") || e.exists(filepath.Join(e.sshd, "10-consola-user-ana.conf")) {
		t.Errorf("código %d, existe=%v", code, e.userExists("ana"))
	}
}

func TestCreateScriptRollsBackWhenVisudoFails(t *testing.T) {
	e := newEnv(t)
	e.vars = []string{"GLOBAL_PW=no", "FAIL_VISUDO=1"}
	_, errs, code := e.create(t, "ana", true, "")
	if code == 0 || e.userExists("ana") || e.exists(filepath.Join(e.sudoers, "consola-ana")) || e.exists(filepath.Join(e.sudoers, "consola-ana.tmp")) {
		t.Errorf("código %d, stderr %s", code, errs)
	}
}

func TestCreateScriptRefusesExistingUserAndMissingSudo(t *testing.T) {
	e := newEnv(t)
	e.addUser(t, "ana", "1005")
	if _, _, code := e.create(t, "ana", false, ""); code != exitExists {
		t.Errorf("código %d, esperado %d", code, exitExists)
	}
	if strings.Contains(e.calls(), "userdel") || strings.Contains(e.calls(), "useradd") {
		t.Errorf("un usuario existente no debe tocarse:\n%s", e.calls())
	}

	e2 := newEnv(t)
	_ = os.Remove(filepath.Join(e2.st, "hassudo"))
	_, _, code := e2.create(t, "bob", true, "")
	if code != exitNoSudo || e2.userExists("bob") {
		t.Errorf("código %d existe=%v", code, e2.userExists("bob"))
	}
}

func TestDeleteScriptRemovesFilesAndLeftovers(t *testing.T) {
	e := newEnv(t)
	e.addUser(t, "ana", "1001")
	_ = os.WriteFile(filepath.Join(e.sudoers, "consola-ana"), []byte("x"), 0o440)
	_ = os.WriteFile(filepath.Join(e.sshd, "10-consola-user-ana.conf"), []byte("x"), 0o644)
	out, errs, code := e.del(t, "ana", true)
	if code != 0 {
		t.Fatalf("código %d\n%s\n%s", code, out, errs)
	}
	if e.userExists("ana") || e.exists(filepath.Join(e.st, "home", "ana")) {
		t.Error("usuario y home deben desaparecer")
	}
	if e.exists(filepath.Join(e.sudoers, "consola-ana")) || e.exists(filepath.Join(e.sshd, "10-consola-user-ana.conf")) {
		t.Error("deben borrarse la regla de sudo y el drop-in")
	}
	c := e.calls()
	if !strings.Contains(c, "userdel -r ana") || !strings.Contains(c, "find /tmp /var/tmp -xdev -uid 1001 -delete") {
		t.Errorf("llamadas:\n%s", c)
	}
	if !strings.Contains(out, "el usuario ya no existe") || !strings.Contains(out, "home eliminado") {
		t.Errorf("verificación:\n%s", out)
	}
}

func TestDeleteScriptKeepsHomeWhenNotAsked(t *testing.T) {
	e := newEnv(t)
	e.addUser(t, "ana", "1001")
	out, _, code := e.del(t, "ana", false)
	if code != 0 || e.userExists("ana") || !e.exists(filepath.Join(e.st, "home", "ana")) {
		t.Fatalf("código %d", code)
	}
	if strings.Contains(e.calls(), "userdel -r") || strings.Contains(e.calls(), "find") || !strings.Contains(out, "home conservado") {
		t.Errorf("llamadas:\n%s\nsalida:\n%s", e.calls(), out)
	}
}

func TestDeleteScriptProtectsSystemAccountsAndMissing(t *testing.T) {
	e := newEnv(t)
	e.addUser(t, "root", "0")
	e.addUser(t, "daemon", "1")
	e.addUser(t, "limite", "999")
	for _, u := range []string{"root", "daemon", "limite"} {
		if _, _, code := e.del(t, u, true); code != exitProtected || !e.userExists(u) {
			t.Errorf("%s: código %d, existe=%v", u, code, e.userExists(u))
		}
	}
	if _, _, code := e.del(t, "nadie", true); code != exitNotFound {
		t.Errorf("código %d", code)
	}
	if strings.Contains(e.calls(), "userdel") {
		t.Errorf("no debía borrarse nada:\n%s", e.calls())
	}
}

// --- contraseña opcional ---

func (e *env) createPw(t *testing.T, user string, sudo bool, pub, pw string) (string, string, int) {
	t.Helper()
	pwfile := filepath.Join(e.st, "pwfile")
	if pw != "" {
		if err := os.WriteFile(pwfile, []byte(user+":"+pw+"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return e.run(t, renderWith(createScript, e.paths(), user, sudo, pub, pwfile))
}

func TestCreateScriptWithPasswordAppliesItAndDeletesFile(t *testing.T) {
	e := newEnv(t)
	out, errs, code := e.createPw(t, "ana", false, "", "S3creta larga!")
	if code != 0 {
		t.Fatalf("código %d\n%s\n%s", code, out, errs)
	}
	calls := e.calls()
	if !strings.Contains(calls, "chpasswd: ana:S3creta larga!") {
		t.Errorf("debe aplicar la contraseña con chpasswd:\n%s", calls)
	}
	if strings.Contains(calls, "usermod -p *") {
		t.Error("con contraseña no debe bloquearse la cuenta")
	}
	if e.exists(filepath.Join(e.st, "pwfile")) {
		t.Error("el archivo con la contraseña debe borrarse")
	}
	if strings.Contains(out+errs, "S3creta") {
		t.Errorf("la salida no debe mostrar la contraseña:\n%s", out)
	}
	if !strings.Contains(out, "contraseña: definida") || !strings.Contains(out, "sin llave") {
		t.Errorf("salida:\n%s", out)
	}
}

func TestCreateScriptPasswordWithSudoAsksPassword(t *testing.T) {
	e := newEnv(t)
	if _, errs, code := e.createPw(t, "ana", true, "", "12345678"); code != 0 {
		t.Fatalf("código %d: %s", code, errs)
	}
	rule, _ := os.ReadFile(filepath.Join(e.sudoers, "consola-ana"))
	if string(rule) != "ana ALL=(ALL) ALL\n" {
		t.Errorf("con contraseña la regla no debe ser NOPASSWD: %q", rule)
	}
	// sin contraseña sigue siendo NOPASSWD
	e2 := newEnv(t)
	if _, _, code := e2.create(t, "bob", true, ""); code != 0 {
		t.Fatal("falló")
	}
	rule, _ = os.ReadFile(filepath.Join(e2.sudoers, "consola-bob"))
	if string(rule) != "bob ALL=(ALL) NOPASSWD:ALL\n" {
		t.Errorf("regla sin contraseña = %q", rule)
	}
}

func TestCreateScriptPasswordAndKeyKeepsSSHPasswordBlocked(t *testing.T) {
	e := newEnv(t)
	e.vars = []string{"GLOBAL_PW=yes"}
	out, errs, code := e.createPw(t, "ana", false, testPub, "12345678")
	if code != 0 {
		t.Fatalf("código %d\n%s\n%s", code, out, errs)
	}
	if !e.exists(filepath.Join(e.sshd, "10-consola-user-ana.conf")) {
		t.Error("con llave, la contraseña no debe valer por SSH: falta el Match User")
	}
	if !strings.Contains(e.calls(), "chpasswd: ana:12345678") {
		t.Error("la contraseña también debe aplicarse")
	}
}

func TestCreateScriptRollsBackAndDeletesPasswordFileOnFailure(t *testing.T) {
	for name, v := range map[string]string{"visudo": "FAIL_VISUDO=1", "chpasswd": "FAIL_CHPASSWD=1"} {
		e := newEnv(t)
		e.vars = append(e.vars, v)
		_, _, code := e.createPw(t, "ana", true, "", "12345678")
		if code == 0 {
			t.Fatalf("%s: debía fallar", name)
		}
		if e.userExists("ana") {
			t.Errorf("%s: la cuenta debe deshacerse", name)
		}
		if e.exists(filepath.Join(e.st, "pwfile")) {
			t.Errorf("%s: el archivo de contraseña debe borrarse", name)
		}
	}
}

func TestCreateScriptExistingUserStillDeletesPasswordFile(t *testing.T) {
	e := newEnv(t)
	e.addUser(t, "ana", "1001")
	if _, _, code := e.createPw(t, "ana", false, "", "12345678"); code != exitExists {
		t.Fatalf("código %d", code)
	}
	if e.exists(filepath.Join(e.st, "pwfile")) {
		t.Error("el archivo de contraseña no debe quedar en la VM")
	}
}

func TestCreateScriptMissingPasswordFile(t *testing.T) {
	e := newEnv(t)
	script := renderWith(createScript, e.paths(), "ana", false, "", filepath.Join(e.st, "no-existe"))
	if _, _, code := e.run(t, script); code != exitNoPwFile || e.userExists("ana") {
		t.Errorf("código %d, existe=%v", code, e.userExists("ana"))
	}
}

// --- eliminar: directorio personal huérfano ---

func (e *env) orphan(t *testing.T, name string) string {
	t.Helper()
	d := filepath.Join(e.st, "home", name)
	if err := os.MkdirAll(filepath.Join(d, "docs"), 0o755); err != nil {
		t.Fatal(err)
	}
	_ = os.WriteFile(filepath.Join(d, "docs", "a.txt"), []byte("x"), 0o644)
	return d
}

func TestDeleteScriptCleansOrphanHomeWhenAsked(t *testing.T) {
	e := newEnv(t)
	d := e.orphan(t, "ana")
	out, errs, code := e.del(t, "ana", true)
	if code != 0 {
		t.Fatalf("código %d\n%s\n%s", code, out, errs)
	}
	if e.exists(d) {
		t.Error("el directorio huérfano debe eliminarse")
	}
	if !strings.Contains(out, "directorio personal huérfano") || !strings.Contains(e.calls(), "find /tmp /var/tmp -xdev -uid 1001") {
		t.Errorf("salida/llamadas:\n%s\n%s", out, e.calls())
	}
}

func TestDeleteScriptOrphanNeedsCheckbox(t *testing.T) {
	e := newEnv(t)
	d := e.orphan(t, "ana")
	if _, _, code := e.del(t, "ana", false); code != exitNotFound {
		t.Fatalf("código %d", code)
	}
	if !e.exists(d) {
		t.Error("sin la casilla no se toca el directorio")
	}
}

func TestDeleteScriptOrphanRefusesSystemOwnerAndSymlinks(t *testing.T) {
	e := newEnv(t)
	d := e.orphan(t, "ana")
	e.vars = append(e.vars, "FAKE_UID=999") // dueño con UID de sistema
	if _, _, code := e.del(t, "ana", true); code != exitNotFound || !e.exists(d) {
		t.Errorf("código %d, existe=%v: no debe borrar directorios de UID < 1000", code, e.exists(d))
	}

	e2 := newEnv(t)
	target := filepath.Join(e2.st, "importante")
	_ = os.MkdirAll(target, 0o755)
	if err := os.Symlink(target, filepath.Join(e2.st, "home", "ana")); err != nil {
		t.Skip("sin enlaces simbólicos")
	}
	if _, _, code := e2.del(t, "ana", true); code != exitNotFound || !e2.exists(target) {
		t.Errorf("código %d: no debe seguir enlaces simbólicos", code)
	}
}

func TestDeleteScriptNoUserNoOrphan(t *testing.T) {
	e := newEnv(t)
	if _, _, code := e.del(t, "ana", true); code != exitNotFound {
		t.Fatalf("código %d", code)
	}
}

// --- crear sobre un home que quedó de un usuario anterior ---

func TestCreateScriptRefusesLeftoverHome(t *testing.T) {
	e := newEnv(t)
	d := e.orphan(t, "ana")
	_, errs, code := e.create(t, "ana", true, testPub)
	if code != exitHomeLeft {
		t.Fatalf("código %d\n%s", code, errs)
	}
	if e.userExists("ana") || strings.Contains(e.calls(), "useradd") {
		t.Error("no debe crearse la cuenta")
	}
	if !e.exists(filepath.Join(d, "docs", "a.txt")) {
		t.Error("el home viejo no debe tocarse")
	}
	if e.exists(filepath.Join(e.sudoers, "consola-ana")) {
		t.Error("no debe dejar reglas de sudo")
	}
}

func TestCreateScriptRefusesLeftoverHomeEvenIfSymlinkAndDeletesPasswordFile(t *testing.T) {
	e := newEnv(t)
	target := filepath.Join(e.st, "otro")
	_ = os.MkdirAll(target, 0o755)
	if err := os.Symlink(target, filepath.Join(e.st, "home", "ana")); err != nil {
		t.Skip("sin enlaces simbólicos")
	}
	if _, _, code := e.createPw(t, "ana", false, "", "12345678"); code != exitHomeLeft {
		t.Fatalf("código %d", code)
	}
	if e.exists(filepath.Join(e.st, "pwfile")) {
		t.Error("el archivo de contraseña debe borrarse")
	}
}

func TestDeleteThenCreateFlowThroughLeftoverHome(t *testing.T) {
	e := newEnv(t)
	if _, _, code := e.create(t, "ana", false, ""); code != 0 {
		t.Fatal("alta inicial falló")
	}
	if _, _, code := e.del(t, "ana", false); code != 0 { // se conserva el home
		t.Fatal("baja falló")
	}
	if _, _, code := e.create(t, "ana", false, ""); code != exitHomeLeft {
		t.Fatalf("recrear con el home viejo debe rechazarse, código %d", code)
	}
	if _, _, code := e.del(t, "ana", true); code != 0 { // limpieza del huérfano
		t.Fatal("la limpieza falló")
	}
	if _, errs, code := e.create(t, "ana", false, ""); code != 0 {
		t.Fatalf("con la carpeta limpia debe poder crearse: %d %s", code, errs)
	}
}
