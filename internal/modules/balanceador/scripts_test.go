package balanceador

// Ejecuta los scripts reales con bash contra haproxy/systemctl/ss FALSOS que
// trabajan sobre una carpeta temporal: nunca tocan el sistema de pruebas.

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"consola/internal/sshtest"
)

const fakeHAProxy = `#!/bin/bash
case "$1" in
  -v) echo "HAProxy version 3.0.11-1 2025/01/01"; exit 0 ;;
  -c) f="$3"
      if grep -q "INVALIDO" "$f"; then echo "[ALERT] (1) : config : parsing [$f:9] : unknown keyword 'INVALIDO'" >&2; echo "[ALERT] fatal errors found in configuration." >&2; exit 1; fi
      echo "Configuration file is valid"; exit 0 ;;
esac
`
const fakeSystemctl = `#!/bin/bash
echo "systemctl $*" >> "$ST/calls"
args=(); quiet=0
for a in "$@"; do case "$a" in --quiet) quiet=1;; --no-pager|-l) ;; *) args+=("$a");; esac; done
case "${args[0]}" in
  is-active) if [ -f "$ST/active" ]; then [ $quiet = 1 ] || echo active; else [ $quiet = 1 ] || echo inactive; exit 3; fi ;;
  reload|restart) [ -n "$FAIL_RELOAD_ONCE" ] && [ ! -f "$ST/failed-once" ] && { touch "$ST/failed-once"; echo "reload falló" >&2; exit 1; }
                  [ -n "$FAIL_RELOAD" ] && [ "${args[0]}" = reload ] && { echo "reload falló" >&2; exit 1; }
                  touch "$ST/active"; cp "$CFG" "$ST/loaded.cfg" ;;
  start) [ -n "$FAIL_START" ] && { echo "start falló" >&2; exit 1; }; touch "$ST/active"; cp "$CFG" "$ST/loaded.cfg" ;;
  status) echo "● haproxy.service" ;;
esac
`
const fakeSS = `#!/bin/bash
[ -n "$NO_LISTEN" ] && exit 0
if [ -n "$OTHER_LISTENER" ]; then echo 'LISTEN 0 511 0.0.0.0:80 0.0.0.0:* users:(("nginx",pid=1,fd=6))'; exit 0; fi
echo 'LISTEN 0 4096 0.0.0.0:80 0.0.0.0:* users:(("haproxy",pid=7,fd=5))'
`

type benv struct {
	st, bin, cfg, tmp string
	vars              []string
}

func newBEnv(t *testing.T, initial string) *benv {
	t.Helper()
	sshtest.RequireBash(t)
	d := t.TempDir()
	e := &benv{st: d + "/st", bin: d + "/bin", cfg: d + "/haproxy.cfg", tmp: d + "/tmp"}
	for _, p := range []string{e.st, e.bin, e.tmp} {
		_ = os.MkdirAll(p, 0o755)
	}
	for n, b := range map[string]string{"haproxy": fakeHAProxy, "systemctl": fakeSystemctl, "ss": fakeSS,
		"journalctl": "#!/bin/bash\necho 'journal: [ALERT] cannot bind socket'\n"} {
		_ = os.WriteFile(filepath.Join(e.bin, n), []byte(b), 0o755)
	}
	_ = os.WriteFile(e.cfg, []byte(initial), 0o644)
	_ = os.WriteFile(e.st+"/active", nil, 0o644)
	return e
}

func (e *benv) paths() scriptPaths { return scriptPaths{Cfg: e.cfg, Tmp: e.tmp, Wait: "0"} }

func (e *benv) run(t *testing.T, script string) (string, string, int) {
	t.Helper()
	var out, errb bytes.Buffer
	cmd := exec.Command("bash", "-c", script)
	cmd.Env = append(os.Environ(), "PATH="+e.bin+":"+os.Getenv("PATH"), "ST="+e.st, "CFG="+e.cfg)
	cmd.Env = append(cmd.Env, e.vars...)
	cmd.Stdout, cmd.Stderr = &out, &errb
	code := 0
	if err := cmd.Run(); err != nil {
		ee, ok := err.(*exec.ExitError)
		if !ok {
			t.Fatalf("bash: %v", err)
		}
		code = ee.ExitCode()
	}
	return out.String(), errb.String(), code
}

func (e *benv) current() string { b, _ := os.ReadFile(e.cfg); return string(b) }
func (e *benv) calls() string   { b, _ := os.ReadFile(e.st + "/calls"); return string(b) }

// apply ejecuta el script de aplicar con `content` como nueva configuración y
// `expectFrom` como contenido que se supone leído antes.
func (e *benv) apply(t *testing.T, content, expectFrom string) (string, string, int) {
	sum := sha256.Sum256([]byte(expectFrom))
	return e.run(t, e.paths().render(applyScript, "{{EXPECT}}", hex.EncodeToString(sum[:]), "{{PORT}}", "80",
		"{{B64}}", base64.StdEncoding.EncodeToString([]byte(content))))
}

func TestReadScriptPrintsConfigVerbatim(t *testing.T) {
	e := newBEnv(t, debianDefault)
	out, _, code := e.run(t, e.paths().render(readScript))
	if code != 0 {
		t.Fatal(code)
	}
	if got := out[strings.Index(out, cfgMarker+"\n")+len(cfgMarker)+1:]; got != debianDefault {
		t.Errorf("la configuración debe salir byte a byte:\n%q", got)
	}
	if !strings.Contains(out, "estado: active") || !strings.Contains(out, "versión: HAProxy version 3.0.11") {
		t.Errorf("salida:\n%s", out)
	}
	// Sin HAProxy: PATH vacío (el script solo usa comandos internos de bash hasta ese punto).
	empty := t.TempDir()
	if _, errs, code := e.run(t, "PATH="+empty+"; "+e.paths().render(readScript)); code != exitNoHAProxy || !strings.Contains(errs, "no está instalado") {
		t.Errorf("sin HAProxy: código %d %s", code, errs)
	}
}

func TestApplyScriptHappyPath(t *testing.T) {
	e := newBEnv(t, debianDefault)
	p, _ := parseConfig(debianDefault, 80)
	next := p.render(buildBlock(80, []Server{{"web1", "192.168.1.10", 80}}))
	out, errs, code := e.apply(t, next, debianDefault)
	if code != 0 {
		t.Fatalf("código %d\n%s\n%s", code, out, errs)
	}
	if e.current() != next {
		t.Errorf("el archivo no quedó con la nueva configuración:\n%s", e.current())
	}
	if st, _ := os.Stat(e.cfg); st.Mode().Perm() != 0o644 {
		t.Errorf("permisos = %v", st.Mode().Perm())
	}
	if b, _ := os.ReadFile(e.cfg + ".consola.bak"); string(b) != debianDefault {
		t.Error("debe guardarse el original una sola vez")
	}
	if !strings.Contains(e.calls(), "systemctl reload haproxy") {
		t.Errorf("con HAProxy activo se recarga:\n%s", e.calls())
	}
	if l, _ := os.ReadFile(e.st + "/loaded.cfg"); string(l) != next {
		t.Error("lo cargado debe ser la nueva configuración")
	}
	for _, want := range []string{"--- verificación ---", "validación: Configuration file is valid", "estado: active", "escuchando: LISTEN", "server web1 192.168.1.10:80 check"} {
		if !strings.Contains(out, want) {
			t.Errorf("falta %q en la salida:\n%s", want, out)
		}
	}
	if ents, _ := os.ReadDir(e.tmp); len(ents) != 0 {
		t.Errorf("deben limpiarse los temporales: %v", ents)
	}
	// segunda aplicación: el respaldo sigue siendo el original
	next2 := p.render(buildBlock(80, nil))
	if _, _, code := e.apply(t, next2, next); code != 0 {
		t.Fatal("segunda aplicación")
	}
	if b, _ := os.ReadFile(e.cfg + ".consola.bak"); string(b) != debianDefault {
		t.Error("el respaldo no debe sobrescribirse")
	}
}

func TestApplyScriptStartsHAProxyWhenStopped(t *testing.T) {
	e := newBEnv(t, debianDefault)
	_ = os.Remove(e.st + "/active")
	if _, errs, code := e.apply(t, debianDefault+"# x\n", debianDefault); code != 0 {
		t.Fatalf("%d %s", code, errs)
	}
	if !strings.Contains(e.calls(), "systemctl start haproxy") {
		t.Errorf("debe iniciarlo:\n%s", e.calls())
	}
}

func TestApplyScriptRejectsInvalidConfigWithoutTouchingAnything(t *testing.T) {
	e := newBEnv(t, debianDefault)
	_, errs, code := e.apply(t, debianDefault+"INVALIDO\n", debianDefault)
	if code != exitInvalid || !strings.Contains(errs, "unknown keyword") {
		t.Errorf("código %d\n%s", code, errs)
	}
	if e.current() != debianDefault || strings.Contains(e.calls(), "reload") {
		t.Error("una configuración inválida no debe aplicarse ni recargarse")
	}
	if _, err := os.Stat(e.cfg + ".consola.bak"); err == nil {
		t.Error("no debe crearse respaldo si no se aplicó nada")
	}
}

func TestApplyScriptRefusesWhenFileChangedMeanwhile(t *testing.T) {
	e := newBEnv(t, debianDefault+"# alguien editó\n")
	_, errs, code := e.apply(t, "otra cosa\n", debianDefault)
	if code != exitChanged || !strings.Contains(errs, "cambió") || e.current() != debianDefault+"# alguien editó\n" {
		t.Errorf("código %d\n%s", code, errs)
	}
}

func TestApplyScriptRestoresOnReloadFailure(t *testing.T) {
	e := newBEnv(t, debianDefault)
	e.vars = []string{"FAIL_RELOAD=1"}
	_, errs, code := e.apply(t, debianDefault+"# nuevo\n", debianDefault)
	if code != exitReload || !strings.Contains(errs, "Se restauró") || !strings.Contains(errs, "journal:") {
		t.Errorf("código %d\n%s", code, errs)
	}
	if e.current() != debianDefault {
		t.Errorf("debe restaurarse el archivo anterior:\n%s", e.current())
	}
}

func TestApplyScriptRestoresWhenNotListening(t *testing.T) {
	for name, v := range map[string]string{"nadie escucha": "NO_LISTEN=1", "otro programa en el puerto": "OTHER_LISTENER=1"} {
		e := newBEnv(t, debianDefault)
		e.vars = []string{v}
		_, errs, code := e.apply(t, debianDefault+"# nuevo\n", debianDefault)
		if code != exitReload || !strings.Contains(errs, "no está escuchando en el puerto 80") || e.current() != debianDefault {
			t.Errorf("%s: código %d\n%s\nconfig=%q", name, code, errs, e.current())
		}
	}
}

func TestApplyScriptRestoresWhenStartFailsAndKeepsStopped(t *testing.T) {
	e := newBEnv(t, debianDefault)
	_ = os.Remove(e.st + "/active")
	e.vars = []string{"FAIL_START=1"}
	_, _, code := e.apply(t, debianDefault+"# nuevo\n", debianDefault)
	if code != exitReload || e.current() != debianDefault {
		t.Errorf("código %d config=%q", code, e.current())
	}
}
