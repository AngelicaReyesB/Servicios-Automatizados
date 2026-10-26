package servicios

// Ejecuta los scripts reales con bash contra systemctl/useradd/etc. FALSOS que
// trabajan sobre una carpeta temporal: nunca tocan el sistema de pruebas.

import (
	"bytes"
	"encoding/base64"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"consola/internal/sshtest"
)

const fakeSystemctl = `#!/bin/bash
echo "systemctl $*" >> "$ST/calls"
quiet=0; args=()
for a in "$@"; do case "$a" in --quiet|--no-pager|-l) [ "$a" = --quiet ] && quiet=1;; *) args+=("$a");; esac; done
cmd="${args[0]}"; n="${args[1]%.service}"
case "$cmd" in
  cat) [ -f "$UNITDIR/$n.service" ] || [ -f "$ST/sysunits/$n" ] ;;
  is-active) if [ -f "$ST/active/$n" ]; then [ $quiet = 1 ] || echo active; else [ $quiet = 1 ] || echo inactive; exit 3; fi ;;
  is-enabled) if [ -f "$ST/enabled/$n" ]; then echo enabled; else echo disabled; exit 1; fi ;;
  start|restart) [ -n "$FAIL_START" ] && { echo "Job for $n.service failed" >&2; exit 1; }
                 [ -n "$CRASH" ] || { mkdir -p "$ST/active"; touch "$ST/active/$n"; } ;;
  stop) rm -f "$ST/active/$n" ;;
  enable) mkdir -p "$ST/enabled"; touch "$ST/enabled/$n" ;;
  disable) rm -f "$ST/enabled/$n" ;;
  status) echo "● $n.service - Servicio"; [ -f "$ST/active/$n" ] && echo "   Active: active (running)" || echo "   Active: inactive (dead)"; exit 3 ;;
  daemon-reload|reset-failed) ;;
esac
`
const fakeID2 = `#!/bin/bash
if [ "$1" = "-u" ]; then [ -f "$ST/users/$2" ]; exit $?; fi
[ -f "$ST/users/$1" ] && echo "uid=998($1) gid=998($1)" || exit 1
`
const fakeGetent2 = `#!/bin/bash
[ "$1" = passwd ] && [ -f "$ST/users/$2" ] && echo "$2:x:998:998::$(cat "$ST/users/$2"):/usr/sbin/nologin" || exit 2
`
const fakeUseradd2 = `#!/bin/bash
echo "useradd $*" >> "$ST/calls"
H=""; prev=""
for a in "$@"; do [ "$prev" = "--home-dir" ] && H="$a"; prev="$a"; done
echo "$H" > "$ST/users/${@: -1}"
`
const fakeUserdel2 = `#!/bin/bash
echo "userdel $*" >> "$ST/calls"; rm -f "$ST/users/$1"
`

type senv struct {
	st, bin, opt, unitdir, tmp string
	vars                       []string
}

func newSEnv(t *testing.T) *senv {
	t.Helper()
	sshtest.RequireBash(t)
	d := t.TempDir()
	e := &senv{st: d + "/st", bin: d + "/bin", opt: d + "/opt", unitdir: d + "/units", tmp: d + "/tmp"}
	for _, p := range []string{e.st + "/users", e.st + "/active", e.st + "/enabled", e.st + "/sysunits", e.bin, e.opt, e.unitdir, e.tmp} {
		if err := os.MkdirAll(p, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	for n, b := range map[string]string{"systemctl": fakeSystemctl, "id": fakeID2, "getent": fakeGetent2, "useradd": fakeUseradd2,
		"userdel": fakeUserdel2, "chown": "#!/bin/bash\nexit 0\n",
		"journalctl":      "#!/bin/bash\necho 'registro: línea 1'\n",
		"systemd-analyze": "#!/bin/bash\n[ -n \"$FAIL_VERIFY\" ] && { echo 'Unknown key in section' >&2; exit 1; }\nexit 0\n"} {
		if err := os.WriteFile(filepath.Join(e.bin, n), []byte(b), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	return e
}

func (e *senv) paths() scriptPaths {
	return scriptPaths{Opt: e.opt, UnitDir: e.unitdir, Tmp: e.tmp, Wait: "0"}
}

func (e *senv) run(t *testing.T, script string) (string, string, int) {
	t.Helper()
	var out, errb bytes.Buffer
	cmd := exec.Command("bash", "-c", script)
	cmd.Env = append(os.Environ(), "PATH="+e.bin+":"+os.Getenv("PATH"), "ST="+e.st, "UNITDIR="+e.unitdir)
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

func (e *senv) exists(p string) bool { _, err := os.Stat(p); return err == nil }
func (e *senv) calls() string        { b, _ := os.ReadFile(e.st + "/calls"); return string(b) }
func (e *senv) isActive(n string) bool {
	return e.exists(e.st + "/active/" + n)
}

// stage deja en «/tmp» de la VM falsa lo que Deploy subiría.
func (e *senv) stage(t *testing.T, o DeployOptions, bin string, tgz string) string {
	t.Helper()
	_ = os.WriteFile(e.tmp+"/consola-"+o.Name+".bin", []byte(bin), 0o600)
	if tgz != "" {
		b, _ := os.ReadFile(tgz)
		_ = os.WriteFile(e.tmp+"/consola-"+o.Name+".tgz", b, 0o600)
	}
	return e.paths().render(deployScript, "{{NAME}}", o.Name, "{{EXEC}}", o.ExecName,
		"{{UNIT_B64}}", base64.StdEncoding.EncodeToString([]byte(BuildUnit(o))))
}

func (e *senv) act(t *testing.T, name, action string) (string, string, int) {
	return e.run(t, e.paths().render(actionScript, "{{NAME}}", name, "{{ACTION}}", action))
}

func sopts() DeployOptions {
	return DeployOptions{Name: "catalogo", Kind: KindSimple, Args: "-port 8080", ExecName: "catalogo"}
}

func TestDeployScriptInstallsEverything(t *testing.T) {
	e := newSEnv(t)
	o := sopts()
	tgz := filepath.Join(t.TempDir(), "x.tgz")
	if err := PackExtras(makeZip(t, map[string]string{"templates/a.html": "A"}, nil), "x.zip", tgz); err != nil {
		t.Fatal(err)
	}
	out, errs, code := e.run(t, e.stage(t, o, "#!/bin/sh\necho hola\n", tgz))
	if code != 0 {
		t.Fatalf("código %d\n%s\n%s", code, out, errs)
	}
	bin := e.opt + "/catalogo/catalogo"
	if st, err := os.Stat(bin); err != nil || st.Mode().Perm() != 0o755 {
		t.Errorf("ejecutable: %v %v", st, err)
	}
	if b, _ := os.ReadFile(e.opt + "/catalogo/templates/a.html"); string(b) != "A" {
		t.Errorf("archivo adicional = %q", b)
	}
	if b, _ := os.ReadFile(e.unitdir + "/catalogo.service"); string(b) != BuildUnit(o) {
		t.Errorf("unidad = %q", b)
	}
	c := e.calls()
	if !strings.Contains(c, "useradd --system --no-create-home --home-dir "+e.opt+"/catalogo --shell /usr/sbin/nologin catalogo") || !strings.Contains(c, "systemctl daemon-reload") {
		t.Errorf("llamadas:\n%s", c)
	}
	if strings.Contains(c, "systemctl start") || e.isActive("catalogo") {
		t.Error("el despliegue no debe iniciar el servicio")
	}
	if e.exists(e.tmp+"/consola-catalogo.bin") || e.exists(e.tmp+"/consola-catalogo.tgz") || e.exists(e.tmp+"/consola-verify-catalogo") {
		t.Error("deben limpiarse los temporales")
	}
	if !strings.Contains(out, "--- verificación ---") || !strings.Contains(out, "estado: inactive") {
		t.Errorf("salida:\n%s", out)
	}
}

func TestDeployScriptRedeployRestartsIfWasActive(t *testing.T) {
	e := newSEnv(t)
	o := sopts()
	if _, _, code := e.run(t, e.stage(t, o, "#!/bin/sh\nv1\n", "")); code != 0 {
		t.Fatal("primer despliegue")
	}
	_ = os.WriteFile(e.st+"/active/catalogo", nil, 0o644)
	out, errs, code := e.run(t, e.stage(t, o, "#!/bin/sh\nv2\n", ""))
	if code != 0 {
		t.Fatalf("%d\n%s", code, errs)
	}
	if b, _ := os.ReadFile(e.opt + "/catalogo/catalogo"); !strings.Contains(string(b), "v2") {
		t.Error("el binario debe reemplazarse")
	}
	c := e.calls()
	if !strings.Contains(c, "systemctl stop catalogo") || !strings.Contains(c, "systemctl start catalogo") || !e.isActive("catalogo") {
		t.Errorf("debe detener y volver a iniciar:\n%s", c)
	}
	if !strings.Contains(out, "el servicio ya existe") {
		t.Errorf("salida:\n%s", out)
	}
	if strings.Count(e.calls(), "useradd") != 1 {
		t.Error("el usuario se crea una sola vez")
	}
}

func TestDeployScriptRefusesForeignUnitsAndUsers(t *testing.T) {
	e := newSEnv(t)
	o := sopts()
	// unidad propia de otro origen en /etc/systemd/system
	_ = os.WriteFile(e.unitdir+"/catalogo.service", []byte("[Service]\nExecStart=/bin/x\n"), 0o644)
	if _, _, code := e.run(t, e.stage(t, o, "#!/bin/sh\n", "")); code != exitConflict {
		t.Errorf("unidad ajena: código %d", code)
	}
	if b, _ := os.ReadFile(e.unitdir + "/catalogo.service"); !strings.Contains(string(b), "/bin/x") {
		t.Error("no debe sobrescribirse una unidad ajena")
	}
	// servicio del sistema
	e = newSEnv(t)
	_ = os.WriteFile(e.st+"/sysunits/catalogo", nil, 0o644)
	if _, _, code := e.run(t, e.stage(t, o, "#!/bin/sh\n", "")); code != exitConflict || e.exists(e.opt+"/catalogo") {
		t.Errorf("servicio del sistema: código %d", code)
	}
	// usuario ajeno
	e = newSEnv(t)
	_ = os.WriteFile(e.st+"/users/catalogo", []byte("/var/lib/otro\n"), 0o644)
	if _, _, code := e.run(t, e.stage(t, o, "#!/bin/sh\n", "")); code != exitUserClash || e.exists(e.opt+"/catalogo") {
		t.Errorf("usuario ajeno: código %d", code)
	}
	// ejecutable no subido
	e = newSEnv(t)
	script := e.paths().render(deployScript, "{{NAME}}", o.Name, "{{EXEC}}", o.ExecName, "{{UNIT_B64}}", "")
	if _, _, code := e.run(t, script); code != exitNoUpload {
		t.Errorf("sin archivo: código %d", code)
	}
}

func TestDeployScriptFailsWhenSystemdRejectsUnit(t *testing.T) {
	e := newSEnv(t)
	e.vars = []string{"FAIL_VERIFY=1"}
	_, errs, code := e.run(t, e.stage(t, sopts(), "#!/bin/sh\n", ""))
	if code != exitUnitBad || !strings.Contains(errs, "Unknown key") {
		t.Errorf("código %d\n%s", code, errs)
	}
	if e.exists(e.unitdir + "/catalogo.service") {
		t.Error("no debe instalarse una unidad inválida")
	}
}

func TestActionScripts(t *testing.T) {
	e := newSEnv(t)
	o := sopts()
	if _, _, code := e.run(t, e.stage(t, o, "#!/bin/sh\n", "")); code != 0 {
		t.Fatal("despliegue")
	}
	steps := []struct {
		act, want string
		active    bool
		enabled   bool
	}{
		{"start", "estado: active", true, false},
		{"enable", "arranque: enabled", true, true},
		{"restart", "estado: active", true, true},
		{"stop", "estado: inactive", false, true},
		{"disable", "arranque: disabled", false, false},
	}
	for _, s := range steps {
		out, errs, code := e.act(t, "catalogo", s.act)
		if code != 0 || !strings.Contains(out, "--- verificación ---") || !strings.Contains(out[strings.LastIndex(out, "--- verificación ---"):], s.want) {
			t.Fatalf("%s: código %d\n%s\n%s", s.act, code, out, errs)
		}
		if e.isActive("catalogo") != s.active || e.exists(e.st+"/enabled/catalogo") != s.enabled {
			t.Errorf("%s: activo=%v habilitado=%v", s.act, e.isActive("catalogo"), e.exists(e.st+"/enabled/catalogo"))
		}
	}
	_ = os.WriteFile(e.st+"/active/catalogo", nil, 0o644)
	out, _, code := e.act(t, "catalogo", "status")
	if code != 0 || !strings.Contains(after(out, statusMarker), "Active: active (running)") || !strings.Contains(out, "registro: línea 1") {
		t.Errorf("status (%d):\n%s", code, out)
	}
	// status de un servicio inactivo NO es error aunque systemctl devuelva 3
	_ = os.Remove(e.st + "/active/catalogo")
	if _, _, code := e.act(t, "catalogo", "status"); code != 0 {
		t.Errorf("status de servicio detenido: código %d", code)
	}
}

func TestActionScriptRefusesUnmanagedAndReportsFailures(t *testing.T) {
	e := newSEnv(t)
	_ = os.WriteFile(e.unitdir+"/ssh.service", []byte("[Service]\n"), 0o644)
	if _, errs, code := e.act(t, "ssh", "stop"); code != exitNotManaged || strings.Contains(e.calls(), "systemctl stop") {
		t.Errorf("servicio ajeno: código %d\n%s\n%s", code, errs, e.calls())
	}
	if _, _, code := e.act(t, "inexistente", "start"); code != exitNotManaged {
		t.Errorf("inexistente: código %d", code)
	}

	e = newSEnv(t)
	if _, _, code := e.run(t, e.stage(t, sopts(), "#!/bin/sh\n", "")); code != 0 {
		t.Fatal("despliegue")
	}
	e.vars = []string{"FAIL_START=1"}
	_, errs, code := e.act(t, "catalogo", "start")
	if code != exitFailed || !strings.Contains(errs, "registro: línea 1") {
		t.Errorf("fallo de start: código %d\n%s", code, errs)
	}
	// el proceso arranca pero se cae enseguida: systemctl start devuelve 0 y el servicio no queda activo
	e.vars = []string{"CRASH=1"}
	_, errs, code = e.act(t, "catalogo", "start")
	if code != exitFailed || !strings.Contains(errs, "no quedó activo") {
		t.Errorf("caída tras start: código %d\n%s", code, errs)
	}
}

func TestListScript(t *testing.T) {
	e := newSEnv(t)
	if _, _, code := e.run(t, e.stage(t, sopts(), "#!/bin/sh\n", "")); code != 0 {
		t.Fatal("despliegue")
	}
	_ = os.WriteFile(e.unitdir+"/ajeno.service", []byte("[Service]\n"), 0o644)
	_ = os.WriteFile(e.st+"/active/catalogo", nil, 0o644)
	out, _, code := e.run(t, e.paths().render(listScript))
	if code != 0 {
		t.Fatalf("código %d", code)
	}
	l := parseList(out)
	if len(l) != 1 || l[0] != (Info{"catalogo", "active", "disabled"}) {
		t.Errorf("lista = %+v\n%s", l, out)
	}
	// sin ninguna unidad
	e = newSEnv(t)
	out, _, code = e.run(t, e.paths().render(listScript))
	if code != 0 || len(parseList(out)) != 0 {
		t.Errorf("lista vacía: código %d %q", code, out)
	}
}

func TestRemoveScript(t *testing.T) {
	e := newSEnv(t)
	o := sopts()
	if _, _, code := e.run(t, e.stage(t, o, "#!/bin/sh\n", "")); code != 0 {
		t.Fatal("despliegue")
	}
	_ = os.WriteFile(e.st+"/active/catalogo", nil, 0o644)
	rm := func(files string) (string, string, int) {
		return e.run(t, e.paths().render(removeScript, "{{NAME}}", "catalogo", "{{FLAG}}", files))
	}
	out, errs, code := rm("0")
	if code != 0 || e.exists(e.unitdir+"/catalogo.service") || e.isActive("catalogo") || !e.exists(e.opt+"/catalogo/catalogo") {
		t.Fatalf("sin borrar archivos: %d\n%s\n%s", code, out, errs)
	}
	if !strings.Contains(out, "archivos conservados") {
		t.Errorf("salida:\n%s", out)
	}
	// redesplegar y borrar con archivos
	if _, _, code := e.run(t, e.stage(t, o, "#!/bin/sh\n", "")); code != 0 {
		t.Fatal("redespliegue")
	}
	out, errs, code = rm("1")
	if code != 0 || e.exists(e.opt+"/catalogo") || e.exists(e.st+"/users/catalogo") || !strings.Contains(out, "archivos eliminados") {
		t.Fatalf("borrando archivos: %d\n%s\n%s", code, out, errs)
	}
	// ya no es administrado
	if _, _, code := rm("1"); code != exitNotManaged {
		t.Errorf("segundo borrado: código %d", code)
	}
}
