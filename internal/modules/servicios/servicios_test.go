package servicios

import (
	"context"
	"encoding/base64"
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"consola/internal/oplog"
	"consola/internal/runner"
)

type upload struct {
	remote  string
	content string
	mode    os.FileMode
}

type fakeRunner struct {
	scripts []string
	uploads []upload
	res     runner.Result
	err     error
	upErr   error
}

func (f *fakeRunner) Name() string { return "SSH (fake)" }
func (f *fakeRunner) Run(_ context.Context, s string) (runner.Result, error) {
	f.scripts = append(f.scripts, s)
	return f.res, f.err
}
func (f *fakeRunner) RunInput(context.Context, string, string) (runner.Result, error) {
	return runner.Result{}, runner.ErrNotSupported
}
func (f *fakeRunner) Upload(_ context.Context, local, remote string, mode os.FileMode) error {
	b, _ := os.ReadFile(local)
	f.uploads = append(f.uploads, upload{remote, string(b), mode})
	return f.upErr
}

type fakeProvider struct{ r runner.Runner }

func (p fakeProvider) Get(string) (runner.Runner, error) { return p.r, nil }

func newSvc(t *testing.T, f *fakeRunner) *Service {
	t.Helper()
	log, err := oplog.New(filepath.Join(t.TempDir(), "ops.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { log.Close() })
	return New(fakeProvider{f}, log, "main")
}

func writeFile(t *testing.T, name, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

func validOpts(t *testing.T) DeployOptions {
	return DeployOptions{Name: "catalogo", Kind: KindSimple, Args: "-port 8080", ExecName: "catalogo", ExecPath: writeFile(t, "catalogo", "\x7fELF....")}
}

func TestValidateExecutable(t *testing.T) {
	ok := map[string]string{"elf": "\x7fELFxxxx", "script": "#!/bin/bash\necho hi\n"}
	for n, b := range ok {
		if err := ValidateExecutable(writeFile(t, n, b)); err != nil {
			t.Errorf("%s: %v", n, err)
		}
	}
	if err := ValidateExecutable(writeFile(t, "a.exe", "MZ\x90\x00")); err == nil || !strings.Contains(err.Error(), "Windows") {
		t.Errorf("un .exe debe explicar que es de Windows: %v", err)
	}
	for _, b := range []string{"", "hola", "<html>"} {
		if err := ValidateExecutable(writeFile(t, "x", b)); err == nil {
			t.Errorf("%q debía rechazarse", b)
		}
	}
	if err := ValidateExecutable("/no/existe"); err == nil {
		t.Error("archivo inexistente")
	}
}

func TestDeployOptionsValidation(t *testing.T) {
	good := validOpts(t)
	if err := good.Validate(); err != nil {
		t.Fatal(err)
	}
	mut := map[string]func(*DeployOptions){
		"nombre vacío":     func(o *DeployOptions) { o.Name = "" },
		"nombre con mayús": func(o *DeployOptions) { o.Name = "Catalogo" },
		"nombre con punto": func(o *DeployOptions) { o.Name = "a.b" },
		"nombre inyección": func(o *DeployOptions) { o.Name = "a;reboot" },
		"nombre ruta":      func(o *DeployOptions) { o.Name = "../x" },
		"tipo":             func(o *DeployOptions) { o.Kind = "forking" },
		"exec con espacio": func(o *DeployOptions) { o.ExecName = "mi app" },
		"exec con ruta":    func(o *DeployOptions) { o.ExecName = "../app" },
		"args con ;":       func(o *DeployOptions) { o.Args = "-x; reboot" },
		"args con $":       func(o *DeployOptions) { o.Args = "$HOME" },
		"args con %":       func(o *DeployOptions) { o.Args = "%n" },
		"args con salto":   func(o *DeployOptions) { o.Args = "a\nExecStartPost=/bin/x" },
		"args con comilla": func(o *DeployOptions) { o.Args = `"a"` },
		"args largo":       func(o *DeployOptions) { o.Args = strings.Repeat("a", 201) },
		"sin archivo":      func(o *DeployOptions) { o.ExecPath = "" },
	}
	for n, m := range mut {
		o := good
		m(&o)
		if err := o.Validate(); err == nil {
			t.Errorf("%s: debía rechazarse", n)
		}
	}
}

func TestBuildUnit(t *testing.T) {
	o := validOpts(t)
	u := BuildUnit(o)
	for _, want := range []string{marker, "Type=simple", "Restart=on-failure", "User=catalogo", "WorkingDirectory=/opt/catalogo",
		"ExecStart=/opt/catalogo/catalogo -port 8080\n", "WantedBy=multi-user.target", "NoNewPrivileges=true"} {
		if !strings.Contains(u, want) {
			t.Errorf("falta %q en\n%s", want, u)
		}
	}
	o.Kind, o.Args = KindOneshot, "  "
	u = BuildUnit(o)
	if !strings.Contains(u, "Type=oneshot") || !strings.Contains(u, "RemainAfterExit=yes") || strings.Contains(u, "Restart=") || !strings.Contains(u, "ExecStart=/opt/catalogo/catalogo\n") {
		t.Errorf("oneshot:\n%s", u)
	}
}

func unitFromScript(t *testing.T, script string) string {
	m := regexp.MustCompile(`printf '%s' '([A-Za-z0-9+/=]*)' \| base64 -d`).FindStringSubmatch(script)
	if m == nil {
		t.Fatalf("sin unidad en base64:\n%s", script)
	}
	b, _ := base64.StdEncoding.DecodeString(m[1])
	return string(b)
}

func TestDeployUploadsThenRunsScript(t *testing.T) {
	f := &fakeRunner{res: runner.Result{Stdout: "--- verificación ---\nestado: inactive\n"}}
	svc := newSvc(t, f)
	o := validOpts(t)
	o.ExtraPath = writeFile(t, "extra.tgz", "TGZ")
	out := svc.Deploy(context.Background(), o)
	if !out.OK || !strings.Contains(out.Message, "desplegado") {
		t.Fatalf("%+v", out)
	}
	if len(f.uploads) != 2 || f.uploads[0].remote != "/tmp/consola-catalogo.bin" || f.uploads[1].remote != "/tmp/consola-catalogo.tgz" {
		t.Fatalf("subidas: %+v", f.uploads)
	}
	if f.uploads[0].content != "\x7fELF...." || f.uploads[0].mode != 0o600 {
		t.Errorf("contenido/modo: %+v", f.uploads[0])
	}
	if len(f.scripts) != 1 || strings.Contains(f.scripts[0], "{{") {
		t.Fatalf("script: %v", f.scripts)
	}
	if u := unitFromScript(t, f.scripts[0]); u != BuildUnit(o) {
		t.Errorf("la unidad enviada difiere:\n%s", u)
	}
	if !strings.Contains(f.scripts[0], "N=catalogo\n") || !strings.Contains(f.scripts[0], "EXE=catalogo\n") {
		t.Errorf("parámetros:\n%s", f.scripts[0])
	}
}

func TestDeployWithoutExtraUploadsOnlyBinary(t *testing.T) {
	f := &fakeRunner{}
	svc := newSvc(t, f)
	if out := svc.Deploy(context.Background(), validOpts(t)); !out.OK {
		t.Fatalf("%+v", out)
	}
	if len(f.uploads) != 1 {
		t.Errorf("subidas: %+v", f.uploads)
	}
}

func TestDeployInvalidDoesNotTouchVM(t *testing.T) {
	f := &fakeRunner{}
	svc := newSvc(t, f)
	o := validOpts(t)
	o.Name = "A B"
	if out := svc.Deploy(context.Background(), o); out.Title != "Datos no válidos" {
		t.Errorf("%+v", out)
	}
	o = validOpts(t)
	o.ExecPath = writeFile(t, "w.exe", "MZ..")
	if out := svc.Deploy(context.Background(), o); out.OK || !strings.Contains(out.Message, "Windows") {
		t.Errorf("%+v", out)
	}
	if len(f.uploads)+len(f.scripts) != 0 {
		t.Fatal("no debía tocarse la VM")
	}
}

func TestDeployFailures(t *testing.T) {
	// fallo de transferencia
	f := &fakeRunner{upErr: errors.New("sftp: sin espacio")}
	out := newSvc(t, f).Deploy(context.Background(), validOpts(t))
	if out.OK || !strings.Contains(out.Title, "transferir") || !strings.Contains(out.Detail, "sin espacio") || len(f.scripts) != 0 {
		t.Errorf("%+v", out)
	}
	// errores del script
	for code, want := range map[int]string{exitConflict: "no pertenece a esta consola", exitUserClash: "usuario del sistema", exitUnitBad: "rechazó la unidad"} {
		f := &fakeRunner{res: runner.Result{ExitCode: code, Stderr: "técnico Z"}}
		out := newSvc(t, f).Deploy(context.Background(), validOpts(t))
		if out.OK || !strings.Contains(out.Message, want) || !strings.Contains(out.Detail, "técnico Z") {
			t.Errorf("%d → %+v", code, out)
		}
	}
	// error de comunicación
	f = &fakeRunner{err: errors.New("conexión perdida")}
	out = newSvc(t, f).Deploy(context.Background(), validOpts(t))
	if out.OK || !strings.Contains(out.Title, "No se pudo ejecutar") {
		t.Errorf("%+v", out)
	}
}

func TestActValidationAndScript(t *testing.T) {
	f := &fakeRunner{res: runner.Result{Stdout: "x\n--- verificación ---\nestado: active · arranque: disabled\n"}}
	svc := newSvc(t, f)
	for _, bad := range [][2]string{{"a;b", "start"}, {"", "start"}, {"ok", "mask"}, {"ok", "start; reboot"}, {"ok", ""}} {
		if out := svc.Act(context.Background(), bad[0], bad[1]); out.Title != "Datos no válidos" {
			t.Errorf("%v → %+v", bad, out)
		}
	}
	if len(f.scripts) != 0 {
		t.Fatal("no debía ejecutarse nada")
	}
	for _, a := range Actions {
		f.scripts = nil
		out := svc.Act(context.Background(), "catalogo", a)
		if !out.OK || len(f.scripts) != 1 || !strings.Contains(f.scripts[0], "N=catalogo\n") || !strings.Contains(f.scripts[0], "ACT="+a+"\n") || strings.Contains(f.scripts[0], "{{") {
			t.Errorf("%s → %+v", a, out)
		}
	}
	out := svc.Act(context.Background(), "catalogo", "start")
	if !strings.Contains(out.Message, "iniciado") || !strings.Contains(out.Message, "estado: active") {
		t.Errorf("mensaje: %q", out.Message)
	}
}

func TestActStatusReturnsPreview(t *testing.T) {
	f := &fakeRunner{res: runner.Result{Stdout: "estado: active\n--- estado ---\n● catalogo.service - Servicio\n   Active: active (running)\n"}}
	out := newSvc(t, f).Act(context.Background(), "catalogo", "status")
	if !out.OK || !strings.Contains(out.Preview, "Active: active (running)") || strings.Contains(out.Preview, "estado: active\n---") {
		t.Errorf("%+v", out)
	}
}

func TestActFailureExplains(t *testing.T) {
	f := &fakeRunner{res: runner.Result{ExitCode: exitNotManaged, Stderr: "no es administrado"}}
	out := newSvc(t, f).Act(context.Background(), "ssh", "stop")
	if out.OK || !strings.Contains(out.Message, "no es administrado por esta consola") {
		t.Errorf("%+v", out)
	}
	f = &fakeRunner{res: runner.Result{ExitCode: exitFailed, Stderr: "journal..."}}
	out = newSvc(t, f).Act(context.Background(), "catalogo", "start")
	if out.OK || !strings.Contains(out.Message, "journalctl") || !strings.Contains(out.Detail, "journal...") {
		t.Errorf("%+v", out)
	}
}

func TestRemove(t *testing.T) {
	f := &fakeRunner{}
	svc := newSvc(t, f)
	if out := svc.Remove(context.Background(), "a;b", true); out.Title != "Datos no válidos" {
		t.Errorf("%+v", out)
	}
	out := svc.Remove(context.Background(), "catalogo", true)
	if !out.OK || !strings.Contains(f.scripts[0], "RM_FILES=1\n") || !strings.Contains(out.Message, "/opt/catalogo") {
		t.Errorf("%+v", out)
	}
	out = svc.Remove(context.Background(), "catalogo", false)
	if !strings.Contains(f.scripts[1], "RM_FILES=0\n") || !strings.Contains(out.Message, "conservaron") {
		t.Errorf("%+v", out)
	}
}

func TestListParsesOnlyValidRows(t *testing.T) {
	f := &fakeRunner{res: runner.Result{Stdout: "SVC\tcatalogo\tactive\tenabled\nruido\nSVC\tmalo nombre\tx\ty\nSVC\tregistro\tinactive\tdisabled\n"}}
	l, err := newSvc(t, f).List(context.Background())
	if err != nil || len(l) != 2 || l[0] != (Info{"catalogo", "active", "enabled"}) || l[1].Name != "registro" {
		t.Errorf("%+v %v", l, err)
	}
	if _, err := newSvc(t, &fakeRunner{err: errors.New("x")}).List(context.Background()); err == nil {
		t.Error("el error de comunicación debe propagarse")
	}
	if _, err := newSvc(t, &fakeRunner{res: runner.Result{ExitCode: 1, Stderr: "boom"}}).List(context.Background()); err == nil {
		t.Error("código distinto de cero debe dar error")
	}
}
