package preparacion

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"

	"consola/internal/runner"
)

type fakeRunner struct {
	scripts []string
	res     runner.Result
	err     error
}

func (f *fakeRunner) Name() string { return "Guest Additions (fake)" }
func (f *fakeRunner) Run(_ context.Context, script string) (runner.Result, error) {
	f.scripts = append(f.scripts, script)
	return f.res, f.err
}
func (f *fakeRunner) RunInput(context.Context, string, string) (runner.Result, error) {
	return runner.Result{}, runner.ErrNotSupported
}
func (f *fakeRunner) Upload(context.Context, string, string, os.FileMode) error { return nil }

func newSvc(t *testing.T, f *fakeRunner) *Service {
	t.Helper()
	svc, _ := newSvcBackend(t, f)
	return svc
}

func TestInstallRejectsInvalidNameWithoutTouchingVM(t *testing.T) {
	f := &fakeRunner{}
	out := newSvc(t, f).InstallPackage(context.Background(), "htop; reboot")
	if out.OK || len(f.scripts) != 0 {
		t.Fatalf("no debía ejecutar nada: %+v scripts=%d", out, len(f.scripts))
	}
}

func TestInstallBuildsAptCommandAndReportsState(t *testing.T) {
	f := &fakeRunner{res: runner.Result{Stdout: "...\n--- verificación ---\nhtop 3.4.1-1 (installed)\n"}}
	out := newSvc(t, f).InstallPackage(context.Background(), " htop ")
	if !out.OK {
		t.Fatalf("debía terminar bien: %+v", out)
	}
	if len(f.scripts) != 1 || !strings.Contains(f.scripts[0], "apt-get install -y htop") || strings.Contains(f.scripts[0], "{{") {
		t.Fatalf("script inesperado: %v", f.scripts)
	}
	if !strings.Contains(out.Message, "htop 3.4.1-1 (installed)") {
		t.Errorf("el mensaje debe incluir el estado final: %q", out.Message)
	}
}

func TestInstallUnknownPackageGivesUnderstandableMessage(t *testing.T) {
	f := &fakeRunner{res: runner.Result{ExitCode: 100, Stderr: "E: Unable to locate package foo"}}
	out := newSvc(t, f).InstallPackage(context.Background(), "foo")
	if out.OK || !strings.Contains(out.Message, "no existe") {
		t.Fatalf("mensaje inesperado: %+v", out)
	}
	if !strings.Contains(out.Detail, "Unable to locate package foo") || !strings.Contains(out.Detail, "100") {
		t.Errorf("el detalle técnico debe conservar stderr y código: %q", out.Detail)
	}
}

func TestRemoveNotInstalledIsReportedAsNoChange(t *testing.T) {
	f := &fakeRunner{res: runner.Result{Stdout: "Package 'cowsay' is not installed, so not removed\n--- verificación ---\ncowsay: ya no está en el sistema\n"}}
	out := newSvc(t, f).RemovePackage(context.Background(), "cowsay")
	if !out.OK || !strings.Contains(out.Message, "no estaba instalado") {
		t.Fatalf("%+v", out)
	}
}

func TestRemoveProtectedPackageIsBlocked(t *testing.T) {
	f := &fakeRunner{}
	out := newSvc(t, f).RemovePackage(context.Background(), "openssh-server")
	if out.OK || len(f.scripts) != 0 || !strings.Contains(out.Title, "bloqueada") {
		t.Fatalf("%+v", out)
	}
}

func TestHostnameRejectsUnderscore(t *testing.T) {
	f := &fakeRunner{}
	out := newSvc(t, f).SetHostname(context.Background(), "app_web1")
	if out.OK || len(f.scripts) != 0 || !strings.Contains(out.Message, "guion") {
		t.Fatalf("%+v", out)
	}
}

func TestHostnameScript(t *testing.T) {
	f := &fakeRunner{res: runner.Result{Stdout: "--- verificación ---\nhostname: app-web1\n"}}
	out := newSvc(t, f).SetHostname(context.Background(), "app-web1")
	if !out.OK {
		t.Fatalf("%+v", out)
	}
	s := f.scripts[0]
	for _, want := range []string{"NEW=app-web1", "hostnamectl set-hostname", "/etc/hosts"} {
		if !strings.Contains(s, want) {
			t.Errorf("el script no contiene %q:\n%s", want, s)
		}
	}
}

func TestTransportErrorIsReportedClearly(t *testing.T) {
	f := &fakeRunner{err: errors.New("VBoxManage terminó con código 1: VM no encontrada")}
	out := newSvc(t, f).SetHostname(context.Background(), "app-web1")
	if out.OK || !strings.Contains(out.Title, "No se pudo ejecutar") || !strings.Contains(out.Detail, "VM no encontrada") {
		t.Fatalf("%+v", out)
	}
}
