package preparacion

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"consola/internal/oplog"
	"consola/internal/runner"
)

// fakeBackend implementa KeyBackend y anota el orden de las operaciones.
type fakeBackend struct {
	guest      runner.Runner
	events     []string
	probers    map[string]*fakeProber // "new" (llave sin confirmar) y "final"
	marked     int
	markedPath string
	sshForPath []string
	keyDir     string
}

func (b *fakeBackend) Get(string) (runner.Runner, error) {
	return &eventRunner{b: b, inner: b.guest}, nil
}

func (b *fakeBackend) SSHFor(_, keyPath string) (runner.KeyProber, error) {
	b.sshForPath = append(b.sshForPath, keyPath)
	label := "final"
	if strings.HasSuffix(keyPath, ".new") {
		label = "new"
	}
	p, ok := b.probers[label]
	if !ok {
		return nil, errors.New("sin prober " + label)
	}
	return p, nil
}

func (b *fakeBackend) MarkSSHReady(_, keyPath string) error {
	b.events = append(b.events, "mark")
	b.marked++
	b.markedPath = keyPath
	return nil
}

type eventRunner struct {
	b     *fakeBackend
	inner runner.Runner
}

func (e *eventRunner) Name() string { return e.inner.Name() }
func (e *eventRunner) Run(ctx context.Context, s string) (runner.Result, error) {
	e.b.events = append(e.b.events, "guest-run")
	return e.inner.Run(ctx, s)
}
func (e *eventRunner) RunInput(ctx context.Context, s, in string) (runner.Result, error) {
	return e.inner.RunInput(ctx, s, in)
}
func (e *eventRunner) Upload(ctx context.Context, l, r string, m os.FileMode) error {
	return e.inner.Upload(ctx, l, r, m)
}

type fakeProber struct {
	b        *fakeBackend
	label    string
	res      runner.Result
	err      error
	scripts  []string
	accepted bool
	probeErr error
}

func (p *fakeProber) Name() string { return runner.ChannelSSH }
func (p *fakeProber) Run(_ context.Context, script string) (runner.Result, error) {
	p.b.events = append(p.b.events, p.label+"-run")
	p.scripts = append(p.scripts, script)
	return p.res, p.err
}
func (p *fakeProber) RunInput(context.Context, string, string) (runner.Result, error) {
	return runner.Result{}, runner.ErrNotSupported
}
func (p *fakeProber) Upload(context.Context, string, string, os.FileMode) error { return nil }
func (p *fakeProber) PasswordLoginAccepted(context.Context, string) (bool, error) {
	p.b.events = append(p.b.events, "probe")
	return p.accepted, p.probeErr
}

func newSvcBackend(t *testing.T, guest runner.Runner) (*Service, *fakeBackend) {
	t.Helper()
	log, err := oplog.New(filepath.Join(t.TempDir(), "ops.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { log.Close() })
	b := &fakeBackend{guest: guest, probers: map[string]*fakeProber{}, keyDir: filepath.Join(t.TempDir(), "keys")}
	return New(b, log, "main", Options{KeyDir: b.keyDir, RootPassword: "1234"}), b
}

// keyFlow prepara un servicio con el flujo feliz y devuelve los dobles para
// modificarlos antes de ejecutar.
func keyFlow(t *testing.T) (*Service, *fakeBackend, *fakeRunner) {
	t.Helper()
	oldDelay, oldAttempts := retryDelay, verifyAttempts
	retryDelay, verifyAttempts = 0, 3
	t.Cleanup(func() { retryDelay, verifyAttempts = oldDelay, oldAttempts })

	guest := &fakeRunner{res: runner.Result{Stdout: "--- verificación ---\nauthorized_keys: 1 llave(s)\n"}}
	svc, b := newSvcBackend(t, guest)
	b.probers["new"] = &fakeProber{b: b, label: "new", res: runner.Result{Stdout: "root\n"}}
	b.probers["final"] = &fakeProber{b: b, label: "final", res: runner.Result{Stdout: "--- verificación ---\npasswordauthentication no\n"}}
	return svc, b, guest
}

func countOf(events []string, name string) int {
	n := 0
	for _, e := range events {
		if e == name {
			n++
		}
	}
	return n
}

func TestConfigureRootKeyHappyPath(t *testing.T) {
	svc, b, guest := keyFlow(t)
	out := svc.ConfigureRootKey(context.Background())
	if !out.OK {
		t.Fatalf("debía terminar bien: %+v", out)
	}

	// Orden de seguridad: instalar → comprobar con la llave → cambiar de canal → bloquear → sondear contraseña.
	want := []string{"guest-run", "new-run", "mark", "final-run", "probe"}
	if strings.Join(b.events, ",") != strings.Join(want, ",") {
		t.Fatalf("orden de operaciones = %v, esperado %v", b.events, want)
	}
	if b.marked != 1 || b.markedPath != filepath.Join(b.keyDir, "main_root_ed25519") {
		t.Errorf("MarkSSHReady: %d veces, ruta %q", b.marked, b.markedPath)
	}

	// La comprobación usa la llave sin confirmar; el bloqueo, la definitiva.
	if len(b.sshForPath) != 2 || !strings.HasSuffix(b.sshForPath[0], ".new") || strings.HasSuffix(b.sshForPath[1], ".new") {
		t.Errorf("rutas de llave usadas: %v", b.sshForPath)
	}

	// La contraseña NO se bloquea en el primer paso, solo en el segundo.
	install, lock := guest.scripts[0], b.probers["final"].scripts[0]
	if strings.Contains(install, "PasswordAuthentication no") || !strings.Contains(install, "PermitRootLogin prohibit-password") {
		t.Errorf("el script de instalación no debe bloquear la contraseña todavía:\n%s", install)
	}
	if !strings.Contains(lock, "PasswordAuthentication no") || !strings.Contains(lock, "KbdInteractiveAuthentication no") {
		t.Errorf("el script de bloqueo debe desactivar la contraseña:\n%s", lock)
	}
	if strings.Contains(install+lock, "{{") {
		t.Error("quedaron marcas sin reemplazar en los scripts")
	}

	// Archivos locales: definitiva presente, temporal ausente, y la pública coincide con la autorizada.
	final := filepath.Join(b.keyDir, "main_root_ed25519")
	priv, err := os.ReadFile(final)
	if err != nil || !strings.HasPrefix(string(priv), "-----BEGIN OPENSSH PRIVATE KEY-----") {
		t.Fatalf("llave privada guardada incorrectamente: %v", err)
	}
	pub, _ := os.ReadFile(final + ".pub")
	if !strings.Contains(install, strings.TrimSpace(string(pub))) || !strings.Contains(lock, strings.TrimSpace(string(pub))) {
		t.Error("la pública guardada no es la que se instaló en la VM")
	}
	for _, p := range []string{final + ".new", final + ".new.pub"} {
		if _, err := os.Stat(p); err == nil {
			t.Errorf("no debía quedar %s", p)
		}
	}

	// La privada jamás viaja a la VM ni a los scripts registrados.
	if strings.Contains(install+lock, "PRIVATE KEY") {
		t.Error("la llave privada no debe aparecer en ningún script")
	}

	st := svc.KeyStatus()
	if !st.Exists || !strings.HasPrefix(st.Fingerprint, "SHA256:") || !strings.Contains(out.Message, st.Fingerprint) {
		t.Errorf("KeyStatus = %+v, mensaje %q", st, out.Message)
	}
	name, data, err := svc.PrivateKeyForDownload()
	if err != nil || name != downloadName || string(data) != string(priv) {
		t.Errorf("descarga: %q, %v", name, err)
	}
}

func TestConfigureRootKeyAbortsWhenKeyLoginFails(t *testing.T) {
	svc, b, _ := keyFlow(t)
	b.probers["new"].err = errors.New("no se pudo conectar a 192.168.1.37:22: connection refused")

	out := svc.ConfigureRootKey(context.Background())
	if out.OK || !strings.Contains(out.Title, "no se pudo entrar por SSH") {
		t.Fatalf("%+v", out)
	}
	if b.marked != 0 || countOf(b.events, "final-run") != 0 || countOf(b.events, "probe") != 0 {
		t.Fatalf("no debía bloquear ni cambiar de canal: %v", b.events)
	}
	if n := countOf(b.events, "new-run"); n != 3 {
		t.Errorf("se esperaban 3 intentos, hubo %d", n)
	}
	if st := svc.KeyStatus(); st.Exists {
		t.Error("una llave sin verificar no debe quedar como definitiva")
	}
	if _, err := os.Stat(filepath.Join(b.keyDir, "main_root_ed25519.new")); err == nil {
		t.Error("debe borrarse la llave temporal")
	}
	if !strings.Contains(out.Detail, "connection refused") {
		t.Errorf("el detalle debe conservar el error técnico: %q", out.Detail)
	}
}

func TestConfigureRootKeyRetriesUntilSSHAnswers(t *testing.T) {
	svc, b, _ := keyFlow(t)
	calls := 0
	// SSH falla las dos primeras veces (sshd aún recargando) y luego responde.
	flaky := &flakyProber{fakeProber: &fakeProber{b: b, label: "new"}, failFirst: 2, calls: &calls}
	svc.provider = &flakyBackend{fakeBackend: b, flaky: flaky}

	out := svc.ConfigureRootKey(context.Background())
	if !out.OK || calls != 3 {
		t.Fatalf("debía reintentar y terminar bien (llamadas %d): %+v", calls, out)
	}
}

type flakyProber struct {
	*fakeProber
	failFirst int
	calls     *int
}

func (f *flakyProber) Run(ctx context.Context, s string) (runner.Result, error) {
	*f.calls++
	if *f.calls <= f.failFirst {
		return runner.Result{}, errors.New("connection refused")
	}
	return runner.Result{Stdout: "root\n", Channel: runner.ChannelSSH}, nil
}

type flakyBackend struct {
	*fakeBackend
	flaky *flakyProber
}

func (f *flakyBackend) SSHFor(target, keyPath string) (runner.KeyProber, error) {
	if strings.HasSuffix(keyPath, ".new") {
		f.fakeBackend.sshForPath = append(f.fakeBackend.sshForPath, keyPath)
		return f.flaky, nil
	}
	return f.fakeBackend.SSHFor(target, keyPath)
}

func TestConfigureRootKeyStopsIfInstallFails(t *testing.T) {
	svc, b, guest := keyFlow(t)
	guest.res = runner.Result{ExitCode: 1, Stderr: "sshd rechazó la configuración (sshd -t); se restauró el estado anterior"}

	out := svc.ConfigureRootKey(context.Background())
	if out.OK || !strings.Contains(out.Message, "sshd rechazó") {
		t.Fatalf("%+v", out)
	}
	if strings.Join(b.events, ",") != "guest-run" || len(b.sshForPath) != 0 || svc.KeyStatus().Exists {
		t.Errorf("no debía continuar: eventos %v", b.events)
	}
}

func TestConfigureRootKeyReportsGuestTransportError(t *testing.T) {
	svc, _, guest := keyFlow(t)
	guest.err = errors.New("VBoxManage terminó con código 1: VM no encontrada")
	out := svc.ConfigureRootKey(context.Background())
	if out.OK || !strings.Contains(out.Title, "No se pudo ejecutar") || !strings.Contains(out.Detail, "VM no encontrada") {
		t.Fatalf("%+v", out)
	}
}

func TestConfigureRootKeyFailsIfServerStillAcceptsPassword(t *testing.T) {
	svc, b, _ := keyFlow(t)
	b.probers["final"].accepted = true

	out := svc.ConfigureRootKey(context.Background())
	if out.OK || !strings.Contains(out.Title, "todavía acepta") {
		t.Fatalf("%+v", out)
	}
	if b.marked != 1 {
		t.Error("la llave ya funcionaba: el canal sí debe haber cambiado a SSH")
	}
}

func TestConfigureRootKeyLockFailureKeepsChannelOnSSH(t *testing.T) {
	svc, b, _ := keyFlow(t)
	b.probers["final"].res = runner.Result{ExitCode: 1, Stderr: "La configuración efectiva de sshd no cumple «passwordauthentication no»: otro archivo la contradice.\nsegunda línea"}

	out := svc.ConfigureRootKey(context.Background())
	if out.OK || !strings.Contains(out.Title, "no se pudo bloquear") || !strings.Contains(out.Message, "passwordauthentication no") {
		t.Fatalf("%+v", out)
	}
	if strings.Contains(out.Message, "segunda línea") {
		t.Error("el mensaje debe mostrar solo la primera línea del motivo")
	}
	if b.marked != 1 || countOf(b.events, "probe") != 0 {
		t.Errorf("eventos %v", b.events)
	}
}

func TestConfigureRootKeyProbeIsInconclusiveButNotFatal(t *testing.T) {
	svc, b, _ := keyFlow(t)
	b.probers["final"].probeErr = errors.New("timeout")
	out := svc.ConfigureRootKey(context.Background())
	if !out.OK || !strings.Contains(out.Message, "No se pudo repetir la comprobación") {
		t.Fatalf("%+v", out)
	}
}

func TestConfigureRootKeyWithoutRootPasswordSkipsProbe(t *testing.T) {
	svc, b, _ := keyFlow(t)
	svc.opts.RootPassword = ""
	out := svc.ConfigureRootKey(context.Background())
	if !out.OK || countOf(b.events, "probe") != 0 || !strings.Contains(out.Message, "guestPassword no está configurado") {
		t.Fatalf("%+v events=%v", out, b.events)
	}
}

func TestRegeneratingReplacesKeyAndKeepsOldUntilVerified(t *testing.T) {
	svc, b, _ := keyFlow(t)
	if out := svc.ConfigureRootKey(context.Background()); !out.OK {
		t.Fatalf("%+v", out)
	}
	first := svc.KeyStatus().Fingerprint

	// Segunda ejecución con la verificación caída: la llave anterior debe seguir intacta.
	b.probers["new"].err = errors.New("sin conexión")
	if out := svc.ConfigureRootKey(context.Background()); out.OK {
		t.Fatal("debía fallar")
	}
	if got := svc.KeyStatus().Fingerprint; got != first {
		t.Errorf("la llave anterior cambió aunque la nueva no se verificó: %s → %s", first, got)
	}

	// Segunda ejecución exitosa: la llave se reemplaza.
	b.probers["new"].err = nil
	if out := svc.ConfigureRootKey(context.Background()); !out.OK {
		t.Fatalf("%+v", out)
	}
	if got := svc.KeyStatus().Fingerprint; got == first {
		t.Error("la llave debía haberse reemplazado")
	}
}

func TestDownloadWithoutKey(t *testing.T) {
	svc, _, _ := keyFlow(t)
	if _, _, err := svc.PrivateKeyForDownload(); !errors.Is(err, ErrNoKey) {
		t.Errorf("error = %v, esperado ErrNoKey", err)
	}
	if svc.KeyStatus().Exists {
		t.Error("no debe haber llave")
	}
}

func TestConfigureRootKeyBusy(t *testing.T) {
	svc, _, _ := keyFlow(t)
	svc.mu.Lock()
	defer svc.mu.Unlock()
	if out := svc.ConfigureRootKey(context.Background()); out.OK || !strings.Contains(out.Title, "en curso") {
		t.Fatalf("%+v", out)
	}
}
