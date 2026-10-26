package preparacion

// Prueba de punta a punta de 3.1.2 SIN máquina virtual:
//   - el Manager real decide el canal y persiste el cambio a SSH,
//   - el cliente SSH real se conecta con la llave generada,
//   - los scripts reales se ejecutan con bash (sshd/systemctl falsos),
//   - un servidor SSH en proceso lee el authorized_keys escrito por el script y
//     solo acepta contraseña mientras el drop-in no diga "PasswordAuthentication no".

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"consola/internal/config"
	"consola/internal/oplog"
	"consola/internal/runner"
	"consola/internal/sshtest"
)

// localRunner hace de "Guest Additions": ejecuta el script en este equipo.
type localRunner struct{}

func (localRunner) Name() string { return runner.ChannelGuest }
func (localRunner) Run(ctx context.Context, script string) (runner.Result, error) {
	var out, errb bytes.Buffer
	cmd := exec.CommandContext(ctx, "bash", "-c", script)
	cmd.Stdout, cmd.Stderr = &out, &errb
	res := runner.Result{Channel: runner.ChannelGuest}
	if err := cmd.Run(); err != nil {
		ee, ok := err.(*exec.ExitError)
		if !ok {
			return res, err
		}
		res.ExitCode = ee.ExitCode()
	}
	res.Stdout, res.Stderr = out.String(), errb.String()
	return res, nil
}
func (localRunner) RunInput(context.Context, string, string) (runner.Result, error) {
	return runner.Result{}, runner.ErrNotSupported
}
func (localRunner) Upload(context.Context, string, string, os.FileMode) error { return nil }

// e2eBackend usa el Manager real, pero antes de SSH ejecuta en local.
type e2eBackend struct{ *runner.Manager }

func (b e2eBackend) Get(target string) (runner.Runner, error) {
	if _, ready := b.Manager.Status(target); ready {
		return b.Manager.Get(target)
	}
	return localRunner{}, nil
}

func newE2E(t *testing.T) (*Service, *runner.Manager, *scriptEnv) {
	t.Helper()
	e := newScriptEnv(t) // omite la prueba si no hay bash o en Windows
	t.Setenv("FAKE_SSHD_DIR", e.sshDir)
	t.Setenv("FAKE_LOG", e.logf)

	oldPaths, oldDelay := prodPaths, retryDelay
	prodPaths, retryDelay = e.paths, 50*time.Millisecond
	t.Cleanup(func() { prodPaths, retryDelay = oldPaths, oldDelay })

	// "sshd" de prueba: acepta la llave si está en authorized_keys y la
	// contraseña solo mientras el bloqueo no se haya aplicado.
	port := sshtest.Start(t, sshtest.Options{
		Host: sshtest.NewHostSigner(t),
		AuthKey: func(user string, key ssh.PublicKey) bool {
			data, err := os.ReadFile(e.keys)
			if err != nil || user != "root" {
				return false
			}
			for _, line := range strings.Split(string(data), "\n") {
				if pk, _, _, _, err := ssh.ParseAuthorizedKey([]byte(line)); err == nil && bytes.Equal(pk.Marshal(), key.Marshal()) {
					return true
				}
			}
			return false
		},
		AuthPass: func(user, pw string) bool {
			return user == "root" && pw == "1234" && !strings.Contains(e.dropin(), "PasswordAuthentication no")
		},
	})

	dir := t.TempDir()
	cfg := &config.Config{
		DataDir: dir,
		Targets: map[string]config.Target{"main": {VMName: "vm", IP: "127.0.0.1", SSHPort: port, GuestUser: "root"}},
	}
	mgr, err := runner.NewManager(cfg)
	if err != nil {
		t.Fatal(err)
	}
	log, err := oplog.New(filepath.Join(dir, "ops.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { log.Close() })
	svc := New(e2eBackend{mgr}, log, "main", Options{KeyDir: filepath.Join(dir, "keys"), RootPassword: "1234"})
	return svc, mgr, e
}

func TestConfigureRootKeyEndToEnd(t *testing.T) {
	svc, mgr, e := newE2E(t)

	// Estado inicial realista: ya hay otra llave autorizada que no debe perderse.
	other := "ssh-rsa AAAAOTHERKEY usuario@pc"
	if err := os.MkdirAll(filepath.Dir(e.keys), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(e.keys, []byte(other+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if ch, ready := mgr.Status("main"); ready || ch != runner.ChannelGuest {
		t.Fatalf("antes: canal %q, ready %v", ch, ready)
	}

	out := svc.ConfigureRootKey(context.Background())
	if !out.OK {
		t.Fatalf("el flujo completo debía terminar bien:\n%s\n%s\n%s", out.Title, out.Message, out.Detail)
	}
	if !strings.Contains(out.Message, "es rechazado") {
		t.Errorf("debía comprobarse que la contraseña es rechazada: %s", out.Message)
	}

	// El canal cambió a SSH y se recuerda.
	if ch, ready := mgr.Status("main"); !ready || ch != runner.ChannelSSH {
		t.Errorf("después: canal %q, ready %v", ch, ready)
	}
	r, _ := mgr.Get("main")
	if _, ok := r.(*runner.SSH); !ok {
		t.Fatalf("el Manager debe devolver SSH, devolvió %T", r)
	}

	// Estado final en la "VM": llave ajena conservada, la de la consola presente, contraseña bloqueada.
	keys := e.read(e.keys)
	if !strings.Contains(keys, other) || strings.Count(keys, "consola-root") != 1 {
		t.Errorf("authorized_keys inesperado:\n%s", keys)
	}
	if !strings.Contains(e.dropin(), "PasswordAuthentication no") {
		t.Errorf("drop-in sin bloqueo:\n%s", e.dropin())
	}

	// Las operaciones siguientes usan SSH con la llave de verdad.
	res, err := r.Run(context.Background(), "echo hola desde ssh")
	if err != nil || strings.TrimSpace(res.Stdout) != "hola desde ssh" || res.Channel != runner.ChannelSSH {
		t.Errorf("Run por SSH: %+v, %v", res, err)
	}

	// La llave descargada es la que funciona: se puede usar fuera de la consola.
	_, data, err := svc.PrivateKeyForDownload()
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.ParsePrivateKey(data)
	if err != nil {
		t.Fatalf("la llave descargada no es válida: %v", err)
	}
	if !strings.Contains(e.read(e.keys), strings.Fields(string(ssh.MarshalAuthorizedKey(signer.PublicKey())))[1]) {
		t.Error("la llave descargada no corresponde a la autorizada en la VM")
	}

	// Regenerar (rotación): la llave anterior deja de estar autorizada y la nueva funciona.
	firstFP := svc.KeyStatus().Fingerprint
	if out := svc.ConfigureRootKey(context.Background()); !out.OK {
		t.Fatalf("la regeneración debía funcionar:\n%s\n%s\n%s", out.Title, out.Message, out.Detail)
	}
	if svc.KeyStatus().Fingerprint == firstFP {
		t.Error("la llave debía cambiar")
	}
	keys = e.read(e.keys)
	if !strings.Contains(keys, other) || strings.Count(keys, "consola-root") != 1 {
		t.Errorf("tras regenerar, authorized_keys inesperado:\n%s", keys)
	}
	r, _ = mgr.Get("main")
	if res, err := r.Run(context.Background(), "echo otra vez"); err != nil || strings.TrimSpace(res.Stdout) != "otra vez" {
		t.Errorf("tras regenerar, Run por SSH: %+v, %v", res, err)
	}
}

func TestConfigureRootKeyEndToEndDetectsOverridingConfig(t *testing.T) {
	svc, mgr, e := newE2E(t)
	t.Setenv("FAKE_FORCE_PW_YES", "1") // otra directiva de sshd anula el bloqueo

	out := svc.ConfigureRootKey(context.Background())
	if out.OK || !strings.Contains(out.Title, "no se pudo bloquear") || !strings.Contains(out.Message, "passwordauthentication no") {
		t.Fatalf("debía informar que el bloqueo no se pudo aplicar: %+v", out)
	}
	// La llave ya funcionaba: el canal quedó en SSH, y la configuración se restauró.
	if _, ready := mgr.Status("main"); !ready {
		t.Error("el canal debía haber pasado a SSH")
	}
	if strings.Contains(e.dropin(), "PasswordAuthentication") {
		t.Errorf("el drop-in debía restaurarse sin el bloqueo:\n%s", e.dropin())
	}
}
