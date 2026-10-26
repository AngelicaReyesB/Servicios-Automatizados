package runner

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"

	"consola/internal/config"
)

func TestShellQuote(t *testing.T) {
	if got := shellQuote("a'b"); got != `'a'\''b'` {
		t.Errorf("shellQuote = %s", got)
	}
}

func TestWrapScriptRoundTrip(t *testing.T) {
	script := "echo 'hola'\nexit 3\n"
	w := wrapScript(script)
	if !strings.Contains(w, base64.StdEncoding.EncodeToString([]byte(script))) {
		t.Error("el script en base64 no está en el envoltorio")
	}
	if strings.ContainsAny(w, "\n\"") {
		t.Error("el envoltorio no debe tener saltos de línea ni comillas dobles")
	}
}

func TestSplitExit(t *testing.T) {
	clean, code, ok := splitExit("aviso\n__CONSOLA_EXIT=100\n")
	if !ok || code != 100 || strings.TrimSpace(clean) != "aviso" {
		t.Errorf("splitExit = %q, %d, %v", clean, code, ok)
	}
	if _, _, ok := splitExit("sin marcador"); ok {
		t.Error("no debería encontrar marcador")
	}
	if _, _, ok := splitExit("__CONSOLA_EXIT=abc"); ok {
		t.Error("marcador no numérico no es válido")
	}
}

func hostKey(t *testing.T) ssh.PublicKey {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	k, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func TestTrustOnFirstUse(t *testing.T) {
	path := filepath.Join(t.TempDir(), "kh", "main")
	cb := trustOnFirstUse(path)
	k1, k2 := hostKey(t), hostKey(t)
	if err := cb("h", nil, k1); err != nil {
		t.Fatalf("primer uso debe aceptar: %v", err)
	}
	if err := cb("h", nil, k1); err != nil {
		t.Fatalf("misma llave debe aceptar: %v", err)
	}
	if err := cb("h", nil, k2); err == nil {
		t.Fatal("una llave distinta debe rechazarse")
	}
}

func TestManagerSwitchesToSSH(t *testing.T) {
	dir := t.TempDir()
	cfg := &config.Config{
		DataDir:    dir,
		VBoxManage: "VBoxManage",
		Targets:    map[string]config.Target{"main": {VMName: "vm", IP: "192.168.1.10", SSHPort: 22, GuestUser: "root"}},
	}
	m, err := NewManager(cfg)
	if err != nil {
		t.Fatal(err)
	}
	r, _ := m.Get("main")
	if _, ok := r.(*GuestControl); !ok {
		t.Fatalf("antes de SSH se esperaba GuestControl, fue %T", r)
	}
	if err := m.MarkSSHReady("main", filepath.Join(dir, "k")); err != nil {
		t.Fatal(err)
	}
	// Una instancia nueva debe recordar el estado.
	m2, err := NewManager(cfg)
	if err != nil {
		t.Fatal(err)
	}
	r, _ = m2.Get("main")
	if _, ok := r.(*SSH); !ok {
		t.Fatalf("después de SSH se esperaba SSH, fue %T", r)
	}
	if ch, ready := m2.Status("main"); ch != ChannelSSH || !ready {
		t.Errorf("Status = %q, %v", ch, ready)
	}
	if _, err := m2.Get("otro"); err == nil {
		t.Error("un objetivo desconocido debe dar error")
	}
}
