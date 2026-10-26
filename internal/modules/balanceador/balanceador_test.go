package balanceador

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"consola/internal/oplog"
	"consola/internal/runner"
)

type fakeRunner struct {
	scripts []string
	read    runner.Result // respuesta al script de lectura
	apply   runner.Result // respuesta al script de aplicar
	err     error
}

func (f *fakeRunner) Name() string { return "SSH (fake)" }
func (f *fakeRunner) Run(_ context.Context, s string) (runner.Result, error) {
	f.scripts = append(f.scripts, s)
	if f.err != nil {
		return runner.Result{}, f.err
	}
	if strings.Contains(s, "EXPECT=") {
		return f.apply, nil
	}
	return f.read, nil
}
func (f *fakeRunner) RunInput(context.Context, string, string) (runner.Result, error) {
	return runner.Result{}, runner.ErrNotSupported
}
func (f *fakeRunner) Upload(context.Context, string, string, os.FileMode) error { return nil }

type fakeProber struct {
	fakeRunner
	probeRes runner.Result
	probeErr error
}

func (p *fakeProber) Run(_ context.Context, s string) (runner.Result, error) {
	return p.probeRes, p.probeErr
}
func (p *fakeProber) PasswordLoginAccepted(context.Context, string) (bool, error) { return false, nil }

type fakeBackend struct {
	r      *fakeRunner
	prober *fakeProber
	marked []string
}

func (b *fakeBackend) Get(string) (runner.Runner, error) { return b.r, nil }
func (b *fakeBackend) SSHFor(_, key string) (runner.KeyProber, error) {
	return b.prober, nil
}
func (b *fakeBackend) MarkSSHReady(_, key string) error { b.marked = append(b.marked, key); return nil }

func readOut(cfg string) runner.Result {
	return runner.Result{Stdout: "estado: active\nversión: HAProxy version 3.0.11\n" + cfgMarker + "\n" + cfg}
}

func newSvc(t *testing.T, cfg string) (*Service, *fakeBackend) {
	t.Helper()
	log, err := oplog.New(filepath.Join(t.TempDir(), "ops.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { log.Close() })
	b := &fakeBackend{r: &fakeRunner{read: readOut(cfg), apply: runner.Result{Stdout: "--- verificación ---\nestado: active\n"}}, prober: &fakeProber{}}
	key := filepath.Join(t.TempDir(), "main_root_ed25519")
	_ = os.WriteFile(key, []byte("k"), 0o600)
	return New(b, log, "haproxy", Options{KeyPath: key, BalancerIP: "192.168.1.6"}), b
}

// applied extrae del script enviado el archivo completo y el hash esperado.
func applied(t *testing.T, script string) (content, expect string) {
	t.Helper()
	m := regexp.MustCompile(`printf '%s' '([A-Za-z0-9+/=]*)' \| base64 -d`).FindStringSubmatch(script)
	e := regexp.MustCompile(`(?m)^EXPECT=([0-9a-f]{64})$`).FindStringSubmatch(script)
	if m == nil || e == nil {
		t.Fatalf("script mal armado:\n%s", script)
	}
	b, _ := base64.StdEncoding.DecodeString(m[1])
	return string(b), e[1]
}

func TestAddServerFirstTimeCreatesBlockAndSendsExpectedHash(t *testing.T) {
	svc, b := newSvc(t, debianDefault)
	out := svc.AddServer(context.Background(), "web1", "192.168.1.10", 80)
	if !out.OK || len(b.r.scripts) != 2 {
		t.Fatalf("%+v scripts=%d", out, len(b.r.scripts))
	}
	content, expect := applied(t, b.r.scripts[1])
	sum := sha256.Sum256([]byte(debianDefault))
	if expect != hex.EncodeToString(sum[:]) {
		t.Error("el hash esperado debe ser el del archivo leído")
	}
	if !strings.HasPrefix(content, debianDefault) || !strings.Contains(content, "    server web1 192.168.1.10:80 check\n") || !strings.Contains(content, "bind *:80") {
		t.Errorf("contenido:\n%s", content)
	}
	if strings.Contains(b.r.scripts[1], "{{") || !strings.Contains(b.r.scripts[1], "PORT=80\n") {
		t.Errorf("script:\n%s", b.r.scripts[1])
	}
	if !strings.Contains(out.Message, "1 servidor") {
		t.Errorf("mensaje: %q", out.Message)
	}
}

func TestAddSecondServerAndRemove(t *testing.T) {
	cfg := debianDefault + "\n" + buildBlock(80, []Server{{"web1", "192.168.1.10", 80}})
	svc, b := newSvc(t, cfg)
	if out := svc.AddServer(context.Background(), "web2", "192.168.1.11", 8080); !out.OK {
		t.Fatalf("%+v", out)
	}
	content, _ := applied(t, b.r.scripts[1])
	if !strings.Contains(content, "server web1 192.168.1.10:80 check\n    server web2 192.168.1.11:8080 check\n") {
		t.Errorf("contenido:\n%s", content)
	}

	b.r.scripts = nil
	out := svc.RemoveServer(context.Background(), "web1")
	if !out.OK || !strings.Contains(out.Message, "Quedan 0") || !strings.Contains(out.Message, "503") {
		t.Fatalf("%+v", out)
	}
	content, _ = applied(t, b.r.scripts[1])
	if strings.Contains(content, "server web1") || !strings.HasPrefix(content, debianDefault) || !strings.Contains(content, "balance roundrobin") {
		t.Errorf("contenido tras quitar:\n%s", content)
	}
}

func TestAddServerRejectsInvalidAndDuplicatesWithoutApplying(t *testing.T) {
	cfg := debianDefault + "\n" + buildBlock(80, []Server{{"web1", "192.168.1.10", 80}})
	svc, b := newSvc(t, cfg)
	bad := []struct {
		name, ip string
		port     int
	}{
		{"", "192.168.1.10", 80}, {"Web 1", "192.168.1.10", 80}, {"a;b", "192.168.1.10", 80}, {"w", "no-ip", 80},
		{"w", "999.1.1.1", 80}, {"w", "127.0.0.1", 80}, {"w", "0.0.0.0", 80}, {"w", "224.0.0.1", 80}, {"w", "192.168.001.010", 80},
		{"w", "192.168.1.10", 0}, {"w", "192.168.1.10", 70000}, {"w", "192.168.1.6", 80},
	}
	for _, c := range bad {
		if out := svc.AddServer(context.Background(), c.name, c.ip, c.port); out.OK || out.Title != "Datos no válidos" {
			t.Errorf("%+v → %+v", c, out)
		}
	}
	if len(b.r.scripts) != 0 {
		t.Fatal("los datos inválidos no deben llegar a la VM")
	}
	if out := svc.AddServer(context.Background(), "web1", "192.168.1.20", 80); out.OK || out.Title != "El servidor ya existe" {
		t.Errorf("nombre repetido: %+v", out)
	}
	if out := svc.AddServer(context.Background(), "otro", "192.168.1.10", 80); out.OK || out.Title != "El servidor ya existe" {
		t.Errorf("dirección repetida: %+v", out)
	}
	// misma IP con otro puerto sí es un servidor distinto
	if out := svc.AddServer(context.Background(), "web1-alt", "192.168.1.10", 8080); !out.OK {
		t.Errorf("misma IP, otro puerto: %+v", out)
	}
	for _, s := range b.r.scripts {
		if strings.Contains(s, "EXPECT=") && !strings.Contains(s, "web1-alt") && !strings.Contains(s, "PORT=80") {
			t.Error("solo debía aplicarse el último agregado")
		}
	}
}

func TestRemoveUnknownServer(t *testing.T) {
	svc, b := newSvc(t, debianDefault)
	if out := svc.RemoveServer(context.Background(), "x;y"); out.Title != "Datos no válidos" {
		t.Errorf("%+v", out)
	}
	if out := svc.RemoveServer(context.Background(), "web9"); out.OK || out.Title != "El servidor no existe" {
		t.Errorf("%+v", out)
	}
	for _, s := range b.r.scripts {
		if strings.Contains(s, "EXPECT=") {
			t.Error("no debía aplicarse nada")
		}
	}
}

func TestHandEditedBlockAndConflictsAreRefused(t *testing.T) {
	edited := strings.Replace(buildBlock(80, []Server{{"a", "10.0.0.1", 80}}), "roundrobin", "leastconn", 1)
	svc, b := newSvc(t, debianDefault+edited)
	out := svc.AddServer(context.Background(), "web2", "192.168.1.11", 80)
	if out.OK || out.Title != "No se puede modificar la configuración" || !strings.Contains(out.Message, "modificado a mano") {
		t.Errorf("%+v", out)
	}
	svc, b = newSvc(t, debianDefault+"\nfrontend web\n    bind *:80\n")
	out = svc.AddServer(context.Background(), "web2", "192.168.1.11", 80)
	if out.OK || !strings.Contains(out.Message, "puerto 80") {
		t.Errorf("%+v", out)
	}
	for _, s := range b.r.scripts {
		if strings.Contains(s, "EXPECT=") {
			t.Error("no debía aplicarse nada")
		}
	}
}

func TestFailuresAreExplained(t *testing.T) {
	cases := map[int]string{exitNoHAProxy: "no está instalado", exitChanged: "cambió", exitInvalid: "rechazó la configuración", exitReload: "Se restauró"}
	for code, want := range cases {
		svc, b := newSvc(t, debianDefault)
		b.r.apply = runner.Result{ExitCode: code, Stderr: "detalle técnico Q"}
		out := svc.AddServer(context.Background(), "web1", "192.168.1.10", 80)
		if out.OK || !strings.Contains(out.Message, want) || !strings.Contains(out.Detail, "detalle técnico Q") {
			t.Errorf("%d → %+v", code, out)
		}
	}
	svc, b := newSvc(t, debianDefault)
	b.r.read = runner.Result{ExitCode: exitNoHAProxy, Stderr: "HAProxy no está instalado en la VM"}
	if out := svc.AddServer(context.Background(), "web1", "192.168.1.10", 80); out.OK || !strings.Contains(out.Message, "apt install haproxy") {
		t.Errorf("lectura: %+v", out)
	}
	b.r.read = runner.Result{}
	b.r.err = errors.New("no se pudo conectar")
	if out := svc.AddServer(context.Background(), "web1", "192.168.1.10", 80); out.OK || !strings.Contains(out.Title, "No se pudo ejecutar") {
		t.Errorf("transporte: %+v", out)
	}
}

func TestState(t *testing.T) {
	cfg := debianDefault + buildBlock(80, []Server{{"a", "10.0.0.1", 80}, {"b", "10.0.0.2", 80}})
	svc, _ := newSvc(t, cfg)
	v, err := svc.State(context.Background())
	if err != nil || len(v.Servers) != 2 || !v.Managed || v.Active != "active" || !strings.Contains(v.Version, "3.0.11") {
		t.Errorf("%+v %v", v, err)
	}
	svc, _ = newSvc(t, debianDefault)
	if v, err := svc.State(context.Background()); err != nil || v.Managed || len(v.Servers) != 0 {
		t.Errorf("sin bloque: %+v %v", v, err)
	}
	svc, _ = newSvc(t, debianDefault+beginMark+"\nbasura\n"+endMark+"\n")
	if _, err := svc.State(context.Background()); err == nil {
		t.Error("el bloque editado debe verse como error en el estado")
	}
}

func TestConnectSSH(t *testing.T) {
	svc, b := newSvc(t, debianDefault)
	b.prober.probeRes = runner.Result{Stdout: "root\npermitrootlogin without-password\npasswordauthentication no\n"}
	out := svc.ConnectSSH(context.Background())
	if !out.OK || len(b.marked) != 1 || strings.Contains(out.Message, "Aviso") {
		t.Fatalf("%+v marked=%v", out, b.marked)
	}
	b.prober.probeRes = runner.Result{Stdout: "root\npasswordauthentication yes\n"}
	if out := svc.ConnectSSH(context.Background()); !out.OK || !strings.Contains(out.Message, "Aviso") {
		t.Errorf("debe avisar de que acepta contraseña: %+v", out)
	}
	// no entra: no se cambia de canal
	b.marked = nil
	b.prober.probeRes = runner.Result{ExitCode: 255, Stderr: "Permission denied"}
	if out := svc.ConnectSSH(context.Background()); out.OK || len(b.marked) != 0 || !strings.Contains(out.Message, "Guest Additions") {
		t.Errorf("%+v", out)
	}
	b.prober.probeRes, b.prober.probeErr = runner.Result{}, errors.New("no se pudo conectar")
	if out := svc.ConnectSSH(context.Background()); out.OK || len(b.marked) != 0 || !strings.Contains(out.Detail, "no se pudo conectar") {
		t.Errorf("%+v", out)
	}
	// otro usuario distinto de root no sirve
	b.prober.probeRes, b.prober.probeErr = runner.Result{Stdout: "angelica\n"}, nil
	if out := svc.ConnectSSH(context.Background()); out.OK || len(b.marked) != 0 {
		t.Errorf("solo root: %+v", out)
	}
	// sin llave en el host
	svc.opts.KeyPath = filepath.Join(t.TempDir(), "no-existe")
	if out := svc.ConnectSSH(context.Background()); out.OK || out.Title != "Falta la llave de root" {
		t.Errorf("%+v", out)
	}
}
