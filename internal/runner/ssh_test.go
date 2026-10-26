package runner

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"consola/internal/sshkey"
	"consola/internal/sshtest"
)

// startServer levanta un servidor SSH de prueba que acepta solo la llave
// indicada (y la contraseña, si se da) y ejecuta los comandos localmente.
func startServer(t *testing.T, host ssh.Signer, authorized ssh.PublicKey, password string) int {
	t.Helper()
	o := sshtest.Options{
		Host: host,
		AuthKey: func(user string, key ssh.PublicKey) bool {
			return user == "root" && authorized != nil && bytes.Equal(key.Marshal(), authorized.Marshal())
		},
	}
	if password != "" {
		o.AuthPass = func(user, pw string) bool { return user == "root" && pw == password }
	}
	return sshtest.Start(t, o)
}

func newHostSigner(t *testing.T) ssh.Signer { return sshtest.NewHostSigner(t) }

// newClient crea un cliente SSH con una llave nueva; devuelve también la
// llave pública para autorizarla en el servidor de prueba.
func newClient(t *testing.T, port int) (*SSH, ssh.PublicKey) {
	t.Helper()
	pair, err := sshkey.Generate("consola-root")
	if err != nil {
		t.Fatal(err)
	}
	pub, _, _, _, err := ssh.ParseAuthorizedKey([]byte(pair.Authorized))
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "id")
	if err := os.WriteFile(keyPath, pair.PrivatePEM, 0o600); err != nil {
		t.Fatal(err)
	}
	return &SSH{Host: "127.0.0.1", Port: port, User: "root", KeyPath: keyPath,
		KnownHostsPath: filepath.Join(dir, "known_hosts"), DialTimeout: 5 * time.Second}, pub
}

func ctx5(t *testing.T) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	t.Cleanup(cancel)
	return ctx
}

func TestSSHRunReportsOutputAndExitCode(t *testing.T) {
	sshtest.RequireBash(t)
	// El cliente se crea primero para conocer su pública; el servidor se levanta con ella.
	c, pub := newClient(t, 0)
	c.Port = startServer(t, newHostSigner(t), pub, "")

	res, err := c.Run(ctx5(t), "echo salida; echo aviso >&2; exit 3")
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if res.Stdout != "salida\n" || res.Stderr != "aviso\n" || res.ExitCode != 3 || res.Channel != ChannelSSH {
		t.Errorf("resultado inesperado: %+v", res)
	}
	// Un código distinto de cero NO es un error de transporte.
	res, err = c.Run(ctx5(t), "true")
	if err != nil || !res.OK() {
		t.Errorf("true debía salir bien: %+v, %v", res, err)
	}
}

func TestSSHRejectsUnauthorizedKey(t *testing.T) {
	c, _ := newClient(t, 0)
	_, otherPub := newClient(t, 0)
	c.Port = startServer(t, newHostSigner(t), otherPub, "")

	_, err := c.Run(ctx5(t), "true")
	if err == nil || !strings.Contains(err.Error(), "unable to authenticate") {
		t.Fatalf("una llave no autorizada debe rechazarse, error = %v", err)
	}
}

func TestPasswordLoginAccepted(t *testing.T) {
	host := newHostSigner(t)

	// Servidor solo con llave: la contraseña debe ser rechazada.
	c, pub := newClient(t, 0)
	c.Port = startServer(t, host, pub, "")
	if ok, err := c.PasswordLoginAccepted(ctx5(t), "secreto"); ok || err != nil {
		t.Errorf("servidor solo con llave: accepted=%v err=%v (esperado false, nil)", ok, err)
	}

	// Servidor que aún permite contraseña: debe detectarse.
	c2, pub2 := newClient(t, 0)
	c2.Port = startServer(t, newHostSigner(t), pub2, "secreto")
	if ok, err := c2.PasswordLoginAccepted(ctx5(t), "secreto"); !ok || err != nil {
		t.Errorf("servidor con contraseña: accepted=%v err=%v (esperado true, nil)", ok, err)
	}
	if ok, err := c2.PasswordLoginAccepted(ctx5(t), "otra"); ok || err != nil {
		t.Errorf("contraseña incorrecta: accepted=%v err=%v (esperado false, nil)", ok, err)
	}
}

func TestPasswordLoginProbeReportsNetworkErrors(t *testing.T) {
	c, _ := newClient(t, 1) // puerto 1: nadie escucha
	ok, err := c.PasswordLoginAccepted(ctx5(t), "x")
	if ok || err == nil {
		t.Errorf("sin servidor debía dar error de conexión, got accepted=%v err=%v", ok, err)
	}
}

func TestSSHRejectsChangedHostKey(t *testing.T) {
	c, pub := newClient(t, 0)
	c.Port = startServer(t, newHostSigner(t), pub, "")
	cl, err := c.dial(ctx5(t))
	if err != nil {
		t.Fatalf("primera conexión: %v", err)
	}
	cl.Close()

	// Otro servidor con otra huella, mismo archivo known_hosts.
	c.Port = startServer(t, newHostSigner(t), pub, "")
	if _, err := c.dial(ctx5(t)); err == nil || !strings.Contains(err.Error(), "cambió") {
		t.Fatalf("una huella distinta debe rechazarse, error = %v", err)
	}
}
