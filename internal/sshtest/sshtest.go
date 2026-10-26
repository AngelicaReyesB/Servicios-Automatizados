// Package sshtest ofrece un servidor SSH mínimo, en proceso, para las pruebas.
// Solo lo importan archivos _test.go: no forma parte del programa final.
package sshtest

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"net"
	"os/exec"
	"runtime"
	"testing"

	"golang.org/x/crypto/ssh"
)

// Options configura el servidor. AuthPass nil significa "sin contraseña".
type Options struct {
	Host     ssh.Signer
	AuthKey  func(user string, key ssh.PublicKey) bool
	AuthPass func(user, password string) bool
}

// RequireBash omite la prueba si no hay un bash de verdad. En Windows se omite
// siempre: el "bash.exe" que suele aparecer en el PATH es el de WSL, que falla
// si no hay una distribución de Linux instalada.
func RequireBash(t *testing.T) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("esta prueba ejecuta bash y solo corre en Linux/macOS")
	}
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skip("bash no está disponible")
	}
}

// NewHostSigner crea una llave de servidor nueva.
func NewHostSigner(t *testing.T) ssh.Signer {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	s, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// Start levanta el servidor en 127.0.0.1 y devuelve su puerto. Los comandos
// "exec" se ejecutan localmente con bash.
func Start(t *testing.T, o Options) int {
	t.Helper()
	cfg := &ssh.ServerConfig{
		PublicKeyCallback: func(c ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
			if o.AuthKey != nil && o.AuthKey(c.User(), key) {
				return nil, nil
			}
			return nil, errors.New("llave no autorizada")
		},
	}
	if o.AuthPass != nil {
		cfg.PasswordCallback = func(c ssh.ConnMetadata, pw []byte) (*ssh.Permissions, error) {
			if o.AuthPass(c.User(), string(pw)) {
				return nil, nil
			}
			return nil, errors.New("contraseña incorrecta")
		}
	}
	cfg.AddHostKey(o.Host)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go serveConn(conn, cfg)
		}
	}()
	return ln.Addr().(*net.TCPAddr).Port
}

func serveConn(conn net.Conn, cfg *ssh.ServerConfig) {
	defer conn.Close()
	sc, chans, reqs, err := ssh.NewServerConn(conn, cfg)
	if err != nil {
		return
	}
	defer sc.Close()
	go ssh.DiscardRequests(reqs)
	for nc := range chans {
		if nc.ChannelType() != "session" {
			_ = nc.Reject(ssh.UnknownChannelType, "no soportado")
			continue
		}
		ch, chReqs, err := nc.Accept()
		if err != nil {
			return
		}
		go func() {
			defer ch.Close()
			for r := range chReqs {
				if r.Type != "exec" {
					_ = r.Reply(false, nil)
					continue
				}
				n := binary.BigEndian.Uint32(r.Payload)
				cmd := string(r.Payload[4 : 4+n])
				_ = r.Reply(true, nil)
				c := exec.Command("bash", "-c", cmd)
				c.Stdout, c.Stderr = ch, ch.Stderr()
				code := 0
				if err := c.Run(); err != nil {
					var ee *exec.ExitError
					if errors.As(err, &ee) {
						code = ee.ExitCode()
					} else {
						code = 127
					}
				}
				_, _ = ch.SendRequest("exit-status", false, ssh.Marshal(struct{ Code uint32 }{uint32(code)}))
				return
			}
		}()
	}
}
