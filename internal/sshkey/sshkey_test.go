package sshkey

import (
	"bytes"
	"regexp"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
)

func TestGenerateRoundTripsWithSSHLibrary(t *testing.T) {
	p, err := Generate("consola-root")
	if err != nil {
		t.Fatal(err)
	}
	if !regexp.MustCompile(`^ssh-ed25519 [A-Za-z0-9+/]+=* consola-root$`).MatchString(p.Authorized) {
		t.Fatalf("línea authorized_keys inesperada: %q", p.Authorized)
	}
	if !strings.HasPrefix(string(p.PrivatePEM), "-----BEGIN OPENSSH PRIVATE KEY-----\n") ||
		!strings.HasSuffix(string(p.PrivatePEM), "-----END OPENSSH PRIVATE KEY-----\n") {
		t.Fatalf("PEM inesperado:\n%s", p.PrivatePEM)
	}

	signer, err := ssh.ParsePrivateKey(p.PrivatePEM)
	if err != nil {
		t.Fatalf("la librería SSH no acepta la llave privada: %v", err)
	}
	pub, comment, _, _, err := ssh.ParseAuthorizedKey([]byte(p.Authorized))
	if err != nil {
		t.Fatalf("la librería SSH no acepta la línea authorized_keys: %v", err)
	}
	if comment != "consola-root" {
		t.Errorf("comentario = %q", comment)
	}
	if !bytes.Equal(pub.Marshal(), signer.PublicKey().Marshal()) {
		t.Error("la pública de authorized_keys no corresponde a la privada")
	}
	if want := ssh.FingerprintSHA256(pub); p.Fingerprint != want {
		t.Errorf("huella = %s, esperada %s", p.Fingerprint, want)
	}
	if got, err := Fingerprint(p.Authorized); err != nil || got != p.Fingerprint {
		t.Errorf("Fingerprint() = %q, %v", got, err)
	}

	// La privada realmente firma y la pública verifica.
	msg := []byte("prueba")
	sig, err := signer.Sign(nil, msg)
	if err != nil {
		t.Fatal(err)
	}
	if err := pub.Verify(msg, sig); err != nil {
		t.Errorf("la firma no verifica: %v", err)
	}
}

func TestGenerateIsRandomAndValidatesComment(t *testing.T) {
	a, _ := Generate("consola-root")
	b, _ := Generate("consola-root")
	if a.Authorized == b.Authorized || bytes.Equal(a.PrivatePEM, b.PrivatePEM) {
		t.Error("dos llaves generadas no pueden ser iguales")
	}
	for _, bad := range []string{"", "con espacio", "a;b", "x\ny", strings.Repeat("a", 65)} {
		if _, err := Generate(bad); err == nil {
			t.Errorf("el comentario %q debería rechazarse", bad)
		}
	}
}

func TestFingerprintRejectsGarbage(t *testing.T) {
	for _, bad := range []string{"", "ssh-rsa AAAA x", "ssh-ed25519", "ssh-ed25519 !!!notbase64 x"} {
		if _, err := Fingerprint(bad); err == nil {
			t.Errorf("Fingerprint(%q) debería fallar", bad)
		}
	}
}
