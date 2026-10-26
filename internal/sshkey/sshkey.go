// Package sshkey genera pares de llaves ed25519 en los formatos que usa
// OpenSSH: la llave privada ("OPENSSH PRIVATE KEY") y la línea de
// authorized_keys. Usa solo la librería estándar.
package sshkey

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/pem"
	"errors"
	"fmt"
	"regexp"
	"strings"
)

const keyType = "ssh-ed25519"

var reComment = regexp.MustCompile(`^[A-Za-z0-9._-]{1,64}$`)

// Pair es un par de llaves listo para usar.
type Pair struct {
	PrivatePEM  []byte // llave privada en formato OpenSSH, sin contraseña
	Authorized  string // línea para authorized_keys (sin salto de línea)
	Fingerprint string // huella "SHA256:..."
}

// Generate crea un par ed25519. El comentario identifica la llave en
// authorized_keys y solo admite letras, dígitos, punto, guion y guion bajo.
func Generate(comment string) (Pair, error) {
	if !reComment.MatchString(comment) {
		return Pair{}, errors.New("comentario de llave inválido")
	}
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return Pair{}, fmt.Errorf("no se pudo generar la llave: %w", err)
	}

	blob := appendString(appendString(nil, []byte(keyType)), pub)

	// Sección privada: dos enteros de comprobación iguales, tipo, pública,
	// privada (semilla + pública, 64 bytes), comentario y relleno 1,2,3...
	var check [4]byte
	if _, err := rand.Read(check[:]); err != nil {
		return Pair{}, err
	}
	section := append([]byte{}, check[:]...)
	section = append(section, check[:]...)
	section = appendString(section, []byte(keyType))
	section = appendString(section, pub)
	section = appendString(section, priv)
	section = appendString(section, []byte(comment))
	for i := byte(1); len(section)%8 != 0; i++ {
		section = append(section, i)
	}

	out := []byte("openssh-key-v1\x00")
	out = appendString(out, []byte("none")) // cifrado
	out = appendString(out, []byte("none")) // kdf
	out = appendString(out, nil)            // opciones del kdf
	out = binary.BigEndian.AppendUint32(out, 1)
	out = appendString(out, blob)
	out = appendString(out, section)

	return Pair{
		PrivatePEM:  pem.EncodeToMemory(&pem.Block{Type: "OPENSSH PRIVATE KEY", Bytes: out}),
		Authorized:  keyType + " " + base64.StdEncoding.EncodeToString(blob) + " " + comment,
		Fingerprint: fingerprintOf(blob),
	}, nil
}

// Fingerprint calcula la huella SHA256 de una línea de authorized_keys.
func Fingerprint(authorizedLine string) (string, error) {
	f := strings.Fields(authorizedLine)
	if len(f) < 2 || f[0] != keyType {
		return "", errors.New("no es una llave ssh-ed25519")
	}
	blob, err := base64.StdEncoding.DecodeString(f[1])
	if err != nil {
		return "", fmt.Errorf("llave pública mal formada: %w", err)
	}
	return fingerprintOf(blob), nil
}

func fingerprintOf(blob []byte) string {
	sum := sha256.Sum256(blob)
	return "SHA256:" + base64.RawStdEncoding.EncodeToString(sum[:])
}

func appendString(b, s []byte) []byte {
	b = binary.BigEndian.AppendUint32(b, uint32(len(s)))
	return append(b, s...)
}
