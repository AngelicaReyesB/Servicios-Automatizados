// Package validate contiene las validaciones (listas blancas) de las entradas
// del usuario. Nada llega a un comando sin pasar por aquí.
package validate

import (
	"errors"
	"net"
	"regexp"
	"strings"
)

var (
	rePackage   = regexp.MustCompile(`^[a-z0-9][a-z0-9+.-]{1,99}$`)
	reHostLabel = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)
	reUsername  = regexp.MustCompile(`^[a-z_][a-z0-9_-]{0,31}$`)
	reService   = regexp.MustCompile(`^[a-z][a-z0-9-]{1,30}$`)
	reServer    = regexp.MustCompile(`^[a-z][a-z0-9_-]{0,31}$`)
	reUnit      = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9:_.@-]{0,99}$`)
)

// Package valida un nombre de paquete de Debian.
func Package(s string) error {
	if s == "" {
		return errors.New("escriba el nombre del paquete")
	}
	if !rePackage.MatchString(s) {
		return errors.New("nombre de paquete inválido: use solo minúsculas, dígitos y los símbolos + - . (entre 2 y 100 caracteres, empezando por letra o dígito)")
	}
	return nil
}

// Hostname valida un nombre de host corto (una sola etiqueta RFC 1123).
func Hostname(s string) error {
	switch {
	case s == "":
		return errors.New("escriba el nombre de host")
	case strings.Contains(s, "_"):
		return errors.New("el nombre de host no admite guion bajo (_); use guion (-), por ejemplo app-web1")
	case s != strings.ToLower(s):
		return errors.New("el nombre de host debe estar en minúsculas")
	case strings.Contains(s, "."):
		return errors.New("escriba solo el nombre corto, sin puntos ni dominio")
	case !reHostLabel.MatchString(s):
		return errors.New("nombre de host inválido: use letras, dígitos y guiones, sin empezar ni terminar con guion (máximo 63 caracteres)")
	}
	return nil
}

// Username valida un nombre de usuario de Linux.
func Username(s string) error {
	if s == "" {
		return errors.New("escriba el nombre de usuario")
	}
	if !reUsername.MatchString(s) {
		return errors.New("nombre de usuario inválido: use minúsculas, dígitos, guion y guion bajo (máximo 32, sin empezar por dígito)")
	}
	return nil
}

// UnitName valida el nombre de una unidad de systemd (sin sufijo o con él).
func UnitName(s string) error {
	if s == "" {
		return errors.New("escriba el nombre del servicio")
	}
	if !reUnit.MatchString(s) {
		return errors.New("nombre de servicio inválido: use letras, dígitos y los símbolos : _ . @ -")
	}
	return nil
}

// IPv4 valida una dirección IPv4.
func IPv4(s string) error {
	if ip := net.ParseIP(s); ip == nil || ip.To4() == nil || strings.Contains(s, ":") {
		return errors.New("dirección IPv4 inválida")
	}
	return nil
}

// Port valida un puerto TCP.
func Port(p int) error {
	if p < 1 || p > 65535 {
		return errors.New("puerto fuera de rango (1-65535)")
	}
	return nil
}

// ServiceName valida el nombre de un servicio que crea la consola. También es
// el nombre del usuario del sistema que lo ejecuta y del directorio /opt/<nombre>.
func ServiceName(s string) error {
	if s == "" {
		return errors.New("escriba el nombre del servicio")
	}
	if !reService.MatchString(s) {
		return errors.New("nombre de servicio inválido: use minúsculas, dígitos y guion (2 a 31 caracteres, empezando por letra), por ejemplo catalogo-libros")
	}
	return nil
}

// ServerName valida el nombre de un servidor del back-end de HAProxy.
func ServerName(s string) error {
	if s == "" {
		return errors.New("escriba el nombre del servidor")
	}
	if !reServer.MatchString(s) {
		return errors.New("nombre de servidor inválido: use minúsculas, dígitos, guion y guion bajo (máximo 32, empezando por letra), por ejemplo web1")
	}
	return nil
}

// BackendIPv4 valida la IPv4 de un servidor del back-end: debe ser una
// dirección unicast alcanzable (no 0.0.0.0, ni loopback, ni multicast/broadcast).
func BackendIPv4(s string) error {
	if err := IPv4(s); err != nil {
		return err
	}
	ip := net.ParseIP(s).To4()
	if ip[0] == 0 || ip[0] == 127 || ip[0] >= 224 || s != ip.String() {
		return errors.New("la IP del servidor debe ser una dirección de la red (no 0.0.0.0, 127.x.x.x ni multicast/broadcast) y sin ceros a la izquierda")
	}
	return nil
}
