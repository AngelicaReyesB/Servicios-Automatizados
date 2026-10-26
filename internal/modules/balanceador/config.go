package balanceador

// La consola administra UN bloque de /etc/haproxy/haproxy.cfg delimitado por
// marcas. El resto del archivo no se toca. El bloque se regenera siempre a
// partir de la lista de servidores, y si el contenido actual del bloque no
// coincide exactamente con lo que se generaría (alguien lo editó a mano), la
// consola se niega a modificarlo en vez de pisar esos cambios.

import (
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

const (
	beginMark    = "# BEGIN consola-automatizacion (no editar a mano)"
	endMark      = "# END consola-automatizacion"
	frontendName = "consola_front"
	backendName  = "consola_back"
)

// Server es un servidor del back-end.
type Server struct {
	Name string
	IP   string
	Port int
}

func (s Server) Addr() string { return s.IP + ":" + strconv.Itoa(s.Port) }

var reServerLine = regexp.MustCompile(`^    server ([a-z][a-z0-9_-]{0,31}) ((?:[0-9]{1,3}\.){3}[0-9]{1,3}):([0-9]{1,5}) check$`)

// buildBlock genera el bloque administrado.
func buildBlock(frontPort int, servers []Server) string {
	var b strings.Builder
	b.WriteString(beginMark + "\n")
	fmt.Fprintf(&b, "frontend %s\n    bind *:%d\n    default_backend %s\n\n", frontendName, frontPort, backendName)
	fmt.Fprintf(&b, "backend %s\n    balance roundrobin\n", backendName)
	for _, s := range servers {
		fmt.Fprintf(&b, "    server %s %s check\n", s.Name, s.Addr())
	}
	b.WriteString(endMark + "\n")
	return b.String()
}

// ErrEdited indica que el bloque administrado fue modificado a mano.
var ErrEdited = errors.New("el bloque administrado por la consola en haproxy.cfg fue modificado a mano; restáurelo o bórrelo (de la marca BEGIN a la marca END) para que la consola vuelva a gestionarlo")

type parsed struct {
	before, after string // texto fuera del bloque (con sus saltos de línea)
	found         bool
	servers       []Server
}

func parseConfig(content string, frontPort int) (parsed, error) {
	lines := strings.Split(content, "\n")
	begin, end := -1, -1
	for i, l := range lines {
		switch strings.TrimRight(l, "\r") {
		case beginMark:
			if begin >= 0 {
				return parsed{}, errors.New("haproxy.cfg tiene dos marcas BEGIN de la consola")
			}
			begin = i
		case endMark:
			if end >= 0 {
				return parsed{}, errors.New("haproxy.cfg tiene dos marcas END de la consola")
			}
			end = i
		}
	}
	if begin < 0 && end < 0 {
		return parsed{before: content, found: false}, nil
	}
	if begin < 0 || end < 0 || end < begin {
		return parsed{}, errors.New("las marcas BEGIN/END de la consola en haproxy.cfg están incompletas o desordenadas")
	}
	var p parsed
	p.found = true
	if begin > 0 {
		p.before = strings.Join(lines[:begin], "\n") + "\n"
	}
	p.after = strings.Join(lines[end+1:], "\n")
	for _, l := range lines[begin : end+1] {
		if m := reServerLine.FindStringSubmatch(l); m != nil {
			port, _ := strconv.Atoi(m[3])
			p.servers = append(p.servers, Server{Name: m[1], IP: m[2], Port: port})
		}
	}
	actual := strings.Join(lines[begin:end+1], "\n") + "\n"
	if actual != buildBlock(frontPort, p.servers) {
		return parsed{}, ErrEdited
	}
	return p, nil
}

// render arma el archivo completo con el bloque dado.
func (p parsed) render(block string) string {
	if !p.found {
		return strings.TrimRight(p.before, "\n") + "\n\n" + block
	}
	return p.before + block + p.after
}

var (
	reOtherBind     = regexp.MustCompile(`(?m)^[ \t]*bind[ \t]+\S*:([0-9]+)\b`)
	reOtherSections = regexp.MustCompile(`(?m)^[ \t]*(frontend|backend)[ \t]+(` + frontendName + `|` + backendName + `)\b`)
)

// checkOutside revisa que lo que está FUERA del bloque no choque con él.
func (p parsed) checkOutside(frontPort int) error {
	outside := p.before + p.after
	if reOtherSections.MatchString(outside) {
		return fmt.Errorf("haproxy.cfg ya define «%s» o «%s» fuera del bloque de la consola", frontendName, backendName)
	}
	for _, m := range reOtherBind.FindAllStringSubmatch(outside, -1) {
		if m[1] == strconv.Itoa(frontPort) {
			return fmt.Errorf("otra sección de haproxy.cfg ya escucha en el puerto %d; la consola no puede crear su frontend en ese puerto", frontPort)
		}
	}
	return nil
}
