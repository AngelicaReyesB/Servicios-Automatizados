package balanceador

import (
	"errors"
	"strings"
	"testing"
)

const debianDefault = `global
	log /dev/log	local0
	log /dev/log	local1 notice
	chroot /var/lib/haproxy
	stats socket /run/haproxy/admin.sock mode 660 level admin
	user haproxy
	group haproxy
	daemon

defaults
	log	global
	mode	http
	option	httplog
	option	dontlognull
	timeout connect 5000
	timeout client  50000
	timeout server  50000
`

func TestBuildBlock(t *testing.T) {
	got := buildBlock(80, []Server{{"web1", "192.168.1.10", 80}, {"web2", "192.168.1.11", 8080}})
	want := beginMark + "\n" +
		"frontend consola_front\n    bind *:80\n    default_backend consola_back\n\n" +
		"backend consola_back\n    balance roundrobin\n" +
		"    server web1 192.168.1.10:80 check\n    server web2 192.168.1.11:8080 check\n" +
		endMark + "\n"
	if got != want {
		t.Errorf("bloque:\n%s\nesperado:\n%s", got, want)
	}
}

func TestParseWithoutBlockAndRenderKeepsOriginal(t *testing.T) {
	p, err := parseConfig(debianDefault, 80)
	if err != nil || p.found || len(p.servers) != 0 {
		t.Fatalf("%+v %v", p, err)
	}
	out := p.render(buildBlock(80, []Server{{"web1", "10.0.0.5", 80}}))
	if !strings.HasPrefix(out, debianDefault) || !strings.HasSuffix(out, endMark+"\n") || !strings.Contains(out, "\n\n"+beginMark) {
		t.Errorf("render:\n%s", out)
	}
	// un archivo sin salto de línea final también queda bien formado
	p, _ = parseConfig(strings.TrimRight(debianDefault, "\n"), 80)
	if out := p.render(buildBlock(80, nil)); !strings.Contains(out, "timeout server  50000\n\n"+beginMark) {
		t.Errorf("sin salto final:\n%s", out)
	}
}

func TestParseRoundTripPreservesSurroundings(t *testing.T) {
	servers := []Server{{"a", "10.0.0.1", 80}, {"b", "10.0.0.2", 81}}
	content := "global\n    daemon\n\n" + buildBlock(80, servers) + "\nlisten stats\n    bind *:9000\n"
	p, err := parseConfig(content, 80)
	if err != nil || !p.found || len(p.servers) != 2 || p.servers[1] != (Server{"b", "10.0.0.2", 81}) {
		t.Fatalf("%+v %v", p, err)
	}
	if got := p.render(buildBlock(80, p.servers)); got != content {
		t.Errorf("no es idempotente:\n%q\n%q", got, content)
	}
	// al cambiar los servidores solo cambia el bloque
	got := p.render(buildBlock(80, p.servers[:1]))
	want := "global\n    daemon\n\n" + buildBlock(80, servers[:1]) + "\nlisten stats\n    bind *:9000\n"
	if got != want {
		t.Errorf("quitar servidor:\n%q\n%q", got, want)
	}
	// bloque al inicio y al final del archivo
	for _, c := range []string{buildBlock(80, servers), buildBlock(80, servers) + "defaults\n    mode http\n", "x\n" + strings.TrimSuffix(buildBlock(80, servers), "\n")} {
		p, err := parseConfig(c, 80)
		if err != nil {
			t.Fatalf("%q: %v", c, err)
		}
		want := c
		if !strings.HasSuffix(c, "\n") {
			want += "\n" // el único cambio permitido: terminar el archivo con salto de línea
		}
		if got := p.render(buildBlock(80, p.servers)); got != want {
			t.Errorf("no idempotente:\n%q\n%q", got, want)
		}
	}
}

func TestParseDetectsHandEditsAndBrokenMarkers(t *testing.T) {
	good := buildBlock(80, []Server{{"a", "10.0.0.1", 80}})
	edits := map[string]string{
		"servidor con opción extra": strings.Replace(good, "check\n", "check weight 5\n", 1),
		"línea ajena":               strings.Replace(good, "    balance roundrobin\n", "    balance leastconn\n", 1),
		"otro puerto":               strings.Replace(good, "*:80", "*:8081", 1),
		"línea añadida":             strings.Replace(good, endMark, "    option httpchk\n"+endMark, 1),
	}
	for name, c := range edits {
		if _, err := parseConfig(c, 80); !errors.Is(err, ErrEdited) {
			t.Errorf("%s: debía dar ErrEdited, dio %v", name, err)
		}
	}
	broken := map[string]string{
		"solo BEGIN":  beginMark + "\nfrontend x\n",
		"solo END":    endMark + "\n",
		"END antes":   endMark + "\n" + beginMark + "\n",
		"BEGIN doble": good + good,
		"dos END":     beginMark + "\n" + endMark + "\n" + endMark + "\n",
	}
	for name, c := range broken {
		if _, err := parseConfig(c, 80); err == nil || errors.Is(err, ErrEdited) {
			t.Errorf("%s: debía dar error de marcas, dio %v", name, err)
		}
	}
}

func TestCheckOutsideDetectsConflicts(t *testing.T) {
	ok, _ := parseConfig(debianDefault+"\nlisten stats\n    bind *:9000\n", 80)
	if err := ok.checkOutside(80); err != nil {
		t.Errorf("sin conflicto: %v", err)
	}
	for name, extra := range map[string]string{
		"mismo puerto":     "frontend otro\n    bind *:80\n",
		"puerto con IP":    "frontend otro\n    bind 0.0.0.0:80 ssl\n",
		"mismo frontend":   "frontend consola_front\n    bind *:81\n",
		"mismo backend":    "backend consola_back\n",
		"puerto en listen": "listen app\n    bind :80\n",
	} {
		p, _ := parseConfig(debianDefault+"\n"+extra, 80)
		if err := p.checkOutside(80); err == nil {
			t.Errorf("%s: debía detectarse el conflicto", name)
		}
	}
	// un bind en 8080 o 800 no es conflicto con 80
	p, _ := parseConfig(debianDefault+"\nfrontend x\n    bind *:8080\n    bind *:800\n", 80)
	if err := p.checkOutside(80); err != nil {
		t.Errorf("8080/800 no chocan con 80: %v", err)
	}
	// el propio bloque no cuenta como «fuera»
	p, _ = parseConfig(debianDefault+"\n"+buildBlock(80, []Server{{"a", "10.0.0.1", 80}}), 80)
	if err := p.checkOutside(80); err != nil {
		t.Errorf("el bloque propio no debe chocar: %v", err)
	}
}
