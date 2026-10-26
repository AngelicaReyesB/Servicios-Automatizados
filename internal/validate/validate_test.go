package validate

import (
	"strings"
	"testing"
)

func TestPackage(t *testing.T) {
	ok := []string{"htop", "apache2", "g++", "libc++-dev", "python3.13"}
	bad := []string{"", "a", "-rf", "Htop", "htop; reboot", "htop apache2", "$(id)", "a`b`", "pkg\nother"}
	for _, s := range ok {
		if err := Package(s); err != nil {
			t.Errorf("Package(%q) debería ser válido: %v", s, err)
		}
	}
	for _, s := range bad {
		if err := Package(s); err == nil {
			t.Errorf("Package(%q) debería ser inválido", s)
		}
	}
}

func TestHostname(t *testing.T) {
	ok := []string{"app-web1", "a", "debian13", strings.Repeat("a", 63)}
	bad := []string{"", "app_web1", "App", "-a", "a-", "a.b", strings.Repeat("a", 64), "a b", "a;b"}
	for _, s := range ok {
		if err := Hostname(s); err != nil {
			t.Errorf("Hostname(%q) debería ser válido: %v", s, err)
		}
	}
	for _, s := range bad {
		if err := Hostname(s); err == nil {
			t.Errorf("Hostname(%q) debería ser inválido", s)
		}
	}
}

func TestUsernameUnitIP(t *testing.T) {
	if Username("carlos_1") != nil || Username("1carlos") == nil || Username("Root") == nil || Username("a;b") == nil {
		t.Error("Username no valida como se esperaba")
	}
	if UnitName("catalogo.service") != nil || UnitName("app@1") != nil || UnitName("-x") == nil || UnitName("a b") == nil {
		t.Error("UnitName no valida como se esperaba")
	}
	if IPv4("192.168.1.10") != nil || IPv4("::1") == nil || IPv4("300.1.1.1") == nil || IPv4("a.b.c.d") == nil {
		t.Error("IPv4 no valida como se esperaba")
	}
	if Port(8080) != nil || Port(0) == nil || Port(70000) == nil {
		t.Error("Port no valida como se esperaba")
	}
}

func TestServiceServerAndBackendIP(t *testing.T) {
	for _, ok := range []string{"catalogo", "catalogo-libros", "ab", "a1"} {
		if ServiceName(ok) != nil {
			t.Errorf("ServiceName(%q) debía ser válido", ok)
		}
	}
	for _, bad := range []string{"", "a", "Catalogo", "1abc", "a_b", "a.b", "a b", "../x", "a;b", strings.Repeat("a", 32)} {
		if ServiceName(bad) == nil {
			t.Errorf("ServiceName(%q) debía ser inválido", bad)
		}
	}
	if ServerName("web1") != nil || ServerName("web_1-a") != nil || ServerName("Web") == nil || ServerName("1web") == nil || ServerName("a b") == nil || ServerName("") == nil {
		t.Error("ServerName no valida como se esperaba")
	}
	if BackendIPv4("192.168.1.10") != nil {
		t.Error("IP de red válida")
	}
	for _, bad := range []string{"0.0.0.0", "127.0.0.1", "224.0.0.1", "255.255.255.255", "192.168.001.010", "::1", "x"} {
		if BackendIPv4(bad) == nil {
			t.Errorf("BackendIPv4(%q) debía ser inválida", bad)
		}
	}
}
