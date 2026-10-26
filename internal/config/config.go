// Package config carga y valida la configuración de la consola.
package config

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"runtime"
)

// Target describe una máquina virtual administrada.
type Target struct {
	VMName        string `json:"vmName"`        // nombre exacto en VirtualBox
	IP            string `json:"ip"`            // IP en modo puente (para SSH)
	SSHPort       int    `json:"sshPort"`       // por defecto 22
	GuestUser     string `json:"guestUser"`     // usuario para Guest Additions (antes de SSH)
	GuestPassword string `json:"guestPassword"` // contraseña para Guest Additions
}

type Config struct {
	Listen     string            `json:"listen"`
	VBoxManage string            `json:"vboxmanage"`
	DataDir    string            `json:"dataDir"`
	Authors    string            `json:"authors"`
	Targets    map[string]Target `json:"targets"`
}

func Load(path string) (*Config, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("no se pudo leer %s: %w (copie config.example.json a config.json y edítelo)", path, err)
	}
	var c Config
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&c); err != nil {
		return nil, fmt.Errorf("config.json inválido: %w", err)
	}
	if err := c.normalize(); err != nil {
		return nil, err
	}
	return &c, nil
}

func (c *Config) normalize() error {
	if c.Listen == "" {
		c.Listen = "127.0.0.1:8080"
	}
	host, _, err := net.SplitHostPort(c.Listen)
	if err != nil {
		return fmt.Errorf("listen inválido %q: %w", c.Listen, err)
	}
	// La consola ejecuta comandos como root en las VMs: solo debe escuchar en loopback.
	if host != "127.0.0.1" && host != "localhost" && host != "::1" {
		return fmt.Errorf("listen debe ser una dirección local (127.0.0.1, localhost o ::1), no %q", host)
	}
	if c.VBoxManage == "" {
		if runtime.GOOS == "windows" {
			c.VBoxManage = `C:\Program Files\Oracle\VirtualBox\VBoxManage.exe`
		} else {
			c.VBoxManage = "VBoxManage"
		}
	}
	if c.DataDir == "" {
		c.DataDir = "data"
	}
	if c.Authors == "" {
		c.Authors = `(configure "authors" en config.json)`
	}
	if _, ok := c.Targets["main"]; !ok {
		return fmt.Errorf(`config.json debe definir el objetivo "main"`)
	}
	for name, t := range c.Targets {
		if t.VMName == "" {
			return fmt.Errorf("objetivo %q: falta vmName", name)
		}
		if net.ParseIP(t.IP) == nil {
			return fmt.Errorf("objetivo %q: ip inválida %q", name, t.IP)
		}
		if t.SSHPort == 0 {
			t.SSHPort = 22
		}
		if t.SSHPort < 1 || t.SSHPort > 65535 {
			return fmt.Errorf("objetivo %q: sshPort fuera de rango", name)
		}
		if t.GuestUser == "" {
			t.GuestUser = "root"
		}
		c.Targets[name] = t
	}
	return nil
}
