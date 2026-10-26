package runner

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sync"

	"consola/internal/config"
)

// TargetState es el estado persistente de cada VM.
type TargetState struct {
	SSHReady bool   `json:"sshReady"`
	KeyPath  string `json:"keyPath,omitempty"`
}

// Manager elige el canal de cada VM: Guest Additions hasta que SSH quede
// configurado con llave; desde ese momento, exclusivamente SSH.
type Manager struct {
	cfg       *config.Config
	statePath string
	mu        sync.Mutex
	state     map[string]TargetState
}

func NewManager(cfg *config.Config) (*Manager, error) {
	m := &Manager{
		cfg:       cfg,
		statePath: filepath.Join(cfg.DataDir, "state.json"),
		state:     map[string]TargetState{},
	}
	b, err := os.ReadFile(m.statePath)
	switch {
	case err == nil:
		if err := json.Unmarshal(b, &m.state); err != nil {
			return nil, fmt.Errorf("%s dañado: %w", m.statePath, err)
		}
	case errors.Is(err, fs.ErrNotExist):
	default:
		return nil, err
	}
	return m, nil
}

func (m *Manager) Get(target string) (Runner, error) {
	t, ok := m.cfg.Targets[target]
	if !ok {
		return nil, fmt.Errorf("objetivo desconocido: %q", target)
	}
	m.mu.Lock()
	st := m.state[target]
	m.mu.Unlock()
	if st.SSHReady {
		return m.sshFor(t, target, st.KeyPath), nil
	}
	return &GuestControl{VBoxManage: m.cfg.VBoxManage, VM: t.VMName, User: t.GuestUser, Password: t.GuestPassword}, nil
}

func (m *Manager) sshFor(t config.Target, target, keyPath string) *SSH {
	return &SSH{
		Host:           t.IP,
		Port:           t.SSHPort,
		User:           "root",
		KeyPath:        keyPath,
		KnownHostsPath: filepath.Join(m.cfg.DataDir, "known_hosts", target),
	}
}

// SSHFor devuelve un cliente SSH que usa la llave dada, sin importar si el
// canal ya cambió a SSH. Sirve para comprobar una llave recién instalada
// antes de dar el cambio por hecho.
func (m *Manager) SSHFor(target, keyPath string) (KeyProber, error) {
	t, ok := m.cfg.Targets[target]
	if !ok {
		return nil, fmt.Errorf("objetivo desconocido: %q", target)
	}
	return m.sshFor(t, target, keyPath), nil
}

// Status informa el canal activo y si SSH ya está listo.
func (m *Manager) Status(target string) (channel string, sshReady bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.state[target].SSHReady {
		return ChannelSSH, true
	}
	return ChannelGuest, false
}

// MarkSSHReady registra que SSH con llave ya funciona; a partir de aquí
// todas las operaciones sobre la VM usan SSH.
func (m *Manager) MarkSSHReady(target, keyPath string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.state[target] = TargetState{SSHReady: true, KeyPath: keyPath}
	b, err := json.MarshalIndent(m.state, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(m.statePath), 0o700); err != nil {
		return err
	}
	return os.WriteFile(m.statePath, b, 0o600)
}
