// Package oplog guarda un registro técnico de cada operación (JSON por línea)
// y conserva las últimas en memoria para mostrarlas en la interfaz.
package oplog

import (
	"encoding/json"
	"log"
	"os"
	"path/filepath"
	"sync"
	"time"
)

const (
	maxRecent = 100
	maxOutput = 64 * 1024
)

type Entry struct {
	Time       time.Time `json:"time"`
	Module     string    `json:"module"`
	Operation  string    `json:"operation"`
	Target     string    `json:"target"`
	Channel    string    `json:"channel"`
	OK         bool      `json:"ok"`
	ExitCode   int       `json:"exitCode"`
	DurationMS int64     `json:"durationMs"`
	Script     string    `json:"script,omitempty"`
	Stdout     string    `json:"stdout,omitempty"`
	Stderr     string    `json:"stderr,omitempty"`
	Error      string    `json:"error,omitempty"`
}

type Logger struct {
	mu     sync.Mutex
	f      *os.File
	recent []Entry // la más antigua primero
}

func New(path string) (*Logger, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, err
	}
	return &Logger{f: f}, nil
}

func trunc(s string) string {
	if len(s) > maxOutput {
		return s[:maxOutput] + "\n[...salida truncada...]"
	}
	return s
}

func (l *Logger) Record(e Entry) {
	if e.Time.IsZero() {
		e.Time = time.Now()
	}
	e.Stdout, e.Stderr = trunc(e.Stdout), trunc(e.Stderr)
	l.mu.Lock()
	defer l.mu.Unlock()
	l.recent = append(l.recent, e)
	if len(l.recent) > maxRecent {
		l.recent = l.recent[len(l.recent)-maxRecent:]
	}
	b, err := json.Marshal(e)
	if err == nil {
		_, err = l.f.Write(append(b, '\n'))
	}
	if err != nil {
		log.Printf("oplog: no se pudo escribir el registro: %v", err)
	}
}

// Recent devuelve hasta n entradas, la más reciente primero.
func (l *Logger) Recent(n int) []Entry {
	l.mu.Lock()
	defer l.mu.Unlock()
	if n > len(l.recent) {
		n = len(l.recent)
	}
	out := make([]Entry, 0, n)
	for i := len(l.recent) - 1; i >= len(l.recent)-n; i-- {
		out = append(out, l.recent[i])
	}
	return out
}

func (l *Logger) Close() error { return l.f.Close() }
