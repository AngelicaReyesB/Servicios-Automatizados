// Package runner abstrae el canal de comunicación con la máquina virtual:
// Guest Additions (VBoxManage guestcontrol) antes de instalar SSH, y SSH con
// llaves después. Los módulos solo conocen la interfaz Runner.
package runner

import (
	"context"
	"errors"
	"os"
	"strings"
	"time"
)

const (
	ChannelGuest = "Guest Additions"
	ChannelSSH   = "SSH (llave)"
)

// Result es el resultado de ejecutar un script en la VM.
type Result struct {
	Stdout   string
	Stderr   string
	ExitCode int
	Channel  string
	Duration time.Duration
}

func (r Result) OK() bool { return r.ExitCode == 0 }

var ErrNotSupported = errors.New("operación no soportada por este canal")

// Runner ejecuta scripts de bash en la VM.
//
// Convención: el error devuelto es solo de transporte (no se pudo llegar a la
// VM). Que el script termine con código distinto de cero NO es un error: se
// informa en Result.ExitCode.
type Runner interface {
	Name() string
	Run(ctx context.Context, script string) (Result, error)
	// RunInput como Run, pero entrega stdin al script (p. ej. contraseñas).
	// El canal Guest Additions no lo soporta.
	RunInput(ctx context.Context, script, stdin string) (Result, error)
	// Upload copia un archivo local a la VM y le asigna los permisos dados.
	Upload(ctx context.Context, local, remote string, mode os.FileMode) error
}

// KeyProber es un Runner por SSH que además puede comprobar si el servidor
// todavía acepta autenticación por contraseña.
type KeyProber interface {
	Runner
	PasswordLoginAccepted(ctx context.Context, password string) (accepted bool, err error)
}

// shellQuote entrecomilla s para bash con comillas simples.
func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}
