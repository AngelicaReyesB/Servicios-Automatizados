package runner

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// exitMarker lo imprime el envoltorio en stderr con el código de salida real
// del script: VBoxManage solo informa éxito/fracaso, no el código exacto.
const exitMarker = "__CONSOLA_EXIT="

// GuestControl ejecuta comandos con "VBoxManage guestcontrol" (Guest Additions).
type GuestControl struct {
	VBoxManage string
	VM         string
	User       string
	Password   string
}

func (g *GuestControl) Name() string { return ChannelGuest }

// wrapScript convierte un script multilínea en una sola línea segura para
// pasar como argumento: lo envía en base64, lo guarda en un temporal, lo
// ejecuta y reporta su código de salida.
func wrapScript(script string) string {
	b64 := base64.StdEncoding.EncodeToString([]byte(script))
	return "f=$(mktemp); echo " + b64 + " | base64 -d > $f; bash $f; rc=$?; rm -f $f; echo " + exitMarker + "$rc >&2"
}

// runArgs arma los argumentos de "VBoxManage guestcontrol ... run".
//
// Según la versión de VirtualBox, lo que va después de "--" se interpreta de
// dos maneras: (A) el primer elemento es argv[0] y el resto son argumentos, o
// (B) argv[0] es el valor de --exe y TODO lo que sigue son argumentos. Con
// "bash -c ..." la variante B ejecutaba "bash bash -c ..." y fallaba con
// "no se puede ejecutar el fichero binario".
//
// Se usa /usr/bin/env como ejecutable: "env env bash -c X" (B) y
// "env bash -c X" (A) hacen exactamente lo mismo, así que funciona en ambas.
func runArgs(vm, user, passwordFile, script string) []string {
	return []string{
		"guestcontrol", vm, "run",
		"--username", user, "--passwordfile", passwordFile,
		"--exe", "/usr/bin/env", "--wait-stdout", "--wait-stderr",
		"--", "env", "bash", "-c", wrapScript(script),
	}
}

// splitExit separa el marcador de código de salida del resto de stderr.
func splitExit(stderr string) (clean string, code int, found bool) {
	i := strings.LastIndex(stderr, exitMarker)
	if i < 0 {
		return stderr, 0, false
	}
	rest := stderr[i+len(exitMarker):]
	num, tail := rest, ""
	if end := strings.IndexAny(rest, "\r\n"); end >= 0 {
		num, tail = rest[:end], rest[end:]
	}
	code, err := strconv.Atoi(strings.TrimSpace(num))
	if err != nil {
		return stderr, 0, false
	}
	return stderr[:i] + strings.TrimLeft(tail, "\r\n"), code, true
}

// pwFile escribe la contraseña en un archivo temporal (0600) para usar
// --passwordfile y no exponerla en la línea de comandos.
func (g *GuestControl) pwFile() (string, func(), error) {
	f, err := os.CreateTemp("", "consola-vbpw-*")
	if err != nil {
		return "", nil, err
	}
	name := f.Name()
	cleanup := func() { os.Remove(name) }
	if _, err := f.WriteString(g.Password); err != nil {
		f.Close()
		cleanup()
		return "", nil, err
	}
	if err := f.Close(); err != nil {
		cleanup()
		return "", nil, err
	}
	return name, cleanup, nil
}

func (g *GuestControl) Run(ctx context.Context, script string) (Result, error) {
	start := time.Now()
	pw, cleanup, err := g.pwFile()
	if err != nil {
		return Result{}, err
	}
	defer cleanup()

	args := runArgs(g.VM, g.User, pw, script)
	var stdout, stderr bytes.Buffer
	cmd := exec.CommandContext(ctx, g.VBoxManage, args...)
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	runErr := cmd.Run()

	clean, code, found := splitExit(stderr.String())
	res := Result{Stdout: stdout.String(), Stderr: clean, ExitCode: code, Channel: g.Name(), Duration: time.Since(start)}
	if found {
		return res, nil
	}
	// Sin marcador: el script no llegó a ejecutarse (VM apagada, credenciales
	// incorrectas, Guest Additions sin iniciar, VBoxManage no encontrado...).
	if ctx.Err() != nil {
		return res, fmt.Errorf("operación cancelada o con tiempo agotado: %w", ctx.Err())
	}
	var ee *exec.ExitError
	switch {
	case errors.As(runErr, &ee):
		return res, fmt.Errorf("VBoxManage terminó con código %d: %s", ee.ExitCode(), strings.TrimSpace(clean))
	case runErr != nil:
		return res, fmt.Errorf("no se pudo ejecutar VBoxManage (%s): %w", g.VBoxManage, runErr)
	}
	return res, errors.New("VBoxManage no devolvió el código de salida del script")
}

func (g *GuestControl) RunInput(ctx context.Context, script, stdin string) (Result, error) {
	return Result{Channel: g.Name()}, ErrNotSupported
}

func (g *GuestControl) Upload(ctx context.Context, local, remote string, mode os.FileMode) error {
	if _, err := os.Stat(local); err != nil {
		return fmt.Errorf("no se puede leer el archivo local: %w", err)
	}
	const stage = "/tmp/consola-upload"
	res, err := g.Run(ctx, "mkdir -p "+stage)
	if err != nil {
		return err
	}
	if !res.OK() {
		return fmt.Errorf("no se pudo crear %s en la VM: %s", stage, strings.TrimSpace(res.Stderr))
	}

	pw, cleanup, err := g.pwFile()
	if err != nil {
		return err
	}
	defer cleanup()
	var out bytes.Buffer
	cmd := exec.CommandContext(ctx, g.VBoxManage, "guestcontrol", g.VM, "copyto",
		"--username", g.User, "--passwordfile", pw, "--target-directory", stage+"/", local)
	cmd.Stdout, cmd.Stderr = &out, &out
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("falló VBoxManage copyto: %w: %s", err, strings.TrimSpace(out.String()))
	}

	staged := stage + "/" + filepath.Base(local)
	install := fmt.Sprintf(`mkdir -p -- "$(dirname -- %[1]s)" && mv -f -- %[2]s %[1]s && chmod %[3]04o %[1]s`,
		shellQuote(remote), shellQuote(staged), uint32(mode.Perm()))
	res, err = g.Run(ctx, install)
	if err != nil {
		return err
	}
	if !res.OK() {
		return fmt.Errorf("no se pudo colocar el archivo en %s: %s", remote, strings.TrimSpace(res.Stderr))
	}
	return nil
}
