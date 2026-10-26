// Package common reúne lo que comparten los módulos de la consola: el
// resultado que se muestra al usuario y la ejecución registrada de scripts.
package common

import (
	"context"
	"fmt"
	"strings"
	"time"

	"consola/internal/oplog"
	"consola/internal/runner"
)

// Outcome es lo que la interfaz muestra al usuario tras una operación.
type Outcome struct {
	OK      bool
	Title   string
	Message string // explicación comprensible
	Detail  string // información técnica para el diagnóstico
	Preview string // texto de vista previa (opcional), se muestra tal cual
	// DownloadUser, si no está vacío, ofrece descargar la llave privada de ese usuario.
	DownloadUser string
}

// Provider entrega el Runner vigente (Guest Additions o SSH) de una VM.
type Provider interface {
	Get(target string) (runner.Runner, error)
}

func Invalid(err error) Outcome {
	return Outcome{Title: "Datos no válidos", Message: err.Error()}
}

func Busy() Outcome {
	return Outcome{Title: "Operación en curso", Message: "Hay otra operación ejecutándose en la máquina virtual. Espere a que termine e intente de nuevo."}
}

func TransportFailure(res runner.Result, err error) Outcome {
	hint := "Verifique que la máquina virtual esté encendida y que la configuración de config.json sea correcta."
	switch {
	case strings.Contains(res.Channel, "SSH"):
		hint = "Verifique que la VM esté encendida, que su IP en config.json sea la actual y que la llave privada siga siendo válida."
	case strings.Contains(res.Channel, "Guest"):
		hint = "Verifique que la VM esté encendida, que las Guest Additions estén en ejecución y que guestUser/guestPassword en config.json sean correctos."
	}
	return Outcome{
		Title:   "No se pudo ejecutar la operación en la máquina virtual",
		Message: hint,
		Detail:  "Error de comunicación: " + err.Error(),
	}
}

// Detail arma el detalle técnico de un resultado.
func Detail(res runner.Result) string {
	var b strings.Builder
	fmt.Fprintf(&b, "Canal: %s\nCódigo de salida: %d\nDuración: %s\n", res.Channel, res.ExitCode, res.Duration.Round(time.Millisecond))
	if s := strings.TrimSpace(res.Stdout); s != "" {
		b.WriteString("\n--- stdout ---\n" + s + "\n")
	}
	if s := strings.TrimSpace(res.Stderr); s != "" {
		b.WriteString("\n--- stderr ---\n" + s + "\n")
	}
	return b.String()
}

func FirstLine(s string) string {
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return strings.TrimSpace(s[:i])
	}
	return strings.TrimSpace(s)
}

// Run ejecuta el script en el canal dado y deja el registro técnico.
func Run(ctx context.Context, log *oplog.Logger, module, target string, r runner.Runner, op, script string) (runner.Result, error) {
	res, err := r.Run(ctx, script)
	res.Channel = r.Name()
	e := oplog.Entry{
		Module: module, Operation: op, Target: target, Channel: res.Channel,
		OK: err == nil && res.OK(), ExitCode: res.ExitCode, DurationMS: res.Duration.Milliseconds(),
		Script: script, Stdout: res.Stdout, Stderr: res.Stderr,
	}
	if err != nil {
		e.Error = err.Error()
	}
	log.Record(e)
	return res, err
}

// RunOn obtiene el canal vigente y ejecuta el script; si no hay canal, lo registra.
func RunOn(ctx context.Context, log *oplog.Logger, p Provider, module, target, op, script string) (runner.Result, error) {
	r, err := p.Get(target)
	if err != nil {
		log.Record(oplog.Entry{Module: module, Operation: op, Target: target, Script: script, Error: err.Error()})
		return runner.Result{}, err
	}
	return Run(ctx, log, module, target, r, op, script)
}
