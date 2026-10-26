package preparacion

// 3.1.3 Personalización de la entrada del sistema (/etc/issue).
//
// agetty muestra /etc/issue antes del "login:" y reemplaza secuencias que
// empiezan con barra invertida (\n nombre del host, \d fecha, \t hora, \4 IPv4,
// ...). Por eso el mensaje del usuario se escapa: si escribe "\n" debe verse
// "\n", no el nombre del host.

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"unicode"
	"unicode/utf8"
)

const (
	maxIssueMessage = 200
	previewMarker   = "--- vista previa: así lo verá en el inicio de sesión ---"
	issueBackupExt  = ".consola.bak"
)

// issuePath es el archivo que se escribe; las pruebas lo cambian.
var issuePath = "/etc/issue"

// IssueOptions indica qué datos mostrar en el aviso de inicio de sesión.
type IssueOptions struct {
	Host    bool // nombre del host   (\n)
	Date    bool // fecha actual      (\d)
	Time    bool // hora actual       (\t)
	IP      bool // dirección IPv4    (\4)
	OS      bool // sistema operativo (\S{PRETTY_NAME})
	Kernel  bool // versión del kernel (\r)
	Arch    bool // arquitectura      (\m)
	TTY     bool // terminal          (\l)
	Users   bool // usuarios conectados (\u)
	Message string
}

// DefaultIssueOptions son las opciones que la interfaz marca de entrada.
func DefaultIssueOptions() IssueOptions {
	return IssueOptions{Host: true, Date: true, Time: true, IP: true}
}

func (o IssueOptions) lines() []string {
	var out []string
	add := func(on bool, line string) {
		if on {
			out = append(out, line)
		}
	}
	add(o.Host, `Nombre del host: \n`)
	add(o.Date, `Fecha: \d`)
	add(o.Time, `Hora: \t`)
	add(o.IP, `Dirección IP: \4`)
	add(o.OS, `Sistema operativo: \S{PRETTY_NAME}`)
	add(o.Kernel, `Kernel: \r`)
	add(o.Arch, `Arquitectura: \m`)
	add(o.TTY, `Terminal: \l`)
	add(o.Users, `Usuarios conectados: \u`)
	return out
}

// BuildIssue valida las opciones y arma el contenido de /etc/issue.
func BuildIssue(o IssueOptions) (string, error) {
	msg := strings.TrimSpace(o.Message)
	if err := validateIssueMessage(msg); err != nil {
		return "", err
	}
	lines := o.lines()
	if len(lines) == 0 && msg == "" {
		return "", errors.New("seleccione al menos un dato o escriba un mensaje personalizado")
	}

	var b strings.Builder
	if msg != "" {
		b.WriteString(strings.ReplaceAll(msg, `\`, `\\`)) // la barra invertida es literal
		b.WriteString("\n")
		if len(lines) > 0 {
			b.WriteString("\n")
		}
	}
	for _, l := range lines {
		b.WriteString(l)
		b.WriteString("\n")
	}
	b.WriteString("\n") // línea en blanco antes del "login:", como el /etc/issue original
	return b.String(), nil
}

func validateIssueMessage(msg string) error {
	if !utf8.ValidString(msg) {
		return errors.New("el mensaje contiene caracteres no válidos")
	}
	if n := utf8.RuneCountInString(msg); n > maxIssueMessage {
		return fmt.Errorf("el mensaje es demasiado largo (%d caracteres; máximo %d)", n, maxIssueMessage)
	}
	for _, r := range msg {
		// Los caracteres de control (p. ej. ESC) permitirían manipular la pantalla del
		// inicio de sesión; los de formato (p. ej. cambios de dirección de texto) permiten
		// disfrazar su contenido.
		if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) || r == ' ' || r == ' ' {
			return errors.New("el mensaje no puede contener caracteres de control ni saltos de línea")
		}
	}
	return nil
}

const issueScript = `export LC_ALL=C
ISSUE={{ISSUE}}
echo "--- estado previo ---"
if [ -f "$ISSUE" ]; then cat "$ISSUE"; else echo "(no existe)"; fi
set -e
if [ -f "$ISSUE" ] && [ ! -f "$ISSUE.consola.bak" ]; then cp -p "$ISSUE" "$ISSUE.consola.bak"; fi
tmp=$(mktemp)
printf '%s' '{{B64}}' | base64 -d > "$tmp"
install -m 644 "$tmp" "$ISSUE"
if ! cmp -s "$tmp" "$ISSUE"; then rm -f "$tmp"; echo "El contenido escrito no coincide con el generado" >&2; exit 1; fi
rm -f "$tmp"
echo "--- verificación ---"
cat "$ISSUE"
echo "` + previewMarker + `"
AG=$(command -v agetty || true)
if [ -n "$AG" ] && command -v script >/dev/null 2>&1; then
  script -qec "$AG --show-issue --issue-file $ISSUE" /dev/null | tr -d '\r' || true
else
  echo "(vista previa no disponible: no se encontró agetty o script)"
fi
`

func renderIssueScript(path, content string) string {
	return strings.NewReplacer(
		"{{ISSUE}}", path,
		"{{B64}}", base64.StdEncoding.EncodeToString([]byte(content)),
	).Replace(issueScript)
}

// ApplyIssue escribe /etc/issue con las opciones dadas (3.1.3).
func (s *Service) ApplyIssue(ctx context.Context, o IssueOptions) Outcome {
	content, err := BuildIssue(o)
	if err != nil {
		return invalid(err)
	}
	if !s.mu.TryLock() {
		return busy()
	}
	defer s.mu.Unlock()
	ctx, cancel := context.WithTimeout(ctx, opTimeout)
	defer cancel()

	res, err := s.exec(ctx, "Personalizar el mensaje de entrada (/etc/issue)", renderIssueScript(issuePath, content))
	if err != nil {
		return transportFailure(res, err)
	}
	if !res.OK() {
		return Outcome{
			Title:   "No se pudo actualizar /etc/issue",
			Message: diagnoseIssue(res.Stdout + "\n" + res.Stderr),
			Detail:  detail(res),
		}
	}
	return Outcome{
		OK:    true,
		Title: "Operación completada",
		Message: "Se actualizó " + issuePath + ". Aparecerá en el siguiente aviso de inicio de sesión de la consola de la VM " +
			"(cierre sesión o pulse Enter en la pantalla de login). Se conservó una copia del original en " + issuePath + issueBackupExt + ".",
		Detail:  detail(res),
		Preview: previewOf(res.Stdout),
	}
}

// previewOf extrae la vista previa que imprime el script, si está disponible.
func previewOf(stdout string) string {
	i := strings.LastIndex(stdout, previewMarker)
	if i < 0 {
		return ""
	}
	p := strings.TrimSpace(stdout[i+len(previewMarker):])
	if strings.HasPrefix(p, "(vista previa no disponible") {
		return ""
	}
	return p
}

func diagnoseIssue(out string) string {
	switch {
	case strings.Contains(out, "No space left"):
		return "No hay espacio en disco en la VM para escribir el archivo."
	case strings.Contains(out, "Read-only file system"):
		return "El sistema de archivos de la VM es de solo lectura."
	case strings.Contains(out, "no coincide"):
		return "El contenido escrito no coincide con el generado. Vuelva a intentarlo."
	}
	return "No se pudo escribir el archivo. Revise el detalle técnico."
}
