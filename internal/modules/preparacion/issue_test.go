package preparacion

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"consola/internal/runner"
	"consola/internal/sshtest"
)

func TestBuildIssueDefaultOptions(t *testing.T) {
	o := DefaultIssueOptions()
	o.Message = "Acceso solo para personal autorizado"
	got, err := BuildIssue(o)
	if err != nil {
		t.Fatal(err)
	}
	want := "Acceso solo para personal autorizado\n\n" +
		"Nombre del host: \\n\n" +
		"Fecha: \\d\n" +
		"Hora: \\t\n" +
		"Dirección IP: \\4\n" +
		"\n"
	if got != want {
		t.Errorf("contenido:\n%q\nesperado:\n%q", got, want)
	}
}

func TestBuildIssueAllOptionsAndOrder(t *testing.T) {
	got, err := BuildIssue(IssueOptions{Host: true, Date: true, Time: true, IP: true, OS: true, Kernel: true, Arch: true, TTY: true, Users: true})
	if err != nil {
		t.Fatal(err)
	}
	var seq []string
	for _, m := range regexp.MustCompile(`\\(?:S\{PRETTY_NAME\}|[ndt4rmlu])`).FindAllString(got, -1) {
		seq = append(seq, m)
	}
	want := []string{`\n`, `\d`, `\t`, `\4`, `\S{PRETTY_NAME}`, `\r`, `\m`, `\l`, `\u`}
	if strings.Join(seq, " ") != strings.Join(want, " ") {
		t.Errorf("secuencias = %v, esperadas %v", seq, want)
	}
	if !strings.HasSuffix(got, "\n\n") {
		t.Error("debe terminar con una línea en blanco")
	}
}

func TestBuildIssueOnlyMessage(t *testing.T) {
	got, err := BuildIssue(IssueOptions{Message: "  Hola  "})
	if err != nil || got != "Hola\n\n" {
		t.Errorf("got %q, %v", got, err)
	}
}

func TestBuildIssueEscapesBackslashes(t *testing.T) {
	// Si el usuario escribe "\n" debe verse "\n", no el nombre del host.
	got, err := BuildIssue(IssueOptions{Message: `Ruta C:\nuevo \4 y \\`})
	if err != nil {
		t.Fatal(err)
	}
	if want := `Ruta C:\\nuevo \\4 y \\\\` + "\n\n"; got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestBuildIssueAcceptsAccentsAndRejectsBadInput(t *testing.T) {
	if _, err := BuildIssue(IssueOptions{Message: "Bienvenido: acción, ñandú y señal ✓"}); err != nil {
		t.Errorf("tildes y ñ deben aceptarse: %v", err)
	}
	cases := map[string]IssueOptions{
		"nada seleccionado":           {},
		"solo espacios":               {Message: "   "},
		"salto de línea":              {Host: true, Message: "a\nb"},
		"ESC (control)":               {Host: true, Message: "a\x1b[31mrojo"},
		"retorno de carro":            {Host: true, Message: "a\rb"},
		"tabulador":                   {Host: true, Message: "a\tb"},
		"cambio de dirección":         {Host: true, Message: "a\u202eb"},
		"separador de línea":          {Host: true, Message: "a\u2028b"},
		"UTF-8 inválido":              {Host: true, Message: "a\xffb"},
		"demasiado largo":             {Host: true, Message: strings.Repeat("a", maxIssueMessage+1)},
		"nulo":                        {Host: true, Message: "a\x00b"},
		"DEL":                         {Host: true, Message: "a\x7fb"},
		"control C1 (U+0085)":         {Host: true, Message: "a\u0085b"},
		"largo en runas, no en bytes": {Host: true, Message: strings.Repeat("ñ", maxIssueMessage+1)},
	}
	for name, o := range cases {
		if _, err := BuildIssue(o); err == nil {
			t.Errorf("%s: debía rechazarse", name)
		}
	}
	if _, err := BuildIssue(IssueOptions{Host: true, Message: strings.Repeat("ñ", maxIssueMessage)}); err != nil {
		t.Errorf("200 caracteres exactos deben aceptarse: %v", err)
	}
}

func decodeB64FromScript(t *testing.T, script string) string {
	t.Helper()
	m := regexp.MustCompile(`printf '%s' '([A-Za-z0-9+/=]*)' \| base64 -d`).FindStringSubmatch(script)
	if m == nil {
		t.Fatalf("no se encontró el contenido en base64 en el script:\n%s", script)
	}
	b, err := base64.StdEncoding.DecodeString(m[1])
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestApplyIssueSendsGeneratedContent(t *testing.T) {
	f := &fakeRunner{res: runner.Result{Stdout: "--- verificación ---\nx\n" + previewMarker + "\nBienvenido\nNombre del host: debian\n"}}
	svc := newSvc(t, f)
	o := DefaultIssueOptions()
	o.Message = `Hola \n mundo`

	out := svc.ApplyIssue(context.Background(), o)
	if !out.OK || len(f.scripts) != 1 {
		t.Fatalf("%+v scripts=%d", out, len(f.scripts))
	}
	want, _ := BuildIssue(o)
	if got := decodeB64FromScript(t, f.scripts[0]); got != want {
		t.Errorf("el script escribe:\n%q\nesperado:\n%q", got, want)
	}
	if strings.Contains(f.scripts[0], "{{") || !strings.Contains(f.scripts[0], "ISSUE=/etc/issue") {
		t.Errorf("script mal armado:\n%s", f.scripts[0])
	}
	if out.Preview != "Bienvenido\nNombre del host: debian" {
		t.Errorf("Preview = %q", out.Preview)
	}
	if !strings.Contains(out.Message, "/etc/issue.consola.bak") {
		t.Errorf("el mensaje debe indicar dónde queda el original: %q", out.Message)
	}
}

func TestApplyIssueRejectsInvalidInputWithoutTouchingVM(t *testing.T) {
	f := &fakeRunner{}
	svc := newSvc(t, f)
	for _, o := range []IssueOptions{{}, {Host: true, Message: "a\x1b"}, {Message: strings.Repeat("x", 500)}} {
		if out := svc.ApplyIssue(context.Background(), o); out.OK || out.Title != "Datos no válidos" {
			t.Errorf("%+v → %+v", o, out)
		}
	}
	if len(f.scripts) != 0 {
		t.Fatal("no debía ejecutarse nada")
	}
}

func TestApplyIssueFailureAndTransportErrors(t *testing.T) {
	f := &fakeRunner{res: runner.Result{ExitCode: 1, Stderr: "install: cannot create regular file '/etc/issue': Read-only file system"}}
	svc := newSvc(t, f)
	out := svc.ApplyIssue(context.Background(), DefaultIssueOptions())
	if out.OK || !strings.Contains(out.Message, "solo lectura") || !strings.Contains(out.Detail, "Read-only") {
		t.Errorf("%+v", out)
	}

	f.res, f.err = runner.Result{}, errors.New("no se pudo conectar a 192.168.1.37:22")
	out = svc.ApplyIssue(context.Background(), DefaultIssueOptions())
	if out.OK || !strings.Contains(out.Title, "No se pudo ejecutar") {
		t.Errorf("%+v", out)
	}
}

func TestPreviewOf(t *testing.T) {
	if previewOf("sin marcador") != "" {
		t.Error("sin marcador no hay vista previa")
	}
	if previewOf("x\n"+previewMarker+"\n(vista previa no disponible: no se encontró agetty o script)\n") != "" {
		t.Error("el aviso de no disponible no es una vista previa")
	}
}

// --- Pruebas del script real con bash ---

func runIssueScript(t *testing.T, path, content string) (stdout, stderr string, code int) {
	t.Helper()
	var out, errb bytes.Buffer
	cmd := exec.Command("bash", "-c", renderIssueScript(path, content))
	cmd.Stdout, cmd.Stderr = &out, &errb
	if err := cmd.Run(); err != nil {
		ee, ok := err.(*exec.ExitError)
		if !ok {
			t.Fatalf("no se pudo ejecutar bash: %v", err)
		}
		code = ee.ExitCode()
	}
	return out.String(), errb.String(), code
}

func TestIssueScriptWritesBacksUpOnceAndPreviews(t *testing.T) {
	sshtest.RequireBash(t)
	path := filepath.Join(t.TempDir(), "issue")
	original := "Debian GNU/Linux 13 \\n \\l\n\n"
	if err := os.WriteFile(path, []byte(original), 0o644); err != nil {
		t.Fatal(err)
	}

	o := DefaultIssueOptions()
	o.Message = `Equipo C:\nuevo`
	content, _ := BuildIssue(o)
	stdout, stderr, code := runIssueScript(t, path, content)
	if code != 0 {
		t.Fatalf("código %d\nstdout:\n%s\nstderr:\n%s", code, stdout, stderr)
	}

	got, _ := os.ReadFile(path)
	if string(got) != content {
		t.Errorf("/etc/issue =\n%q\nesperado\n%q", got, content)
	}
	if st, _ := os.Stat(path); st.Mode().Perm() != 0o644 {
		t.Errorf("permisos = %v, esperado 0644", st.Mode().Perm())
	}
	bak, _ := os.ReadFile(path + issueBackupExt)
	if string(bak) != original {
		t.Errorf("el respaldo debe ser el original, es %q", bak)
	}
	if !strings.Contains(stdout, "--- estado previo ---") || !strings.Contains(stdout, "Debian GNU/Linux 13") ||
		!strings.Contains(stdout, "--- verificación ---") {
		t.Errorf("salida sin estado previo/verificación:\n%s", stdout)
	}

	// Segunda aplicación: el respaldo sigue siendo el original, no la versión anterior de la consola.
	if _, _, code := runIssueScript(t, path, "Otro contenido\n\n"); code != 0 {
		t.Fatal("segunda ejecución falló")
	}
	if bak2, _ := os.ReadFile(path + issueBackupExt); string(bak2) != original {
		t.Errorf("el respaldo no debe sobrescribirse: %q", bak2)
	}

	// Si hay agetty y script (Debian los trae), la vista previa es la REAL: valida el escape.
	_, errA := exec.LookPath("agetty")
	_, errS := exec.LookPath("script")
	if errA == nil && errS == nil {
		if _, _, code := runIssueScript(t, path, content); code != 0 {
			t.Fatal("tercera ejecución falló")
		}
		stdout, _, _ := runIssueScript(t, path, content)
		p := previewOf(stdout)
		if !strings.Contains(p, `Equipo C:\nuevo`) {
			t.Errorf("la barra invertida del mensaje debe verse literal, vista previa:\n%s", p)
		}
		if strings.Contains(p, `\4`) || strings.Contains(p, `\d`) || strings.Contains(p, `\t`) {
			t.Errorf("las secuencias deben haberse reemplazado por datos reales:\n%s", p)
		}
		if !regexp.MustCompile(`Hora: \d\d:\d\d:\d\d`).MatchString(p) || !regexp.MustCompile(`Nombre del host: \S+`).MatchString(p) {
			t.Errorf("la vista previa debe mostrar hora y host reales:\n%s", p)
		}
	}
}

func TestIssueScriptFailsClearlyWhenTargetCannotBeWritten(t *testing.T) {
	sshtest.RequireBash(t)
	path := filepath.Join(t.TempDir(), "no-existe", "issue") // el directorio no existe
	_, stderr, code := runIssueScript(t, path, "x\n\n")
	if code == 0 || stderr == "" {
		t.Errorf("debía fallar con un error legible: código %d, stderr %q", code, stderr)
	}
}
