package usuarios

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"consola/internal/oplog"
	"consola/internal/runner"
)

type fakeRunner struct {
	scripts   []string
	res       runner.Result
	err       error
	uploads   map[string]string // ruta remota → contenido
	uploadErr error
	modes     map[string]os.FileMode
}

func (f *fakeRunner) Name() string { return "SSH (fake)" }
func (f *fakeRunner) Run(_ context.Context, script string) (runner.Result, error) {
	f.scripts = append(f.scripts, script)
	return f.res, f.err
}
func (f *fakeRunner) RunInput(context.Context, string, string) (runner.Result, error) {
	return runner.Result{}, runner.ErrNotSupported
}
func (f *fakeRunner) Upload(_ context.Context, local, remote string, mode os.FileMode) error {
	if f.uploadErr != nil {
		return f.uploadErr
	}
	b, err := os.ReadFile(local)
	if err != nil {
		return err
	}
	if f.uploads == nil {
		f.uploads, f.modes = map[string]string{}, map[string]os.FileMode{}
	}
	f.uploads[remote], f.modes[remote] = string(b), mode
	return nil
}

type fakeProvider struct{ r runner.Runner }

func (p fakeProvider) Get(string) (runner.Runner, error) { return p.r, nil }

func newSvc(t *testing.T, f *fakeRunner) (*Service, string) {
	t.Helper()
	log, err := oplog.New(filepath.Join(t.TempDir(), "ops.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { log.Close() })
	keyDir := filepath.Join(t.TempDir(), "keys")
	return New(fakeProvider{f}, log, "main", Options{KeyDir: keyDir}), keyDir
}

func pubFromScript(t *testing.T, script string) string {
	t.Helper()
	m := regexp.MustCompile(`(?m)^PUB='([^']*)'$`).FindStringSubmatch(script)
	if m == nil {
		t.Fatalf("no se encontró PUB en el script:\n%s", script)
	}
	return m[1]
}

func TestCreateRejectsInvalidNamesWithoutTouchingVM(t *testing.T) {
	f := &fakeRunner{}
	svc, _ := newSvc(t, f)
	for _, n := range []string{"", "Root", "a b", "x;reboot", "1abc", "a$(id)", strings.Repeat("a", 33), "../x", "ñandu"} {
		if out := svc.CreateUser(context.Background(), CreateOptions{Name: n, Sudo: true, GenKey: true}); out.OK || out.Title != "Datos no válidos" {
			t.Errorf("%q → %+v", n, out)
		}
	}
	if len(f.scripts) != 0 {
		t.Fatal("no debía ejecutarse nada")
	}
}

func TestCreateWithKeyGeneratesInstallsAndStoresKeyOnlyOnSuccess(t *testing.T) {
	f := &fakeRunner{res: runner.Result{Stdout: "--- verificación ---\nuid=1001(ana)\n"}}
	svc, keyDir := newSvc(t, f)
	out := svc.CreateUser(context.Background(), CreateOptions{Name: "ana", Sudo: true, GenKey: true})
	if !out.OK || out.DownloadUser != "ana" {
		t.Fatalf("%+v", out)
	}
	if len(f.scripts) != 1 || strings.Contains(f.scripts[0], "{{") {
		t.Fatalf("script mal armado: %v", f.scripts)
	}
	sc := f.scripts[0]
	if !strings.Contains(sc, "U=ana\n") || !strings.Contains(sc, "WANT_SUDO=1\n") {
		t.Errorf("parámetros del script:\n%s", sc)
	}
	pub := pubFromScript(t, sc)
	if !regexp.MustCompile(`^ssh-ed25519 [A-Za-z0-9+/]+=* consola-user-ana$`).MatchString(pub) {
		t.Errorf("llave pública inesperada: %q", pub)
	}
	// La pública instalada es la del par guardado.
	saved, err := os.ReadFile(filepath.Join(keyDir, "main_user_ana_ed25519.pub"))
	if err != nil || strings.TrimSpace(string(saved)) != pub {
		t.Errorf("par guardado distinto del instalado: %v %q", err, saved)
	}
	if st, _ := os.Stat(filepath.Join(keyDir, "main_user_ana_ed25519")); st == nil || st.Mode().Perm() != 0o600 && os.PathSeparator == '/' {
		t.Error("la privada debe existir con permisos 0600")
	}
	if _, err := os.Stat(filepath.Join(keyDir, "main_user_ana_ed25519.new")); err == nil {
		t.Error("no debe quedar el archivo .new")
	}
	name, data, err := svc.PrivateKeyForDownload("ana")
	if err != nil || name != "id_ed25519_ana" || !strings.Contains(string(data), "OPENSSH PRIVATE KEY") {
		t.Errorf("descarga: %q %v", name, err)
	}
	if ks := svc.Keys(); len(ks) != 1 || ks[0].User != "ana" || !strings.HasPrefix(ks[0].Fingerprint, "SHA256:") {
		t.Errorf("Keys() = %+v", ks)
	}
	if !strings.Contains(out.Message, "SHA256:") || !strings.Contains(out.Message, "sudo") {
		t.Errorf("mensaje: %q", out.Message)
	}
}

func TestCreateWithoutKeyOrSudo(t *testing.T) {
	f := &fakeRunner{}
	svc, keyDir := newSvc(t, f)
	out := svc.CreateUser(context.Background(), CreateOptions{Name: "  bob  "})
	if !out.OK || out.DownloadUser != "" || !strings.Contains(out.Message, "No se generó llave") {
		t.Fatalf("%+v", out)
	}
	sc := f.scripts[0]
	if !strings.Contains(sc, "U=bob\n") || !strings.Contains(sc, "WANT_SUDO=0\n") || pubFromScript(t, sc) != "" {
		t.Errorf("script:\n%s", sc)
	}
	if _, err := os.Stat(keyDir); err == nil {
		t.Error("sin llave no se debe crear nada en la carpeta de llaves")
	}
}

func TestCreateFailureDoesNotKeepKeyAndExplains(t *testing.T) {
	cases := map[int]string{
		exitExists:    "Ya existe",
		exitNoSudo:    "sudo no está instalado",
		exitSSHPolicy: "no permite bloquear la contraseña",
	}
	for code, want := range cases {
		f := &fakeRunner{res: runner.Result{ExitCode: code, Stderr: "detalle técnico X"}}
		svc, keyDir := newSvc(t, f)
		out := svc.CreateUser(context.Background(), CreateOptions{Name: "ana", Sudo: true, GenKey: true})
		if out.OK || !strings.Contains(out.Message, want) || !strings.Contains(out.Detail, "detalle técnico X") {
			t.Errorf("código %d → %+v", code, out)
		}
		if ents, _ := os.ReadDir(keyDir); len(ents) != 0 {
			t.Errorf("código %d: no debe quedar ninguna llave: %v", code, ents)
		}
	}
}

func TestCreateTransportErrorKeepsNoKey(t *testing.T) {
	f := &fakeRunner{err: errors.New("no se pudo conectar")}
	svc, keyDir := newSvc(t, f)
	out := svc.CreateUser(context.Background(), CreateOptions{Name: "ana", GenKey: true})
	if out.OK || !strings.Contains(out.Title, "No se pudo ejecutar") {
		t.Fatalf("%+v", out)
	}
	if ents, _ := os.ReadDir(keyDir); len(ents) != 0 {
		t.Errorf("quedaron llaves: %v", ents)
	}
}

func TestRecreatingUserReplacesKey(t *testing.T) {
	f := &fakeRunner{}
	svc, _ := newSvc(t, f)
	svc.CreateUser(context.Background(), CreateOptions{Name: "ana", GenKey: true})
	first := svc.Keys()[0].Fingerprint
	svc.CreateUser(context.Background(), CreateOptions{Name: "ana", GenKey: true})
	if second := svc.Keys()[0].Fingerprint; second == first {
		t.Error("la llave debía cambiar")
	}
}

func TestDeleteValidationAndProtection(t *testing.T) {
	f := &fakeRunner{}
	svc, _ := newSvc(t, f)
	if out := svc.DeleteUser(context.Background(), "a;b", true); out.Title != "Datos no válidos" {
		t.Errorf("%+v", out)
	}
	if out := svc.DeleteUser(context.Background(), "root", true); out.OK || !strings.Contains(out.Title, "bloqueada") {
		t.Errorf("%+v", out)
	}
	if len(f.scripts) != 0 {
		t.Fatal("no debía ejecutarse nada")
	}
}

func TestDeleteBuildsScriptAndRemovesLocalKey(t *testing.T) {
	f := &fakeRunner{}
	svc, _ := newSvc(t, f)
	svc.CreateUser(context.Background(), CreateOptions{Name: "ana", GenKey: true})
	out := svc.DeleteUser(context.Background(), "ana", true)
	if !out.OK || !strings.Contains(out.Message, "archivos") || !strings.Contains(out.Message, "llave guardada") {
		t.Fatalf("%+v", out)
	}
	sc := f.scripts[len(f.scripts)-1]
	if !strings.Contains(sc, "U=ana\n") || !strings.Contains(sc, "RM_FILES=1\n") || strings.Contains(sc, "{{") {
		t.Errorf("script:\n%s", sc)
	}
	if len(svc.Keys()) != 0 {
		t.Error("la llave local debía borrarse")
	}
	out = svc.DeleteUser(context.Background(), "ana", false)
	if !strings.Contains(f.scripts[len(f.scripts)-1], "RM_FILES=0\n") || !strings.Contains(out.Message, "se conservó") {
		t.Errorf("sin borrar archivos: %+v", out)
	}
}

func TestDeleteFailureMessages(t *testing.T) {
	cases := []struct {
		res  runner.Result
		want string
	}{
		{runner.Result{ExitCode: exitNotFound}, "no existe"},
		{runner.Result{ExitCode: exitProtected}, "cuenta del sistema"},
		{runner.Result{ExitCode: 8, Stderr: "userdel: user ana is currently used by process 123"}, "procesos o una sesión"},
	}
	for _, c := range cases {
		svc, _ := newSvc(t, &fakeRunner{res: c.res})
		out := svc.DeleteUser(context.Background(), "ana", false)
		if out.OK || !strings.Contains(out.Message, c.want) {
			t.Errorf("%+v → %+v", c.res, out)
		}
	}
}

func TestKeysIgnoresForeignFilesAndDownloadWithoutKey(t *testing.T) {
	svc, keyDir := newSvc(t, &fakeRunner{})
	_ = os.MkdirAll(keyDir, 0o700)
	_ = os.WriteFile(filepath.Join(keyDir, "main_root_ed25519.pub"), []byte("x"), 0o644)
	_ = os.WriteFile(filepath.Join(keyDir, "main_user_BAD NAME_ed25519.pub"), []byte("x"), 0o644)
	if ks := svc.Keys(); len(ks) != 0 {
		t.Errorf("Keys() = %+v", ks)
	}
	if _, _, err := svc.PrivateKeyForDownload("ana"); !errors.Is(err, ErrNoKey) {
		t.Errorf("err = %v", err)
	}
	if _, _, err := svc.PrivateKeyForDownload("../../etc/passwd"); err == nil {
		t.Error("un nombre con ruta debe rechazarse")
	}
}

func TestValidatePassword(t *testing.T) {
	for _, ok := range []string{"", "12345678", "con espacios y ñ ✓", strings.Repeat("a", 128)} {
		if err := validatePassword(ok); err != nil {
			t.Errorf("%q debía aceptarse: %v", ok, err)
		}
	}
	for name, bad := range map[string]string{"corta": "1234567", "larga": strings.Repeat("a", 129), "salto": "abcdefgh\nroot:x",
		"retorno": "abcdefgh\r", "nulo": "abcdefgh\x00", "UTF-8 inválido": "abcdefg\xff", "ESC": "abcdefg\x1b"} {
		if validatePassword(bad) == nil {
			t.Errorf("%s: debía rechazarse", name)
		}
	}
}

func TestCreateWithPasswordSendsItInAFileNotInTheScript(t *testing.T) {
	f := &fakeRunner{res: runner.Result{Stdout: "--- verificación ---\nuid=1001(ana)\n"}}
	svc, _ := newSvc(t, f)
	pw := "S3creta larga!"
	out := svc.CreateUser(context.Background(), CreateOptions{Name: "ana", Sudo: true, Password: pw})
	if !out.OK {
		t.Fatalf("%+v", out)
	}
	if len(f.uploads) != 1 || len(f.scripts) != 1 {
		t.Fatalf("uploads=%d scripts=%d", len(f.uploads), len(f.scripts))
	}
	var remote string
	for r, c := range f.uploads {
		remote = r
		if c != "ana:"+pw+"\n" {
			t.Errorf("contenido del archivo = %q", c)
		}
		if f.modes[r] != 0o600 {
			t.Errorf("permisos = %v", f.modes[r])
		}
	}
	if !strings.HasPrefix(remote, "/tmp/.consola-pw-") {
		t.Errorf("ruta remota = %q", remote)
	}
	sc := f.scripts[0]
	if strings.Contains(sc, pw) || !strings.Contains(sc, "PWFILE='"+remote+"'") {
		t.Errorf("la contraseña no debe estar en el script y sí la ruta del archivo:\n%s", sc)
	}
	for _, e := range svc.log.Recent(10) {
		if strings.Contains(e.Script+e.Stdout+e.Stderr+e.Operation+e.Error, pw) {
			t.Errorf("la contraseña se filtró al registro: %+v", e)
		}
	}
	if !strings.Contains(out.Message, "sudo le pide su contraseña") || strings.Contains(out.Message, pw) {
		t.Errorf("mensaje: %q", out.Message)
	}
}

func TestCreateWithoutPasswordUploadsNothing(t *testing.T) {
	f := &fakeRunner{res: runner.Result{Stdout: "--- verificación ---\n"}}
	svc, _ := newSvc(t, f)
	if out := svc.CreateUser(context.Background(), CreateOptions{Name: "bob"}); !out.OK || len(f.uploads) != 0 {
		t.Fatalf("%+v uploads=%v", out, f.uploads)
	}
	if !strings.Contains(f.scripts[0], "PWFILE=''") {
		t.Error("sin contraseña PWFILE debe ir vacío")
	}
}

func TestCreateRejectsShortPasswordWithoutTouchingVM(t *testing.T) {
	f := &fakeRunner{}
	svc, _ := newSvc(t, f)
	out := svc.CreateUser(context.Background(), CreateOptions{Name: "ana", Password: "corta"})
	if out.OK || out.Title != "Datos no válidos" || len(f.scripts) != 0 || len(f.uploads) != 0 {
		t.Fatalf("%+v", out)
	}
}

func TestCreateUploadFailureStopsBeforeCreating(t *testing.T) {
	f := &fakeRunner{uploadErr: errors.New("sin espacio")}
	svc, keyDir := newSvc(t, f)
	out := svc.CreateUser(context.Background(), CreateOptions{Name: "ana", GenKey: true, Password: "12345678"})
	if out.OK || !strings.Contains(out.Title, "contraseña") || len(f.scripts) != 0 {
		t.Fatalf("%+v scripts=%d", out, len(f.scripts))
	}
	if _, err := os.Stat(filepath.Join(keyDir, "main_user_ana_ed25519")); err == nil {
		t.Error("no debe guardarse la llave si el usuario no se creó")
	}
}

func TestDeleteOrphanHomeMessage(t *testing.T) {
	f := &fakeRunner{res: runner.Result{Stdout: "«ana» ya no existe como usuario, pero queda su directorio personal huérfano: /home/ana (UID 1001)\n--- verificación ---\ndirectorio huérfano eliminado: /home/ana\n"}}
	svc, _ := newSvc(t, f)
	out := svc.DeleteUser(context.Background(), "ana", true)
	if !out.OK || !strings.Contains(out.Message, "ya no existía") {
		t.Fatalf("%+v", out)
	}
}

func TestDiagnoseLeftoverHome(t *testing.T) {
	f := &fakeRunner{res: runner.Result{ExitCode: exitHomeLeft}}
	svc, keyDir := newSvc(t, f)
	out := svc.CreateUser(context.Background(), CreateOptions{Name: "ana", GenKey: true})
	if out.OK || !strings.Contains(out.Message, "directorio personal de un usuario anterior") || !strings.Contains(out.Message, "Eliminar también todos sus archivos") {
		t.Fatalf("%+v", out)
	}
	if _, err := os.Stat(filepath.Join(keyDir, "main_user_ana_ed25519")); err == nil {
		t.Error("no debe guardarse llave si no se creó el usuario")
	}
}
