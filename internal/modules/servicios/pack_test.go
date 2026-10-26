package servicios

import (
	"archive/tar"
	"archive/zip"
	"compress/gzip"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

func makeZip(t *testing.T, files map[string]string, modes map[string]os.FileMode) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "x.zip")
	f, _ := os.Create(p)
	zw := zip.NewWriter(f)
	for name, body := range files {
		h := &zip.FileHeader{Name: name, Method: zip.Deflate}
		if m, ok := modes[name]; ok {
			h.SetMode(m)
		}
		w, _ := zw.CreateHeader(h)
		_, _ = w.Write([]byte(body))
	}
	zw.Close()
	f.Close()
	return p
}

func makeTgz(t *testing.T, hdrs []tar.Header, bodies []string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "x.tar.gz")
	f, _ := os.Create(p)
	gz := gzip.NewWriter(f)
	tw := tar.NewWriter(gz)
	for i, h := range hdrs {
		h := h
		h.Size = int64(len(bodies[i]))
		_ = tw.WriteHeader(&h)
		_, _ = tw.Write([]byte(bodies[i]))
	}
	tw.Close()
	gz.Close()
	f.Close()
	return p
}

func readTgz(t *testing.T, p string) map[string]string {
	t.Helper()
	f, err := os.Open(p)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	gz, _ := gzip.NewReader(f)
	tr := tar.NewReader(gz)
	out := map[string]string{}
	for {
		h, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		b, _ := io.ReadAll(tr)
		out[h.Name] = string(b)
		if h.Typeflag == tar.TypeReg && h.Mode != 0o644 && h.Mode != 0o755 {
			t.Errorf("modo inesperado %o en %s", h.Mode, h.Name)
		}
	}
	return out
}

func TestPackExtrasFromZip(t *testing.T) {
	src := makeZip(t, map[string]string{"templates/index.html": "<h1>hola</h1>", "static/app.js": "x", "run.sh": "#!/bin/sh"},
		map[string]os.FileMode{"run.sh": 0o755})
	dst := filepath.Join(t.TempDir(), "o.tgz")
	if err := PackExtras(src, "extra.ZIP", dst); err != nil {
		t.Fatal(err)
	}
	got := readTgz(t, dst)
	if got["templates/index.html"] != "<h1>hola</h1>" || got["static/app.js"] != "x" || got["run.sh"] != "#!/bin/sh" {
		t.Errorf("contenido: %v", got)
	}
}

func TestPackExtrasFromTarGzKeepsExecBitOnly(t *testing.T) {
	src := makeTgz(t, []tar.Header{
		{Name: "./bin/", Typeflag: tar.TypeDir, Mode: 0o700},
		{Name: "./bin/tool", Typeflag: tar.TypeReg, Mode: 0o777},
		{Name: "datos.txt", Typeflag: tar.TypeReg, Mode: 0o666},
	}, []string{"", "T", "D"})
	dst := filepath.Join(t.TempDir(), "o.tgz")
	if err := PackExtras(src, "e.tgz", dst); err != nil {
		t.Fatal(err)
	}
	got := readTgz(t, dst)
	var names []string
	for n := range got {
		names = append(names, n)
	}
	sort.Strings(names)
	if strings.Join(names, ",") != "bin/,bin/tool,datos.txt" {
		t.Errorf("nombres = %v", names)
	}
}

func TestPackExtrasRejectsDangerousContent(t *testing.T) {
	bad := map[string]string{
		"ruta con ..":              "../../etc/passwd",
		"ruta absoluta":            "/etc/cron.d/x",
		"ruta con .. en medio":     "a/../../b",
		"ruta con barra invertida": `..\..\x`,
	}
	for name, n := range bad {
		z := makeZip(t, map[string]string{n: "x"}, nil)
		dst := filepath.Join(t.TempDir(), "o.tgz")
		if err := PackExtras(z, "e.zip", dst); err == nil {
			t.Errorf("zip %s debía rechazarse", name)
		}
		if _, err := os.Stat(dst); err == nil {
			t.Errorf("zip %s: no debe quedar salida", name)
		}
		tg := makeTgz(t, []tar.Header{{Name: n, Typeflag: tar.TypeReg, Mode: 0o644}}, []string{"x"})
		if err := PackExtras(tg, "e.tar.gz", filepath.Join(t.TempDir(), "o.tgz")); err == nil {
			t.Errorf("tar %s debía rechazarse", name)
		}
	}
	// enlaces y dispositivos
	for _, tf := range []byte{tar.TypeSymlink, tar.TypeLink, tar.TypeChar, tar.TypeFifo} {
		tg := makeTgz(t, []tar.Header{{Name: "x", Typeflag: tf, Linkname: "/etc/passwd", Mode: 0o777}}, []string{""})
		if err := PackExtras(tg, "e.tgz", filepath.Join(t.TempDir(), "o.tgz")); err == nil || !strings.Contains(err.Error(), "no permitido") {
			t.Errorf("tipo %c debía rechazarse: %v", tf, err)
		}
	}
	zl := makeZip(t, map[string]string{"enlace": "/etc/passwd"}, map[string]os.FileMode{"enlace": os.ModeSymlink | 0o777})
	if err := PackExtras(zl, "e.zip", filepath.Join(t.TempDir(), "o.tgz")); err == nil {
		t.Error("el enlace simbólico dentro de un zip debía rechazarse")
	}
}

func TestPackExtrasRejectsWrongFormatsAndEmpty(t *testing.T) {
	dir := t.TempDir()
	rar := filepath.Join(dir, "x.rar")
	_ = os.WriteFile(rar, []byte("Rar!"), 0o644)
	if err := PackExtras(rar, "x.rar", filepath.Join(dir, "o")); err == nil {
		t.Error("formato no soportado")
	}
	notZip := filepath.Join(dir, "n.zip")
	_ = os.WriteFile(notZip, []byte("no soy zip"), 0o644)
	if err := PackExtras(notZip, "n.zip", filepath.Join(dir, "o")); err == nil {
		t.Error("zip dañado")
	}
	notGz := filepath.Join(dir, "n.tgz")
	_ = os.WriteFile(notGz, []byte("no soy gzip"), 0o644)
	if err := PackExtras(notGz, "n.tgz", filepath.Join(dir, "o")); err == nil {
		t.Error("tgz dañado")
	}
	empty := makeZip(t, map[string]string{}, nil)
	if err := PackExtras(empty, "e.zip", filepath.Join(dir, "o")); err == nil {
		t.Error("zip vacío")
	}
}
