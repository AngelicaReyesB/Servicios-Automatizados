package servicios

// Normaliza los «archivos adicionales» que sube el usuario (.zip, .tar.gz,
// .tgz) a un único .tar.gz creado por esta consola. Así la VM solo extrae un
// archivo que ya pasó por las validaciones: sin rutas absolutas, sin «..», sin
// enlaces ni dispositivos, y con límites de tamaño y de cantidad.

import (
	"archive/tar"
	"archive/zip"
	"compress/gzip"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"strings"
)

const (
	maxExtraFiles = 5000
	maxExtraBytes = 500 << 20 // tamaño descomprimido
)

type entry struct {
	name string
	dir  bool
	exec bool
	size int64
	open func() (io.ReadCloser, error)
}

// PackExtras lee el archivo `src` (nombre original `filename`) y escribe en
// `dst` un .tar.gz con su contenido normalizado.
func PackExtras(src, filename, dst string) error {
	lower := strings.ToLower(filename)
	var entries []entry
	var closer func()
	var err error
	switch {
	case strings.HasSuffix(lower, ".zip"):
		entries, closer, err = readZip(src)
	case strings.HasSuffix(lower, ".tar.gz"), strings.HasSuffix(lower, ".tgz"):
		entries, closer, err = readTarGz(src)
	default:
		return errors.New("los archivos adicionales deben subirse como .zip, .tar.gz o .tgz")
	}
	if closer != nil {
		defer closer()
	}
	if err != nil {
		return err
	}
	if len(entries) == 0 {
		return errors.New("el archivo comprimido está vacío")
	}
	return writeTarGz(entries, dst)
}

func cleanName(n string) (string, error) {
	n = strings.ReplaceAll(n, `\`, "/")
	if strings.HasPrefix(n, "/") || strings.Contains(n, "\x00") {
		return "", fmt.Errorf("ruta no permitida en el archivo comprimido: %q", n)
	}
	c := path.Clean(n)
	if c == "." {
		return "", nil
	}
	if c == ".." || strings.HasPrefix(c, "../") || strings.Contains(c, "/../") {
		return "", fmt.Errorf("ruta no permitida en el archivo comprimido: %q", n)
	}
	return c, nil
}

func readZip(src string) ([]entry, func(), error) {
	zr, err := zip.OpenReader(src)
	if err != nil {
		return nil, nil, fmt.Errorf("no se pudo leer el .zip: %w", err)
	}
	var out []entry
	var total int64
	for _, f := range zr.File {
		name, err := cleanName(f.Name)
		if err != nil {
			return nil, func() { zr.Close() }, err
		}
		if name == "" {
			continue
		}
		mode := f.Mode()
		switch {
		case mode.IsDir():
			out = append(out, entry{name: name, dir: true})
		case mode.IsRegular():
			total += int64(f.UncompressedSize64)
			f := f
			out = append(out, entry{name: name, exec: mode&0o111 != 0, size: int64(f.UncompressedSize64), open: f.Open})
		default:
			return nil, func() { zr.Close() }, fmt.Errorf("el archivo comprimido contiene un elemento no permitido (enlace o archivo especial): %q", name)
		}
		if len(out) > maxExtraFiles || total > maxExtraBytes {
			return nil, func() { zr.Close() }, errors.New("el archivo comprimido es demasiado grande (máximo 5000 archivos y 500 MB descomprimido)")
		}
	}
	return out, func() { zr.Close() }, nil
}

func readTarGz(src string) ([]entry, func(), error) {
	// Se vuelca el contenido a memoria acotada por archivo no es viable: se
	// recorre dos veces (validar y luego copiar), así que se reabre en open().
	f, err := os.Open(src)
	if err != nil {
		return nil, nil, err
	}
	defer f.Close()
	gz, err := gzip.NewReader(f)
	if err != nil {
		return nil, nil, fmt.Errorf("no se pudo leer el .tar.gz: %w", err)
	}
	tr := tar.NewReader(gz)
	var out []entry
	var total int64
	for {
		h, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, nil, fmt.Errorf("el .tar.gz está dañado: %w", err)
		}
		name, err := cleanName(h.Name)
		if err != nil {
			return nil, nil, err
		}
		if name == "" {
			continue
		}
		switch h.Typeflag {
		case tar.TypeDir:
			out = append(out, entry{name: name, dir: true})
		case tar.TypeReg:
			total += h.Size
			target := name
			out = append(out, entry{name: name, exec: h.FileInfo().Mode()&0o111 != 0, size: h.Size, open: func() (io.ReadCloser, error) { return openTarMember(src, target) }})
		case tar.TypeXGlobalHeader, tar.TypeXHeader:
		default:
			return nil, nil, fmt.Errorf("el archivo comprimido contiene un elemento no permitido (enlace o archivo especial): %q", name)
		}
		if len(out) > maxExtraFiles || total > maxExtraBytes {
			return nil, nil, errors.New("el archivo comprimido es demasiado grande (máximo 5000 archivos y 500 MB descomprimido)")
		}
	}
	return out, nil, nil
}

type tarMember struct {
	io.Reader
	f *os.File
}

func (m tarMember) Close() error { return m.f.Close() }

func openTarMember(src, name string) (io.ReadCloser, error) {
	f, err := os.Open(src)
	if err != nil {
		return nil, err
	}
	gz, err := gzip.NewReader(f)
	if err != nil {
		f.Close()
		return nil, err
	}
	tr := tar.NewReader(gz)
	for {
		h, err := tr.Next()
		if err != nil {
			f.Close()
			return nil, err
		}
		if n, _ := cleanName(h.Name); n == name && h.Typeflag == tar.TypeReg {
			return tarMember{Reader: tr, f: f}, nil
		}
	}
}

func writeTarGz(entries []entry, dst string) (err error) {
	out, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	defer func() {
		if cerr := out.Close(); err == nil {
			err = cerr
		}
		if err != nil {
			os.Remove(dst)
		}
	}()
	gz := gzip.NewWriter(out)
	tw := tar.NewWriter(gz)
	for _, e := range entries {
		if e.dir {
			if err := tw.WriteHeader(&tar.Header{Name: e.name + "/", Typeflag: tar.TypeDir, Mode: 0o755}); err != nil {
				return err
			}
			continue
		}
		mode := int64(0o644)
		if e.exec {
			mode = 0o755
		}
		if err := tw.WriteHeader(&tar.Header{Name: e.name, Typeflag: tar.TypeReg, Mode: mode, Size: e.size}); err != nil {
			return err
		}
		rc, err := e.open()
		if err != nil {
			return err
		}
		n, err := io.Copy(tw, io.LimitReader(rc, e.size))
		rc.Close()
		if err != nil {
			return err
		}
		if n != e.size {
			return fmt.Errorf("el archivo comprimido está incompleto: %q", e.name)
		}
	}
	if err := tw.Close(); err != nil {
		return err
	}
	return gz.Close()
}
