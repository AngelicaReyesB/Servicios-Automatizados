package runner

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"
)

// SSH ejecuta comandos y transfiere archivos por SSH, solo con llave privada.
type SSH struct {
	Host           string
	Port           int
	User           string
	KeyPath        string
	KnownHostsPath string
	DialTimeout    time.Duration
}

func (s *SSH) Name() string { return ChannelSSH }

func (s *SSH) dial(ctx context.Context) (*ssh.Client, error) {
	keyBytes, err := os.ReadFile(s.KeyPath)
	if err != nil {
		return nil, fmt.Errorf("no se pudo leer la llave privada %s: %w", s.KeyPath, err)
	}
	signer, err := ssh.ParsePrivateKey(keyBytes)
	if err != nil {
		return nil, fmt.Errorf("llave privada inválida: %w", err)
	}
	return s.connect(ctx, []ssh.AuthMethod{ssh.PublicKeys(signer)}) // sin contraseñas
}

// connect abre la conexión TCP y hace el handshake con los métodos dados.
func (s *SSH) connect(ctx context.Context, auth []ssh.AuthMethod) (*ssh.Client, error) {
	timeout := s.DialTimeout
	if timeout == 0 {
		timeout = 15 * time.Second
	}
	cfg := &ssh.ClientConfig{
		User:            s.User,
		Auth:            auth,
		HostKeyCallback: trustOnFirstUse(s.KnownHostsPath),
	}
	addr := net.JoinHostPort(s.Host, strconv.Itoa(s.Port))
	d := net.Dialer{Timeout: timeout}
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("no se pudo conectar a %s: %w", addr, err)
	}
	_ = conn.SetDeadline(time.Now().Add(timeout))
	c, chans, reqs, err := ssh.NewClientConn(conn, addr, cfg)
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("falló el handshake SSH con %s: %w", addr, err)
	}
	_ = conn.SetDeadline(time.Time{})
	return ssh.NewClient(c, chans, reqs), nil
}

var _ KeyProber = (*SSH)(nil)

// PasswordLoginAccepted intenta entrar con usuario y contraseña (y con
// keyboard-interactive). Devuelve true si el servidor LO PERMITE, que es lo que
// no debe ocurrir una vez configurada la llave. Un error solo indica que no se
// pudo comprobar (red, huella cambiada...), no que la contraseña sea válida.
func (s *SSH) PasswordLoginAccepted(ctx context.Context, password string) (bool, error) {
	client, err := s.connect(ctx, []ssh.AuthMethod{
		ssh.Password(password),
		ssh.KeyboardInteractive(func(_, _ string, questions []string, _ []bool) ([]string, error) {
			answers := make([]string, len(questions))
			for i := range answers {
				answers[i] = password
			}
			return answers, nil
		}),
	})
	if err == nil {
		client.Close()
		return true, nil
	}
	if strings.Contains(err.Error(), "unable to authenticate") {
		return false, nil // el servidor rechazó la contraseña: es lo esperado
	}
	return false, err
}

func (s *SSH) Run(ctx context.Context, script string) (Result, error) {
	return s.run(ctx, script, "")
}

func (s *SSH) RunInput(ctx context.Context, script, stdin string) (Result, error) {
	return s.run(ctx, script, stdin)
}

func (s *SSH) run(ctx context.Context, script, stdin string) (Result, error) {
	start := time.Now()
	client, err := s.dial(ctx)
	if err != nil {
		return Result{Channel: s.Name()}, err
	}
	defer client.Close()
	sess, err := client.NewSession()
	if err != nil {
		return Result{Channel: s.Name()}, fmt.Errorf("no se pudo abrir la sesión SSH: %w", err)
	}
	defer sess.Close()

	var out, errb bytes.Buffer
	sess.Stdout, sess.Stderr = &out, &errb
	if stdin != "" {
		sess.Stdin = strings.NewReader(stdin)
	}
	done := make(chan error, 1)
	go func() { done <- sess.Run("bash -c " + shellQuote(script)) }()

	select {
	case <-ctx.Done():
		client.Close() // hace que sess.Run termine
		return Result{Channel: s.Name(), Duration: time.Since(start)}, fmt.Errorf("operación cancelada o con tiempo agotado: %w", ctx.Err())
	case err = <-done:
	}

	res := Result{Stdout: out.String(), Stderr: errb.String(), Channel: s.Name(), Duration: time.Since(start)}
	if err == nil {
		return res, nil
	}
	var ee *ssh.ExitError
	if errors.As(err, &ee) {
		res.ExitCode = ee.ExitStatus()
		return res, nil
	}
	return res, fmt.Errorf("falló la ejecución remota: %w", err)
}

func (s *SSH) Upload(ctx context.Context, local, remote string, mode os.FileMode) error {
	src, err := os.Open(local)
	if err != nil {
		return fmt.Errorf("no se puede leer el archivo local: %w", err)
	}
	defer src.Close()

	client, err := s.dial(ctx)
	if err != nil {
		return err
	}
	defer client.Close()
	sc, err := sftp.NewClient(client)
	if err != nil {
		return fmt.Errorf("no se pudo iniciar SFTP: %w", err)
	}
	defer sc.Close()

	// Se sube a un temporal y se renombra: permite reemplazar un binario en uso.
	tmp := remote + ".consola-tmp"
	dst, err := sc.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC)
	if err != nil {
		return fmt.Errorf("no se pudo crear %s en la VM (¿existe el directorio?): %w", tmp, err)
	}
	if _, err := io.Copy(dst, src); err != nil {
		dst.Close()
		return fmt.Errorf("falló la transferencia: %w", err)
	}
	if err := dst.Close(); err != nil {
		return err
	}
	if err := sc.Chmod(tmp, mode.Perm()); err != nil {
		return fmt.Errorf("no se pudieron asignar permisos: %w", err)
	}
	if err := sc.PosixRename(tmp, remote); err != nil {
		return fmt.Errorf("no se pudo colocar el archivo en %s: %w", remote, err)
	}
	return nil
}

// trustOnFirstUse guarda la huella del servidor la primera vez y, desde
// entonces, rechaza conexiones si cambia (protección básica contra MITM).
func trustOnFirstUse(path string) ssh.HostKeyCallback {
	return func(hostname string, remote net.Addr, key ssh.PublicKey) error {
		line := key.Type() + " " + base64.StdEncoding.EncodeToString(key.Marshal())
		b, err := os.ReadFile(path)
		switch {
		case errors.Is(err, fs.ErrNotExist):
			if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
				return err
			}
			return os.WriteFile(path, []byte(line+"\n"), 0o600)
		case err != nil:
			return err
		}
		if strings.TrimSpace(string(b)) != line {
			return fmt.Errorf("la huella del servidor SSH cambió (ahora %s); si reinstaló la VM, borre %s", ssh.FingerprintSHA256(key), path)
		}
		return nil
	}
}
