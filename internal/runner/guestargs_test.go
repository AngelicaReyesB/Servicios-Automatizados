package runner

import (
	"strings"
	"testing"
)

func TestRunArgsWorkWithEitherArgvConvention(t *testing.T) {
	args := runArgs("debian", "root", "/tmp/pw", "echo hola\nexit 3\n")

	sep := -1
	for i, a := range args {
		if a == "--" {
			sep = i
		}
	}
	if sep < 0 {
		t.Fatalf("falta el separador --: %v", args)
	}
	after := args[sep+1:]
	// A: argv0=env, args=[bash -c X]. B: argv0=--exe (env), args=[env bash -c X].
	// Ambas deben terminar ejecutando "bash -c X"; nunca "bash bash".
	if len(after) != 4 || after[0] != "env" || after[1] != "bash" || after[2] != "-c" {
		t.Errorf("argumentos después de -- inesperados: %v", after)
	}
	if !contains(args, "/usr/bin/env") {
		t.Errorf("--exe debe ser /usr/bin/env: %v", args)
	}
	if contains(args, "--password") {
		t.Error("la contraseña no debe ir en la línea de comandos")
	}
	if !contains(args, "--passwordfile") {
		t.Error("debe usar --passwordfile")
	}
	if strings.ContainsAny(after[3], "\n\"") {
		t.Error("el script envuelto no debe tener saltos de línea ni comillas dobles")
	}
}

func contains(s []string, v string) bool {
	for _, x := range s {
		if x == v {
			return true
		}
	}
	return false
}
