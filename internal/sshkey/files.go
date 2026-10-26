package sshkey

import (
	"os"
	"path/filepath"
)

// WritePair guarda la privada (0600) y la pública (0644) junto a ella.
func WritePair(path string, p Pair) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	if err := os.WriteFile(path, p.PrivatePEM, 0o600); err != nil {
		return err
	}
	return os.WriteFile(path+".pub", []byte(p.Authorized+"\n"), 0o644)
}

// RemovePair borra la privada y la pública.
func RemovePair(path string) {
	_ = os.Remove(path)
	_ = os.Remove(path + ".pub")
}

// CommitPair reemplaza el par definitivo por el recién verificado.
func CommitPair(from, to string) error {
	if err := os.Rename(from, to); err != nil {
		return err
	}
	return os.Rename(from+".pub", to+".pub")
}
