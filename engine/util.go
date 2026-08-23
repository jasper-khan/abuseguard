package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

// logf writes a timestamped line to stderr (captured by journald for the units).
func logf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "[abuseguard] "+format+"\n", args...)
}

// fatalf logs and exits with code 1.
func fatalf(format string, args ...any) {
	logf(format, args...)
	os.Exit(1)
}

// writeFileAtomic writes data to path via a temp file + rename in the same dir.
func writeFileAtomic(path string, data []byte, perm os.FileMode) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".tmp-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Chmod(perm); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpName, path)
}

// saveJSON marshals v (indented) and writes it atomically.
func saveJSON(path string, v any, perm os.FileMode) error {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	return writeFileAtomic(path, b, perm)
}
