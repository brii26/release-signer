package main

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

type artifactSpec struct {
	Name string
	Size int64
}

var standardArtifacts = []artifactSpec{
	{"small.bin", 1024},
	{"medium.bin", 1024 * 1024},
	{"large.bin", 100 * 1024 * 1024},
}

// Every file is the prefix of the same stream: byte at offset i is i mod 256.
// This is deterministic across platforms, Go versions and all three profiles.
func writeArtifact(w io.Writer, size int64) error {
	if size < 0 {
		return fmt.Errorf("negative artifact size")
	}
	block := make([]byte, 64*1024)
	for i := range block {
		block[i] = byte(i)
	}
	for size > 0 {
		n := min(size, int64(len(block)))
		if _, err := io.Copy(w, bytes.NewReader(block[:n])); err != nil {
			return err
		}
		size -= n
	}
	return nil
}

func generateArtifacts(dir string, specs []artifactSpec) error {
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}
	for _, spec := range specs {
		f, err := os.CreateTemp(dir, ".artifact-*.tmp")
		if err != nil {
			return err
		}
		err = writeArtifact(f, spec.Size)
		closeErr := f.Close()
		if err == nil {
			err = closeErr
		}
		if err == nil {
			err = os.Rename(f.Name(), filepath.Join(dir, spec.Name))
		}
		os.Remove(f.Name())
		if err != nil {
			return err
		}
	}
	return nil
}

func loadArtifact(dir string, spec artifactSpec) ([]byte, string, error) {
	data, err := os.ReadFile(filepath.Join(dir, spec.Name))
	if err != nil {
		return nil, "", err
	}
	if int64(len(data)) != spec.Size {
		return nil, "", fmt.Errorf("%s: expected %d bytes, got %d; run sh bench/gen.sh", spec.Name, spec.Size, len(data))
	}
	for i, b := range data {
		if b != byte(i) {
			return nil, "", fmt.Errorf("%s: unexpected byte at %d; run sh bench/gen.sh", spec.Name, i)
		}
	}
	sum := sha256.Sum256(data)
	return data, fmt.Sprintf("%x", sum), nil
}
