// Package bundle menyimpan byte manifest dan signature dalam JSON Base64.
package bundle

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/brii26/release-signer/pkg/b64"
	"github.com/brii26/release-signer/pkg/strictjson"
)

const (
	Schema  = "minisign-bundle/v1"
	MaxSize = 64 * 1024
)

var ErrFormat = errors.New("bundle format error")

func Build(manifestBytes, sig []byte) []byte {
	wire := struct {
		Schema       string `json:"schema"`
		ManifestB64  string `json:"manifest_b64"`
		SignatureB64 string `json:"signature_b64"`
	}{Schema, b64.Encode(manifestBytes), b64.Encode(sig)}
	data, _ := json.MarshalIndent(wire, "", "  ")
	return append(data, '\n')
}

// Isi manifest dan panjang signature diperiksa caller, bukan di sini.
func ParseStrict(data []byte) (manifestBytes, sig []byte, err error) {
	root, err := strictjson.Parse(data, MaxSize)
	if err != nil {
		return nil, nil, formatErr("%v", err)
	}
	if err := strictjson.ExpectKeys(root, "schema", "manifest_b64", "signature_b64"); err != nil {
		return nil, nil, formatErr("%v", err)
	}

	var schema, manifestB64, signatureB64 string
	fields := []struct {
		key  string
		into *string
	}{
		{"schema", &schema},
		{"manifest_b64", &manifestB64},
		{"signature_b64", &signatureB64},
	}
	for _, field := range fields {
		value, _ := root.Field(field.key)
		s, err := strictjson.AsString(value)
		if err != nil {
			return nil, nil, formatErr("%s: %v", field.key, err)
		}
		*field.into = s
	}
	if schema != Schema {
		return nil, nil, formatErr("schema must be %q", Schema)
	}

	manifestBytes, err = b64.DecodeStrict(manifestB64)
	if err != nil {
		return nil, nil, formatErr("manifest_b64: %v", err)
	}
	sig, err = b64.DecodeStrict(signatureB64)
	if err != nil {
		return nil, nil, formatErr("signature_b64: %v", err)
	}
	return manifestBytes, sig, nil
}

// force=false menolak tujuan yang sudah ada, termasuk symlink.
func WriteFile(path string, data []byte, force bool) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), ".bundle-*.tmp")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	defer tmp.Close()

	if _, err := tmp.Write(data); err != nil {
		return err
	}
	if err := tmp.Sync(); err != nil {
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}

	if force {
		return os.Rename(tmp.Name(), path)
	}
	return os.Link(tmp.Name(), path)
}

func formatErr(format string, args ...any) error {
	return fmt.Errorf("%w: %s", ErrFormat, fmt.Sprintf(format, args...))
}
