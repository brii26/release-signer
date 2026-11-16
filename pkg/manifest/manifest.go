package manifest

import (
	"bytes"
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"github.com/brii26/release-signer/pkg/strictjson"
)

// Schema dan MaxSize (byte) dari manifest.
const (
	Schema  = "minisign-manifest/v1"
	MaxSize = 16 * 1024
)

// ErrFormat membungkus semua error validasi atau parsing manifest.
var ErrFormat = errors.New("manifest format error")

var (
	rePackage = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,63}$`)
	reVersion = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._+-]{0,63}$`)
	reName    = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)
	reHex64   = regexp.MustCompile(`^[0-9a-f]{64}$`)
)

// Artifact: basename file rilis, ukuran byte, dan SHA-256 hex lowercase.
type Artifact struct {
	Name   string
	Size   int64
	SHA256 string
}

// Manifest rilis (Tabel 2.3), Canonical kasih byte persis yang di-sign.
type Manifest struct {
	Schema    string
	Package   string
	Version   string
	Algorithm string
	KeyID     string
	Artifact  Artifact
}

// New bikin Manifest dan validasi semua field (Tabel 2.3).
func New(pkg, version, algorithm, keyID, name string, size int64, sha256hex string) (Manifest, error) {
	m := Manifest{
		Schema:    Schema,
		Package:   pkg,
		Version:   version,
		Algorithm: algorithm,
		KeyID:     keyID,
		Artifact:  Artifact{Name: name, Size: size, SHA256: sha256hex},
	}
	if err := m.Validate(); err != nil {
		return Manifest{}, err
	}
	return m, nil
}

// Algorithm dicocokkan ke profile di verify, bukan di sini.
func (m Manifest) Validate() error {
	switch {
	case m.Schema != Schema:
		return formatErr("schema must be %q", Schema)
	case !rePackage.MatchString(m.Package):
		return formatErr("invalid package name")
	case !reVersion.MatchString(m.Version):
		return formatErr("invalid version")
	case !printableASCII(m.Algorithm):
		return formatErr("algorithm must be printable ascii without quote or backslash")
	case !reHex64.MatchString(m.KeyID):
		return formatErr("keyid must be 64 lowercase hex characters")
	case !reName.MatchString(m.Artifact.Name):
		return formatErr("invalid artifact name")
	case m.Artifact.Size < 0 || m.Artifact.Size > strictjson.MaxSafeInt:
		return formatErr("artifact size out of range")
	case !reHex64.MatchString(m.Artifact.SHA256):
		return formatErr("artifact sha256 must be 64 lowercase hex characters")
	}
	return nil
}

// Canonical mengasumsikan manifest sudah lolos Validate.
func (m Manifest) Canonical() []byte {
	var b strings.Builder
	for _, s := range []string{
		`{"schema":"`, m.Schema,
		`","package":"`, m.Package,
		`","version":"`, m.Version,
		`","algorithm":"`, m.Algorithm,
		`","keyid":"`, m.KeyID,
		`","artifact":{"name":"`, m.Artifact.Name,
		`","size":`, strconv.FormatInt(m.Artifact.Size, 10),
		`,"sha256":"`, m.Artifact.SHA256,
		`"}}`,
	} {
		b.WriteString(s)
	}
	return []byte(b.String())
}

// ParseStrict parse raw jadi manifest, harus sama persis dengan bentuk canonical.
func ParseStrict(raw []byte) (Manifest, error) {
	if len(raw) > MaxSize {
		return Manifest{}, formatErr("manifest exceeds %d bytes", MaxSize)
	}
	root, err := strictjson.Parse(raw, MaxSize)
	if err != nil {
		return Manifest{}, formatErr("%v", err)
	}
	if err := strictjson.ExpectKeys(root, "schema", "package", "version", "algorithm", "keyid", "artifact"); err != nil {
		return Manifest{}, formatErr("%v", err)
	}
	art, _ := root.Field("artifact")
	if err := strictjson.ExpectKeys(art, "name", "size", "sha256"); err != nil {
		return Manifest{}, formatErr("artifact: %v", err)
	}

	var m Manifest
	strs := []struct {
		obj  strictjson.Value
		key  string
		into *string
	}{
		{root, "schema", &m.Schema},
		{root, "package", &m.Package},
		{root, "version", &m.Version},
		{root, "algorithm", &m.Algorithm},
		{root, "keyid", &m.KeyID},
		{art, "name", &m.Artifact.Name},
		{art, "sha256", &m.Artifact.SHA256},
	}
	for _, f := range strs {
		v, _ := f.obj.Field(f.key)
		s, err := strictjson.AsString(v)
		if err != nil {
			return Manifest{}, formatErr("%s: %v", f.key, err)
		}
		*f.into = s
	}
	sizeVal, _ := art.Field("size")
	if m.Artifact.Size, err = strictjson.AsSafeInt(sizeVal); err != nil {
		return Manifest{}, formatErr("size: %v", err)
	}

	if err := m.Validate(); err != nil {
		return Manifest{}, err
	}
	if !bytes.Equal(m.Canonical(), raw) {
		return Manifest{}, formatErr("serialization is not canonical")
	}
	return m, nil
}

func printableASCII(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < 0x20 || s[i] > 0x7e || s[i] == '"' || s[i] == '\\' {
			return false
		}
	}
	return true
}

func formatErr(format string, args ...any) error {
	return fmt.Errorf("%w: %s", ErrFormat, fmt.Sprintf(format, args...))
}
