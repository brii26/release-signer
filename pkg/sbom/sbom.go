// Package sbom bikin dan baca SBOM CycloneDX 1.6 (JSON) yang terikat ke SHA-256 artifact rilis, di-sign sebagai bundle terpisah (lihat pkg/release).
package sbom

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"

	"github.com/brii26/release-signer/pkg/strictjson"
)

const (
	// MaxSize: batas ukuran SBOM yang diparse atau di-sign.
	MaxSize = 1 << 20 // 1 MiB

	// ArtifactNameProperty: nama property yang simpan basename artifact rilis.
	ArtifactNameProperty = "release-signer:artifact-name"

	bomFormat   = "CycloneDX"
	specVersion = "1.6"
	hashAlg     = "SHA-256"
)

var (
	// ErrFormat dikembalikan kalau SBOM tidak bisa diparse atau binding tidak valid.
	ErrFormat = errors.New("sbom format error")

	sha256Regex = regexp.MustCompile(`^[0-9a-f]{64}$`)
)

// Binding adalah info di SBOM yang mengikatnya ke satu artifact rilis.
type Binding struct {
	Package      string
	Version      string
	ArtifactName string
	ArtifactSHA  string
}

type document struct {
	BomFormat   string      `json:"bomFormat"`
	SpecVersion string      `json:"specVersion"`
	Version     int         `json:"version"`
	Metadata    metadata    `json:"metadata"`
	Components  []component `json:"components"`
}

type metadata struct {
	Component component `json:"component"`
}

type component struct {
	Type       string     `json:"type"`
	Name       string     `json:"name"`
	Version    string     `json:"version"`
	Hashes     []hash     `json:"hashes,omitempty"`
	Properties []property `json:"properties,omitempty"`
}

type hash struct {
	Alg     string `json:"alg"`
	Content string `json:"content"`
}

type property struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

// Generate bikin SBOM minimal untuk artifact, isi artifact hanya dibaca.
func Generate(artifactPath, pkg, version string) ([]byte, error) {
	sum, err := hashFile(artifactPath)
	if err != nil {
		return nil, fmt.Errorf("read artifact: %w", err)
	}
	doc := document{
		BomFormat:   bomFormat,
		SpecVersion: specVersion,
		Version:     1,
		Metadata: metadata{Component: component{
			Type:    "application",
			Name:    pkg,
			Version: version,
			Hashes:  []hash{{Alg: hashAlg, Content: sum}},
			Properties: []property{
				{Name: ArtifactNameProperty, Value: filepath.Base(artifactPath)},
			},
		}},
		Components: []component{},
	}
	out, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(out, '\n'), nil
}

// ParseBinding baca binding SBOM, tolak duplicate field, BOM, UTF-8 invalid, dan trailing data, field lain boleh ada.
func ParseBinding(data []byte) (Binding, error) {
	root, err := strictjson.Parse(data, MaxSize)
	if err != nil {
		return Binding{}, formatErr("%v", err)
	}
	if root.Kind != strictjson.Object {
		return Binding{}, formatErr("root must be an object")
	}

	if err := wantString(root, "bomFormat", bomFormat); err != nil {
		return Binding{}, err
	}

	md, ok := root.Field("metadata")
	if !ok {
		return Binding{}, formatErr("missing metadata")
	}
	comp, ok := md.Field("component")
	if !ok {
		return Binding{}, formatErr("missing metadata.component")
	}

	var b Binding
	if b.Package, err = stringField(comp, "name"); err != nil {
		return Binding{}, err
	}
	if b.Version, err = stringField(comp, "version"); err != nil {
		return Binding{}, err
	}

	hashes, err := arrayField(comp, "hashes")
	if err != nil {
		return Binding{}, err
	}
	found := 0
	for _, h := range hashes {
		alg, err := stringField(h, "alg")
		if err != nil {
			return Binding{}, err
		}
		if alg != hashAlg {
			continue
		}
		content, err := stringField(h, "content")
		if err != nil {
			return Binding{}, err
		}
		if !sha256Regex.MatchString(content) {
			return Binding{}, formatErr("SHA-256 hash must be 64 lowercase hex characters")
		}
		b.ArtifactSHA = content
		found++
	}
	if found != 1 {
		return Binding{}, formatErr("expected exactly one SHA-256 hash in metadata.component.hashes, found %d", found)
	}

	props, err := arrayField(comp, "properties")
	if err != nil {
		return Binding{}, err
	}
	found = 0
	for _, p := range props {
		name, err := stringField(p, "name")
		if err != nil {
			return Binding{}, err
		}
		if name != ArtifactNameProperty {
			continue
		}
		if b.ArtifactName, err = stringField(p, "value"); err != nil {
			return Binding{}, err
		}
		found++
	}
	if found != 1 {
		return Binding{}, formatErr("expected exactly one %q property, found %d", ArtifactNameProperty, found)
	}
	return b, nil
}

func wantString(obj strictjson.Value, key, want string) error {
	got, err := stringField(obj, key)
	if err != nil {
		return err
	}
	if got != want {
		return formatErr("%s must be %q, got %q", key, want, got)
	}
	return nil
}

func stringField(obj strictjson.Value, key string) (string, error) {
	v, ok := obj.Field(key)
	if !ok {
		return "", formatErr("missing %q", key)
	}
	s, err := strictjson.AsString(v)
	if err != nil {
		return "", formatErr("%q: %v", key, err)
	}
	return s, nil
}

func arrayField(obj strictjson.Value, key string) ([]strictjson.Value, error) {
	v, ok := obj.Field(key)
	if !ok {
		return nil, formatErr("missing %q", key)
	}
	arr, err := strictjson.AsArray(v)
	if err != nil {
		return nil, formatErr("%q: %v", key, err)
	}
	return arr, nil
}

func hashFile(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func formatErr(format string, args ...any) error {
	return fmt.Errorf("%w: %s", ErrFormat, fmt.Sprintf(format, args...))
}
