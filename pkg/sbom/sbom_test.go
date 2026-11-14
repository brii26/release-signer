package sbom

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const emptySHA = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

func writeArtifact(t *testing.T, name string, data []byte) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(p, data, 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestGenerateThenParseBinding(t *testing.T) {
	art := writeArtifact(t, "empty.bin", nil)
	out, err := Generate(art, "demo-app", "1.0.0")
	if err != nil {
		t.Fatal(err)
	}
	b, err := ParseBinding(out)
	if err != nil {
		t.Fatalf("ParseBinding: %v", err)
	}
	want := Binding{Package: "demo-app", Version: "1.0.0", ArtifactName: "empty.bin", ArtifactSHA: emptySHA}
	if b != want {
		t.Fatalf("binding = %+v, want %+v", b, want)
	}
	if out[len(out)-1] != '\n' {
		t.Fatal("generated SBOM should end with a newline")
	}
}

func TestGenerateDeterministic(t *testing.T) {
	art := writeArtifact(t, "a.bin", []byte("isi"))
	a, _ := Generate(art, "p", "1")
	b, _ := Generate(art, "p", "1")
	if string(a) != string(b) {
		t.Fatal("Generate must be deterministic")
	}
}

func TestGenerateMissingArtifact(t *testing.T) {
	if _, err := Generate(filepath.Join(t.TempDir(), "nope"), "p", "1"); err == nil {
		t.Fatal("expected error for missing artifact")
	}
}

func validDoc(mutate func(string) string) []byte {
	doc := `{"bomFormat":"CycloneDX","specVersion":"1.6","version":1,` +
		`"metadata":{"component":{"type":"application","name":"demo-app","version":"1.0.0",` +
		`"hashes":[{"alg":"SHA-256","content":"` + emptySHA + `"}],` +
		`"properties":[{"name":"release-signer:artifact-name","value":"a.bin"}]}},"components":[]}`
	if mutate != nil {
		doc = mutate(doc)
	}
	return []byte(doc)
}

func TestParseBindingRejects(t *testing.T) {
	cases := map[string]func(string) string{
		"wrong bomFormat": func(s string) string { return strings.Replace(s, `"CycloneDX"`, `"SPDX"`, 1) },
		"no hashes key":   func(s string) string { return strings.Replace(s, `"hashes"`, `"hashez"`, 1) },
		"other hash alg":  func(s string) string { return strings.Replace(s, `"SHA-256"`, `"SHA-512"`, 1) },
		"uppercase hash":  func(s string) string { return strings.Replace(s, emptySHA, strings.ToUpper(emptySHA), 1) },
		"short hash":      func(s string) string { return strings.Replace(s, emptySHA, emptySHA[:63], 1) },
		"two sha256 hashes": func(s string) string {
			h := `{"alg":"SHA-256","content":"` + emptySHA + `"}`
			return strings.Replace(s, h, h+","+h, 1)
		},
		"no name property": func(s string) string {
			return strings.Replace(s, "release-signer:artifact-name", "other", 1)
		},
		"duplicate key":   func(s string) string { return strings.Replace(s, `"version":1,`, `"version":1,"version":2,`, 1) },
		"name not string": func(s string) string { return strings.Replace(s, `"name":"demo-app"`, `"name":1`, 1) },
		"trailing data":   func(s string) string { return s + ` {}` },
		"not an object":   func(string) string { return `[]` },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := ParseBinding(validDoc(mutate))
			if !errors.Is(err, ErrFormat) {
				t.Fatalf("want ErrFormat, got %v", err)
			}
		})
	}
}

func TestParseBindingAllowsExtraFields(t *testing.T) {
	doc := validDoc(func(s string) string {
		return strings.Replace(s, `"components":[]`, `"components":[{"type":"library","name":"x","version":"1"}],"serialNumber":"urn:uuid:1"`, 1)
	})
	if _, err := ParseBinding(doc); err != nil {
		t.Fatalf("extra SBOM fields from external tools must be accepted: %v", err)
	}
}

func TestParseBindingRejectsOversize(t *testing.T) {
	big := validDoc(nil)
	big = append(big, []byte(strings.Repeat(" ", MaxSize))...)
	if _, err := ParseBinding(big); !errors.Is(err, ErrFormat) {
		t.Fatalf("want ErrFormat for oversize input, got %v", err)
	}
}
