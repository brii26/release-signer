package manifest

import (
	"errors"
	"strings"
	"testing"
)

const (
	keyID = "a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90"
	sha   = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"
)

func sample(t *testing.T) Manifest {
	t.Helper()
	m, err := New("contoh-app", "1.0.0", "ed25519", keyID, "contoh-app.zip", 1048576, sha)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return m
}

func TestCanonicalMatchesSpecExample(t *testing.T) {
	want := `{"schema":"minisign-manifest/v1","package":"contoh-app","version":"1.0.0","algorithm":"ed25519","keyid":"` + keyID +
		`","artifact":{"name":"contoh-app.zip","size":1048576,"sha256":"` + sha + `"}}`
	if got := string(sample(t).Canonical()); got != want {
		t.Fatalf("Canonical() =\n%s\nwant\n%s", got, want)
	}
}

func TestParseStrictRoundTrip(t *testing.T) {
	m := sample(t)
	got, err := ParseStrict(m.Canonical())
	if err != nil {
		t.Fatalf("ParseStrict: %v", err)
	}
	if got != m {
		t.Fatalf("round trip mismatch: %+v vs %+v", got, m)
	}
}

func TestParseStrictAcceptsUnknownAlgorithm(t *testing.T) {
	m := sample(t)
	m.Algorithm = "rsa-pkcs1-sha256"
	got, err := ParseStrict(m.Canonical())
	if err != nil || got.Algorithm != "rsa-pkcs1-sha256" {
		t.Fatalf("ParseStrict = %+v, %v", got, err)
	}
}

func TestParseStrictRejects(t *testing.T) {
	canon := string(sample(t).Canonical())
	swap := func(old, new string) string { return strings.Replace(canon, old, new, 1) }

	tests := []struct {
		name string
		in   string
	}{
		{"pretty printed", strings.ReplaceAll(canon, `,"`, ",\n  \"")},
		{"trailing newline", canon + "\n"},
		{"leading bom", "\xEF\xBB\xBF" + canon},
		{"fields swapped", `{"package":"contoh-app","schema":"minisign-manifest/v1",` + canon[strings.Index(canon, `"version"`):]},
		{"extra field", swap(`"artifact"`, `"extra":"x","artifact"`)},
		{"missing field", swap(`"version":"1.0.0",`, ``)},
		{"duplicate field", swap(`"version":"1.0.0",`, `"version":"1.0.0","version":"1.0.0",`)},
		{"size is true", swap(`"size":1048576`, `"size":true`)},
		{"size is string", swap(`"size":1048576`, `"size":"1048576"`)},
		{"size is fraction", swap(`"size":1048576`, `"size":1048576.0`)},
		{"size has leading zero", swap(`"size":1048576`, `"size":01048576`)},
		{"size is null", swap(`"size":1048576`, `"size":null`)},
		{"size above 2^53-1", swap(`"size":1048576`, `"size":9007199254740992`)},
		{"artifact fourth field", swap(`"sha256"`, `"extra":1,"sha256"`)},
		{"uppercase package", swap(`contoh-app","version`, `Contoh-app","version`)},
		{"uppercase keyid", swap(keyID, strings.ToUpper(keyID))},
		{"wrong schema", swap(`manifest/v1`, `manifest/v2`)},
		{"escaped algorithm", swap(`"ed25519"`, "\"\x5cu0065d25519\"")},
		{"too large", strings.Repeat(" ", MaxSize+1)},
		{"not json", `contoh`},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := ParseStrict([]byte(tc.in)); !errors.Is(err, ErrFormat) {
				t.Fatalf("ParseStrict error = %v, want ErrFormat", err)
			}
		})
	}
}

func TestNewRejectsBadMetadata(t *testing.T) {
	tests := []struct {
		name string
		call func() (Manifest, error)
	}{
		{"uppercase package", func() (Manifest, error) {
			return New("Bad", "1.0.0", "ed25519", keyID, "a.zip", 1, sha)
		}},
		{"empty version", func() (Manifest, error) {
			return New("app", "", "ed25519", keyID, "a.zip", 1, sha)
		}},
		{"version with space", func() (Manifest, error) {
			return New("app", "1 0", "ed25519", keyID, "a.zip", 1, sha)
		}},
		{"algorithm with quote", func() (Manifest, error) {
			return New("app", "1.0.0", `ed"25519`, keyID, "a.zip", 1, sha)
		}},
		{"empty algorithm", func() (Manifest, error) {
			return New("app", "1.0.0", "", keyID, "a.zip", 1, sha)
		}},
		{"short keyid", func() (Manifest, error) {
			return New("app", "1.0.0", "ed25519", "abc", "a.zip", 1, sha)
		}},
		{"name with directory", func() (Manifest, error) {
			return New("app", "1.0.0", "ed25519", keyID, "dir/a.zip", 1, sha)
		}},
		{"name starts with dot", func() (Manifest, error) {
			return New("app", "1.0.0", "ed25519", keyID, ".hidden", 1, sha)
		}},
		{"negative size", func() (Manifest, error) {
			return New("app", "1.0.0", "ed25519", keyID, "a.zip", -1, sha)
		}},
		{"size above 2^53-1", func() (Manifest, error) {
			return New("app", "1.0.0", "ed25519", keyID, "a.zip", 9007199254740992, sha)
		}},
		{"short sha256", func() (Manifest, error) {
			return New("app", "1.0.0", "ed25519", keyID, "a.zip", 1, "abc")
		}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := tc.call(); !errors.Is(err, ErrFormat) {
				t.Fatalf("error = %v, want ErrFormat", err)
			}
		})
	}
}

func TestNewAcceptsBoundaries(t *testing.T) {
	maxName := "a" + strings.Repeat("b", 127)
	for _, size := range []int64{0, 9007199254740991} {
		m, err := New("a", "A", "ed25519", keyID, maxName, size, sha)
		if err != nil {
			t.Fatalf("size %d: %v", size, err)
		}
		if _, err := ParseStrict(m.Canonical()); err != nil {
			t.Fatalf("size %d round trip: %v", size, err)
		}
	}
}
