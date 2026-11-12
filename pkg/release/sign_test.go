package release

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/brii26/release-signer/pkg/bundle"
	"github.com/brii26/release-signer/pkg/keys"
	"github.com/brii26/release-signer/pkg/manifest"
	"github.com/brii26/release-signer/pkg/profile"
	"github.com/brii26/release-signer/pkg/sigalg"
	"github.com/brii26/release-signer/pkg/truststore"
)

const emptySHA256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

var allProfiles = []profile.Profile{profile.RSAPSS, profile.ECDSA, profile.Ed25519}

var (
	signerMu    sync.Mutex
	signerCache = map[profile.Profile]crypto.Signer{}
)

func signerFor(t *testing.T, p profile.Profile) crypto.Signer {
	t.Helper()
	signerMu.Lock()
	defer signerMu.Unlock()
	if s, ok := signerCache[p]; ok {
		return s
	}
	s, err := keys.Generate(p)
	if err != nil {
		t.Fatalf("Generate(%s): %v", p, err)
	}
	signerCache[p] = s
	return s
}

func writeKey(t *testing.T, dir string, p profile.Profile) string {
	t.Helper()
	data, err := keys.MarshalPrivatePEM(signerFor(t, p))
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "signer.key.pem")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func writeFile(t *testing.T, path string, data []byte) {
	t.Helper()
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatal(err)
	}
}

func sha(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func TestSignAllProfilesAndContents(t *testing.T) {
	contents := []struct {
		name string
		data []byte
	}{
		{"text.txt", []byte("halo dunia\nbaris kedua\n")},
		{"binary.bin", append([]byte{0, 1, 2, 0xff, 0xfe}, bytes.Repeat([]byte{0xab}, 4096)...)},
		{"empty.bin", nil},
	}
	for _, p := range allProfiles {
		for _, c := range contents {
			t.Run(string(p)+"/"+c.name, func(t *testing.T) {
				dir := t.TempDir()
				artifact := filepath.Join(dir, c.name)
				writeFile(t, artifact, c.data)
				out := filepath.Join(dir, "release.json")

				res, err := Sign(SignInput{
					ArtifactPath: artifact, Package: "contoh-app", Version: "1.0.0",
					KeyPath: writeKey(t, dir, p), OutPath: out,
				})
				if err != nil {
					t.Fatalf("Sign: %v", err)
				}
				if res.Profile != p || res.BundlePath != out {
					t.Fatalf("unexpected output: %+v", res)
				}

				raw, err := os.ReadFile(out)
				if err != nil {
					t.Fatal(err)
				}
				msg, sig, err := bundle.ParseStrict(raw)
				if err != nil {
					t.Fatalf("ParseStrict: %v", err)
				}
				if !bytes.Equal(msg, res.Manifest) {
					t.Fatal("bundle manifest differs from SignOutput.Manifest")
				}
				m, err := manifest.ParseStrict(msg)
				if err != nil {
					t.Fatalf("manifest.ParseStrict: %v", err)
				}
				if m.Artifact.Name != c.name || m.Artifact.Size != int64(len(c.data)) || m.Artifact.SHA256 != sha(c.data) {
					t.Fatalf("manifest artifact wrong: %+v", m.Artifact)
				}
				if m.Algorithm != string(p) || m.KeyID != res.KeyID {
					t.Fatalf("manifest key info wrong: %+v", m)
				}
				if !sigalg.Verify(p, signerFor(t, p).Public(), msg, sig) {
					t.Fatal("signature does not verify")
				}
				if len(sig) != p.SignatureLen() {
					t.Fatalf("signature length = %d, want %d", len(sig), p.SignatureLen())
				}
				if c.data == nil && (m.Artifact.Size != 0 || m.Artifact.SHA256 != emptySHA256) {
					t.Fatalf("empty artifact manifest wrong: %+v", m.Artifact)
				}
			})
		}
	}
}

func TestSignThenVerify(t *testing.T) {
	for _, p := range allProfiles {
		t.Run(string(p), func(t *testing.T) {
			dir := t.TempDir()
			artifact := filepath.Join(dir, "contoh-app.zip")
			writeFile(t, artifact, []byte("isi rilis"))
			out := filepath.Join(dir, "release.json")
			if _, err := Sign(SignInput{
				ArtifactPath: artifact, Package: "contoh-app", Version: "1.0.0",
				KeyPath: writeKey(t, dir, p), OutPath: out,
			}); err != nil {
				t.Fatalf("Sign: %v", err)
			}

			pub, err := keys.MarshalPublicPEM(signerFor(t, p).Public())
			if err != nil {
				t.Fatal(err)
			}
			store, err := truststore.LoadOrEmpty(filepath.Join(dir, "trust.json"))
			if err != nil {
				t.Fatal(err)
			}
			if _, _, err := store.Add(pub, "contoh-app"); err != nil {
				t.Fatal(err)
			}
			storePath := filepath.Join(dir, "trust.json")
			if err := store.Save(storePath); err != nil {
				t.Fatal(err)
			}

			res := Verify(VerifyInput{
				ArtifactPath: artifact, BundlePath: out, TrustStorePath: storePath,
				Package: "contoh-app", Version: "1.0.0",
			})
			if res.Status != StatusOK || !res.Valid {
				t.Fatalf("Verify = %+v, want OK", res)
			}
		})
	}
}

func TestSignDoesNotTouchArtifact(t *testing.T) {
	dir := t.TempDir()
	artifact := filepath.Join(dir, "app.bin")
	data := []byte("jangan diubah")
	writeFile(t, artifact, data)
	past := time.Now().Add(-48 * time.Hour).Truncate(time.Second)
	if err := os.Chtimes(artifact, past, past); err != nil {
		t.Fatal(err)
	}

	if _, err := Sign(SignInput{
		ArtifactPath: artifact, Package: "app", Version: "1",
		KeyPath: writeKey(t, dir, profile.Ed25519), OutPath: filepath.Join(dir, "r.json"),
	}); err != nil {
		t.Fatal(err)
	}

	after, err := os.ReadFile(artifact)
	if err != nil || !bytes.Equal(after, data) {
		t.Fatalf("artifact content changed: %v", err)
	}
	info, _ := os.Stat(artifact)
	if !info.ModTime().Equal(past) {
		t.Fatalf("mtime changed: %v, want %v", info.ModTime(), past)
	}
}

func TestSignRejectsBadInput(t *testing.T) {
	dir := t.TempDir()
	key := writeKey(t, dir, profile.Ed25519)
	good := filepath.Join(dir, "good.bin")
	writeFile(t, good, []byte("x"))

	tests := []struct {
		name string
		in   SignInput
	}{
		{"artifact name with space", SignInput{ArtifactPath: filepath.Join(dir, "a b.bin"), Package: "app", Version: "1"}},
		{"artifact name starts with dot", SignInput{ArtifactPath: filepath.Join(dir, ".hidden"), Package: "app", Version: "1"}},
		{"uppercase package", SignInput{ArtifactPath: good, Package: "App", Version: "1"}},
		{"empty version", SignInput{ArtifactPath: good, Package: "app", Version: ""}},
		{"missing artifact", SignInput{ArtifactPath: filepath.Join(dir, "tidak-ada.bin"), Package: "app", Version: "1"}},
		{"artifact is a directory", SignInput{ArtifactPath: dir, Package: "app", Version: "1"}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if filepath.Base(tc.in.ArtifactPath) == "a b.bin" || filepath.Base(tc.in.ArtifactPath) == ".hidden" {
				writeFile(t, tc.in.ArtifactPath, []byte("x"))
			}
			out := filepath.Join(t.TempDir(), "r.json")
			tc.in.KeyPath, tc.in.OutPath = key, out
			if _, err := Sign(tc.in); !errors.Is(err, ErrInput) {
				t.Fatalf("error = %v, want ErrInput", err)
			}
			if _, err := os.Stat(out); err == nil {
				t.Fatal("bundle must not be written on failure")
			}
		})
	}

	t.Run("missing key", func(t *testing.T) {
		_, err := Sign(SignInput{
			ArtifactPath: good, Package: "app", Version: "1",
			KeyPath: filepath.Join(dir, "tidak-ada.pem"), OutPath: filepath.Join(dir, "r.json"),
		})
		if !errors.Is(err, ErrInput) {
			t.Fatalf("error = %v, want ErrInput", err)
		}
	})
}

func TestSignOutputExists(t *testing.T) {
	dir := t.TempDir()
	artifact := filepath.Join(dir, "app.bin")
	writeFile(t, artifact, []byte("x"))
	key := writeKey(t, dir, profile.Ed25519)
	out := filepath.Join(dir, "release.json")
	writeFile(t, out, []byte("bundle lama"))

	in := SignInput{ArtifactPath: artifact, Package: "app", Version: "1", KeyPath: key, OutPath: out}
	if _, err := Sign(in); !errors.Is(err, ErrInput) {
		t.Fatalf("without Force: error = %v, want ErrInput", err)
	}
	if got, _ := os.ReadFile(out); string(got) != "bundle lama" {
		t.Fatalf("existing bundle was modified: %q", got)
	}

	in.Force = true
	if _, err := Sign(in); err != nil {
		t.Fatalf("with Force: %v", err)
	}
	raw, _ := os.ReadFile(out)
	if _, _, err := bundle.ParseStrict(raw); err != nil {
		t.Fatalf("overwritten bundle invalid: %v", err)
	}
}

func TestSignRejectsUnsupportedKeys(t *testing.T) {
	rsa2048, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	pkcs8, _ := x509.MarshalPKCS8PrivateKey(rsa2048)
	pkcs1 := x509.MarshalPKCS1PrivateKey(rsa2048)

	const secretBody = "c2VjcmV0LWJvZHktamFuZ2FuLWJvY29y"
	keyFiles := map[string][]byte{
		"rsa 2048":       pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pkcs8}),
		"pkcs1 label":    pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: pkcs1}),
		"garbage body":   []byte("-----BEGIN PRIVATE KEY-----\n" + secretBody + "\n-----END PRIVATE KEY-----\n"),
		"not pem at all": []byte("bukan pem"),
	}
	for name, content := range keyFiles {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			artifact := filepath.Join(dir, "app.bin")
			writeFile(t, artifact, []byte("x"))
			keyPath := filepath.Join(dir, "k.pem")
			writeFile(t, keyPath, content)

			_, err := Sign(SignInput{
				ArtifactPath: artifact, Package: "app", Version: "1",
				KeyPath: keyPath, OutPath: filepath.Join(dir, "r.json"),
			})
			if !errors.Is(err, ErrInput) {
				t.Fatalf("error = %v, want ErrInput", err)
			}
			msg := err.Error()
			if strings.Contains(msg, "PRIVATE KEY") || strings.Contains(msg, secretBody) || strings.Contains(msg, hex.EncodeToString(pkcs8[:8])) {
				t.Fatalf("error leaks key material: %q", msg)
			}
		})
	}
}
