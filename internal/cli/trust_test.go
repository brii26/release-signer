package cli

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/brii26/release-signer/pkg/bundle"
	"github.com/brii26/release-signer/pkg/keys"
	"github.com/brii26/release-signer/pkg/manifest"
	"github.com/brii26/release-signer/pkg/release"
	"github.com/brii26/release-signer/pkg/truststore"
)

func runTrustCommand(t *testing.T, wantExit int, args ...string) string {
	t.Helper()
	var stdout, stderr bytes.Buffer
	exit := Run(args, &stdout, &stderr)
	if exit != wantExit {
		t.Fatalf("Run(%v) exit = %d, want %d; stderr: %s", args, exit, wantExit, stderr.String())
	}
	if wantExit != 0 && (stdout.Len() != 0 || stderr.Len() == 0) {
		t.Fatalf("failed trust command output: stdout=%q stderr=%q", stdout.String(), stderr.String())
	}
	return stdout.String()
}

func readTrustFile(t *testing.T, path string) []byte {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func TestTrustCommandsLifecycle(t *testing.T) {
	dir := t.TempDir()
	prefix := filepath.Join(dir, "publisher")
	keyID := strings.TrimSpace(runTrustCommand(t, 0, "keygen", "--algorithm", "ed25519", "--out", prefix))
	pubPath := prefix + ".pub.pem"
	storePath := filepath.Join(dir, "trust.json")
	add := func(pkg string) string {
		return runTrustCommand(t, 0, "trust", "add", "--key", pubPath, "--package", pkg, "--store", storePath)
	}
	output := add("app.name")
	for _, value := range []string{keyID, "ed25519", "app.name"} {
		if !strings.Contains(output, value) {
			t.Fatalf("trust add output %q missing %q", output, value)
		}
	}
	before := readTrustFile(t, storePath)
	// Bila add idempoten mencoba menulis ulang, direktori read-only akan gagal.
	if err := os.Chmod(dir, 0500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := os.Chmod(dir, 0700); err != nil {
			t.Error(err)
		}
	})
	add("app.name")
	if !bytes.Equal(before, readTrustFile(t, storePath)) {
		t.Fatal("idempotent trust add changed file bytes")
	}
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	output = add("other-app")
	store, err := truststore.Load(storePath)
	if err != nil || len(store.Keys) != 1 || len(store.Keys[0].Packages) != 2 ||
		!strings.Contains(output, "app.name,other-app") {
		t.Fatalf("trust add merge = %+v, %v; output %q", store, err, output)
	}
	before = readTrustFile(t, storePath)
	listed := runTrustCommand(t, 0, "trust", "list", "--store", storePath)
	if listed != output || !bytes.Equal(before, readTrustFile(t, storePath)) {
		t.Fatal("trust list output differs from add or changed file bytes")
	}
	runTrustCommand(t, 2, "trust", "remove", "--keyid", strings.Repeat("0", 64), "--store", storePath)
	if !bytes.Equal(before, readTrustFile(t, storePath)) {
		t.Fatal("failed remove changed file bytes")
	}
	runTrustCommand(t, 0, "trust", "remove", "--keyid", keyID, "--store", storePath)
	store, err = truststore.Load(storePath)
	if err != nil || len(store.Keys) != 0 {
		t.Fatalf("trust remove = %+v, %v", store, err)
	}
	if output := runTrustCommand(t, 0, "trust", "list", "--store", storePath); output != "" {
		t.Fatalf("empty trust list output = %q", output)
	}
	runTrustCommand(t, 2, "trust", "remove", "--keyid", keyID, "--store", storePath)
}

func TestTrustCommandsRejectInvalidStore(t *testing.T) {
	dir := t.TempDir()
	prefix := filepath.Join(dir, "publisher")
	keyID := strings.TrimSpace(runTrustCommand(t, 0, "keygen", "--algorithm", "ed25519", "--out", prefix))
	path := filepath.Join(dir, "trust.json")
	bad := []byte(`{"schema":"minisign-trust/v1","keys":null}`)
	if err := os.WriteFile(path, bad, 0600); err != nil {
		t.Fatal(err)
	}
	for _, args := range [][]string{
		{"trust", "add", "--key", prefix + ".pub.pem", "--package", "app", "--store", path},
		{"trust", "list", "--store", path},
		{"trust", "remove", "--keyid", keyID, "--store", path},
	} {
		runTrustCommand(t, 2, args...)
		if !bytes.Equal(bad, readTrustFile(t, path)) {
			t.Fatalf("Run(%v) overwrote a malformed store", args)
		}
	}
	missing := filepath.Join(dir, "missing.json")
	runTrustCommand(t, 2, "trust", "list", "--store", missing)
	runTrustCommand(t, 2, "trust", "remove", "--keyid", keyID, "--store", missing)
	for _, pkg := range []string{"App", "*", "_app", strings.Repeat("a", 65)} {
		runTrustCommand(t, 2, "trust", "add", "--key", prefix+".pub.pem", "--package", pkg, "--store", missing)
	}
	if err := os.WriteFile(prefix+".pub.pem", []byte("bad key"), 0600); err != nil {
		t.Fatal(err)
	}
	runTrustCommand(t, 2, "trust", "add", "--key", prefix+".pub.pem", "--package", "app", "--store", missing)
	if _, err := os.Stat(missing); !os.IsNotExist(err) {
		t.Fatalf("failed command created a store: %v", err)
	}
}

func TestTrustRemovalAffectsVerify(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pubPEM, err := keys.MarshalPublicPEM(pub)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	pubPath := filepath.Join(dir, "publisher.pub.pem")
	storePath := filepath.Join(dir, "trust.json")
	artifactPath := filepath.Join(dir, "app.zip")
	bundlePath := filepath.Join(dir, "bundle.json")
	if err := os.WriteFile(pubPath, pubPEM, 0600); err != nil {
		t.Fatal(err)
	}
	artifact := []byte("release bytes")
	if err := os.WriteFile(artifactPath, artifact, 0600); err != nil {
		t.Fatal(err)
	}
	keyID, err := keys.KeyID(pub)
	if err != nil {
		t.Fatal(err)
	}
	hash := sha256.Sum256(artifact)
	m, err := manifest.New("app.name", "1.0.0", "ed25519", keyID, "app.zip", int64(len(artifact)), fmt.Sprintf("%x", hash))
	if err != nil {
		t.Fatal(err)
	}
	manifestBytes := m.Canonical()
	if err := bundle.WriteFile(bundlePath, bundle.Build(manifestBytes, ed25519.Sign(priv, manifestBytes)), false); err != nil {
		t.Fatal(err)
	}
	in := release.VerifyInput{
		ArtifactPath: artifactPath, BundlePath: bundlePath, TrustStorePath: storePath,
		Package: "app.name", Version: "1.0.0",
	}
	assertVerify := func(want release.Status) {
		t.Helper()
		before := readTrustFile(t, storePath)
		result := release.Verify(in)
		if result.Status != want || result.Valid != (want == release.StatusOK) {
			t.Fatalf("Verify = %+v, want %s", result, want)
		}
		if !bytes.Equal(before, readTrustFile(t, storePath)) {
			t.Fatal("verify changed the trust store")
		}
	}
	runTrustCommand(t, 0, "trust", "add", "--key", pubPath, "--package", "other-app", "--store", storePath)
	assertVerify(release.StatusKeyNotTrusted)
	runTrustCommand(t, 0, "trust", "add", "--key", pubPath, "--package", "app.name", "--store", storePath)
	assertVerify(release.StatusOK)
	runTrustCommand(t, 0, "trust", "remove", "--keyid", keyID, "--store", storePath)
	assertVerify(release.StatusKeyNotTrusted)
}
