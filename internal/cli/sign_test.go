package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/brii26/release-signer/pkg/bundle"
	"github.com/brii26/release-signer/pkg/manifest"
)

func TestSignCommandIsWired(t *testing.T) {
	dir := t.TempDir()
	prefix := filepath.Join(dir, "publisher")
	artifact := filepath.Join(dir, "contoh-app.zip")
	out := filepath.Join(dir, "release.json")
	if err := os.WriteFile(artifact, []byte("isi rilis"), 0o644); err != nil {
		t.Fatal(err)
	}

	var stdout, stderr bytes.Buffer
	if code := Run([]string{"keygen", "--algorithm", "ed25519", "--out", prefix}, &stdout, &stderr); code != 0 {
		t.Fatalf("keygen exit = %d, stderr = %s", code, stderr.String())
	}

	sign := []string{
		"sign", "--file", artifact, "--package", "contoh-app", "--version", "1.0.0",
		"--key", prefix + ".key.pem", "--out", out,
	}
	stdout.Reset()
	stderr.Reset()
	if code := Run(sign, &stdout, &stderr); code != 0 {
		t.Fatalf("sign exit = %d, stderr = %s", code, stderr.String())
	}
	if stdout.Len() != 0 {
		t.Fatalf("sign must not write to stdout, got %q", stdout.String())
	}
	if strings.Contains(stderr.String(), "PRIVATE KEY") {
		t.Fatalf("stderr mentions private key: %q", stderr.String())
	}

	raw, err := os.ReadFile(out)
	if err != nil {
		t.Fatalf("bundle not written: %v", err)
	}
	msg, _, err := bundle.ParseStrict(raw)
	if err != nil {
		t.Fatalf("bundle invalid: %v", err)
	}
	m, err := manifest.ParseStrict(msg)
	if err != nil || m.Package != "contoh-app" || m.Version != "1.0.0" || m.Algorithm != "ed25519" {
		t.Fatalf("manifest wrong: %+v, %v", m, err)
	}

	stderr.Reset()
	if code := Run(sign, &stdout, &stderr); code != 2 {
		t.Fatalf("second sign without --force: exit = %d, want 2", code)
	}
	if code := Run(append(sign, "--force"), &stdout, &stderr); code != 0 {
		t.Fatalf("sign --force exit = %d, stderr = %s", code, stderr.String())
	}
}
