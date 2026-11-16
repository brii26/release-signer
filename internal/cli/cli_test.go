package cli

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRootFlags(t *testing.T) {
	tests := []struct {
		name     string
		args     []string
		wantExit int
		wantOut  string
		wantErr  string
	}{
		{
			name:     "empty args",
			args:     []string{},
			wantExit: 2,
			wantErr:  "Usage:",
		},
		{
			name:     "root help long",
			args:     []string{"--help"},
			wantExit: 0,
			wantOut:  "Usage:",
		},
		{
			name:     "root help short",
			args:     []string{"-h"},
			wantExit: 0,
			wantOut:  "Usage:",
		},
		{
			name:     "root help command",
			args:     []string{"help"},
			wantExit: 0,
			wantOut:  "Usage:",
		},
		{
			name:     "root version",
			args:     []string{"--version"},
			wantExit: 0,
			wantOut:  Version,
		},
		{
			name:     "unknown command",
			args:     []string{"foo"},
			wantExit: 2,
			wantErr:  `unknown command "foo"`,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			code := Run(tc.args, &stdout, &stderr)
			if code != tc.wantExit {
				t.Fatalf("Run(%v) exit = %d, want %d (stdout: %s, stderr: %s)",
					tc.args, code, tc.wantExit, stdout.String(), stderr.String())
			}
			if tc.wantOut != "" && !strings.Contains(stdout.String(), tc.wantOut) {
				t.Errorf("stdout %q does not contain %q", stdout.String(), tc.wantOut)
			}
			if tc.wantErr != "" && !strings.Contains(stderr.String(), tc.wantErr) {
				t.Errorf("stderr %q does not contain %q", stderr.String(), tc.wantErr)
			}
		})
	}
}

func TestSubcommandHelp(t *testing.T) {
	cmds := [][]string{
		{"keygen", "--help"},
		{"sign", "--help"},
		{"verify", "--help"},
		{"trust", "--help"},
		{"trust", "add", "--help"},
		{"trust", "list", "--help"},
		{"trust", "remove", "--help"},
	}

	for _, args := range cmds {
		name := strings.Join(args, " ")
		t.Run(name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			code := Run(args, &stdout, &stderr)
			if code != 0 {
				t.Fatalf("Run(%v) = %d, want 0 (stderr: %s)", args, code, stderr.String())
			}
			if !strings.Contains(stderr.String(), "Usage:") && !strings.Contains(stdout.String(), "Usage:") {
				t.Errorf("expected usage output for %v", args)
			}
		})
	}
}

func TestKeygenCLI(t *testing.T) {
	tmpDir := t.TempDir()

	origKeygen := KeygenAction
	defer func() { KeygenAction = origKeygen }()

	KeygenAction = func(p KeygenParams, stdout, stderr io.Writer) error {
		fmt.Fprintln(stdout, "dummy-keyid-64-chars-hex")
		fmt.Fprintf(stderr, "Generated %s.key.pem\n", p.OutPrefix)
		return nil
	}

	// --algorithm kosong
	{
		var stdout, stderr bytes.Buffer
		code := Run([]string{"keygen", "--out", filepath.Join(tmpDir, "k")}, &stdout, &stderr)
		if code != 2 || !strings.Contains(stderr.String(), "--algorithm is required") {
			t.Fatalf("expected exit 2 on missing algorithm: code=%d err=%s", code, stderr.String())
		}
	}

	// algorithm tidak didukung
	{
		var stdout, stderr bytes.Buffer
		code := Run([]string{"keygen", "--algorithm", "rsa-pkcs1", "--out", filepath.Join(tmpDir, "k")}, &stdout, &stderr)
		if code != 2 || !strings.Contains(stderr.String(), "unsupported algorithm") {
			t.Fatalf("expected exit 2 on unsupported algorithm: code=%d err=%s", code, stderr.String())
		}
	}

	// --out kosong
	{
		var stdout, stderr bytes.Buffer
		code := Run([]string{"keygen", "--algorithm", "ed25519"}, &stdout, &stderr)
		if code != 2 || !strings.Contains(stderr.String(), "--out is required") {
			t.Fatalf("expected exit 2 on missing --out: code=%d err=%s", code, stderr.String())
		}
	}

	// sukses
	{
		var stdout, stderr bytes.Buffer
		prefix := filepath.Join(tmpDir, "key1")
		code := Run([]string{"keygen", "--algorithm", "ed25519", "--out", prefix}, &stdout, &stderr)
		if code != 0 {
			t.Fatalf("expected exit 0 on valid keygen: code=%d err=%s", code, stderr.String())
		}
		if !strings.Contains(stdout.String(), "dummy-keyid-64-chars-hex") {
			t.Fatalf("expected stdout to have keyid, got %q", stdout.String())
		}
	}

	// file sudah ada tanpa --force
	{
		prefix := filepath.Join(tmpDir, "key2")
		privFile := prefix + ".key.pem"
		if err := os.WriteFile(privFile, []byte("key"), 0600); err != nil {
			t.Fatal(err)
		}

		var stdout, stderr bytes.Buffer
		code := Run([]string{"keygen", "--algorithm", "ed25519", "--out", prefix}, &stdout, &stderr)
		if code != 2 || !strings.Contains(stderr.String(), "already exist") {
			t.Fatalf("expected exit 2 when file exists without --force: code=%d err=%s", code, stderr.String())
		}

		// pakai --force
		stdout.Reset()
		stderr.Reset()
		code = Run([]string{"keygen", "--algorithm", "ed25519", "--out", prefix, "--force"}, &stdout, &stderr)
		if code != 0 {
			t.Fatalf("expected exit 0 with --force: code=%d err=%s", code, stderr.String())
		}
	}
}

func TestSignCLI(t *testing.T) {
	tmpDir := t.TempDir()
	artFile := filepath.Join(tmpDir, "app.zip")
	keyFile := filepath.Join(tmpDir, "priv.pem")
	bundleFile := filepath.Join(tmpDir, "bundle.json")

	if err := os.WriteFile(artFile, []byte("artifact-data"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyFile, []byte("key-data"), 0600); err != nil {
		t.Fatal(err)
	}

	origSign := SignAction
	defer func() { SignAction = origSign }()

	SignAction = func(p SignParams, stdout, stderr io.Writer) error {
		return nil
	}

	// flag kosong
	{
		var stdout, stderr bytes.Buffer
		code := Run([]string{"sign", "--file", artFile}, &stdout, &stderr)
		if code != 2 || !strings.Contains(stderr.String(), "missing required flags") {
			t.Fatalf("expected exit 2 on missing flags: code=%d err=%s", code, stderr.String())
		}
	}

	// nama package invalid
	{
		var stdout, stderr bytes.Buffer
		code := Run([]string{
			"sign", "--file", artFile, "--package", "Invalid Package",
			"--version", "1.0.0", "--key", keyFile, "--out", bundleFile,
		}, &stdout, &stderr)
		if code != 2 || !strings.Contains(stderr.String(), "invalid package name") {
			t.Fatalf("expected exit 2 on invalid package name: code=%d err=%s", code, stderr.String())
		}
	}

	// artifact tidak ada
	{
		var stdout, stderr bytes.Buffer
		code := Run([]string{
			"sign", "--file", filepath.Join(tmpDir, "nonexistent.zip"), "--package", "app",
			"--version", "1.0.0", "--key", keyFile, "--out", bundleFile,
		}, &stdout, &stderr)
		if code != 2 || !strings.Contains(stderr.String(), "artifact file") {
			t.Fatalf("expected exit 2 on missing artifact: code=%d err=%s", code, stderr.String())
		}
	}

	// sukses
	{
		var stdout, stderr bytes.Buffer
		code := Run([]string{
			"sign", "--file", artFile, "--package", "app",
			"--version", "1.0.0", "--key", keyFile, "--out", bundleFile,
		}, &stdout, &stderr)
		if code != 0 {
			t.Fatalf("expected exit 0 on sign: code=%d err=%s", code, stderr.String())
		}
	}

	// bundle sudah ada tanpa --force
	{
		if err := os.WriteFile(bundleFile, []byte("{}"), 0644); err != nil {
			t.Fatal(err)
		}
		var stdout, stderr bytes.Buffer
		code := Run([]string{
			"sign", "--file", artFile, "--package", "app",
			"--version", "1.0.0", "--key", keyFile, "--out", bundleFile,
		}, &stdout, &stderr)
		if code != 2 || !strings.Contains(stderr.String(), "already exists") {
			t.Fatalf("expected exit 2 on existing bundle without --force: code=%d err=%s", code, stderr.String())
		}

		// pakai --force
		stdout.Reset()
		stderr.Reset()
		code = Run([]string{
			"sign", "--file", artFile, "--package", "app",
			"--version", "1.0.0", "--key", keyFile, "--out", bundleFile, "--force",
		}, &stdout, &stderr)
		if code != 0 {
			t.Fatalf("expected exit 0 on sign with --force: code=%d err=%s", code, stderr.String())
		}
	}
}

func TestVerifyCLI(t *testing.T) {
	tmpDir := t.TempDir()
	artFile := filepath.Join(tmpDir, "app.zip")
	bundleFile := filepath.Join(tmpDir, "bundle.json")
	trustFile := filepath.Join(tmpDir, "trust.json")

	if err := os.WriteFile(artFile, []byte("artifact-data"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(bundleFile, []byte("bundle-data"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(trustFile, []byte("trust-data"), 0644); err != nil {
		t.Fatal(err)
	}

	origVerify := VerifyAction
	defer func() { VerifyAction = origVerify }()

	// flag kosong + --json: output JSON INPUT_ERROR, valid false, exit 2
	{
		var stdout, stderr bytes.Buffer
		code := Run([]string{"verify", "--file", artFile, "--package", "app", "--version", "1.0.0", "--json"}, &stdout, &stderr)
		if code != 2 {
			t.Fatalf("expected exit 2 on missing flags with --json, got %d", code)
		}

		outStr := stdout.String()
		if !strings.HasSuffix(outStr, "\n") {
			t.Fatalf("verify --json output must end with newline: %q", outStr)
		}

		var res VerifyResult
		if err := json.Unmarshal(stdout.Bytes(), &res); err != nil {
			t.Fatalf("failed to unmarshal JSON output %q: %v", outStr, err)
		}
		if res.Valid != false || res.Status != "INPUT_ERROR" {
			t.Fatalf("expected valid: false, status: INPUT_ERROR, got %+v", res)
		}
	}

	// flag kosong tanpa --json: exit 2, error ke stderr
	{
		var stdout, stderr bytes.Buffer
		code := Run([]string{"verify", "--file", artFile, "--package", "app"}, &stdout, &stderr)
		if code != 2 || !strings.Contains(stderr.String(), "missing required flag") {
			t.Fatalf("expected exit 2 on missing flags: code=%d err=%s", code, stderr.String())
		}
	}

	// sukses dengan --json
	{
		algo := "ed25519"
		kid := "deadbeef"
		pkg := "app"
		ver := "1.0.0"

		VerifyAction = func(p VerifyParams) VerifyResult {
			return VerifyResult{
				Valid:     true,
				Status:    "OK",
				Message:   "verification successful",
				Algorithm: &algo,
				KeyID:     &kid,
				Package:   &pkg,
				Version:   &ver,
			}
		}

		var stdout, stderr bytes.Buffer
		code := Run([]string{
			"verify", "--file", artFile, "--bundle", bundleFile,
			"--trust-store", trustFile, "--package", "app", "--version", "1.0.0", "--json",
		}, &stdout, &stderr)

		if code != 0 {
			t.Fatalf("expected exit 0 on success, got %d (err: %s)", code, stderr.String())
		}

		var res VerifyResult
		if err := json.Unmarshal(stdout.Bytes(), &res); err != nil {
			t.Fatalf("failed to unmarshal JSON: %v", err)
		}
		if !res.Valid || res.Status != "OK" {
			t.Fatalf("expected Valid=true Status=OK, got %+v", res)
		}
	}

	// sukses, output human-readable
	{
		var stdout, stderr bytes.Buffer
		code := Run([]string{
			"verify", "--file", artFile, "--bundle", bundleFile,
			"--trust-store", trustFile, "--package", "app", "--version", "1.0.0",
		}, &stdout, &stderr)

		if code != 0 {
			t.Fatalf("expected exit 0 on human-readable success, got %d", code)
		}
		if !strings.Contains(stdout.String(), "OK:") {
			t.Fatalf("expected stdout to have 'OK:', got %q", stdout.String())
		}
	}

	// ARTIFACT_MISMATCH: exit 1
	{
		VerifyAction = func(p VerifyParams) VerifyResult {
			return VerifyResult{
				Valid:   false,
				Status:  "ARTIFACT_MISMATCH",
				Message: "hash mismatch",
			}
		}

		var stdout, stderr bytes.Buffer
		code := Run([]string{
			"verify", "--file", artFile, "--bundle", bundleFile,
			"--trust-store", trustFile, "--package", "app", "--version", "1.0.0", "--json",
		}, &stdout, &stderr)

		if code != 1 {
			t.Fatalf("expected exit 1 on ARTIFACT_MISMATCH, got %d", code)
		}

		var res VerifyResult
		if err := json.Unmarshal(stdout.Bytes(), &res); err != nil {
			t.Fatalf("unmarshal error: %v", err)
		}
		if res.Valid || res.Status != "ARTIFACT_MISMATCH" {
			t.Fatalf("expected Valid=false Status=ARTIFACT_MISMATCH, got %+v", res)
		}
	}
}

func TestTrustCLI(t *testing.T) {
	tmpDir := t.TempDir()
	pubFile := filepath.Join(tmpDir, "pub.pem")
	storeFile := filepath.Join(tmpDir, "trust.json")

	if err := os.WriteFile(pubFile, []byte("pub-key"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(storeFile, []byte("{}"), 0644); err != nil {
		t.Fatal(err)
	}

	origTrustAdd := TrustAddAction
	origTrustList := TrustListAction
	origTrustRemove := TrustRemoveAction
	defer func() {
		TrustAddAction = origTrustAdd
		TrustListAction = origTrustList
		TrustRemoveAction = origTrustRemove
	}()

	TrustAddAction = func(p TrustAddParams, stdout, stderr io.Writer) error {
		return nil
	}
	TrustListAction = func(p TrustListParams, stdout, stderr io.Writer) error {
		return nil
	}
	TrustRemoveAction = func(p TrustRemoveParams, stdout, stderr io.Writer) error {
		if p.KeyID == "notfound" {
			return ErrNotFound
		}
		return nil
	}

	// trust add tanpa flag
	{
		var stdout, stderr bytes.Buffer
		code := Run([]string{"trust", "add", "--key", pubFile}, &stdout, &stderr)
		if code != 2 {
			t.Fatalf("expected exit 2 on trust add missing flags, got %d", code)
		}
	}

	// trust add sukses
	{
		var stdout, stderr bytes.Buffer
		code := Run([]string{"trust", "add", "--key", pubFile, "--package", "app", "--store", storeFile}, &stdout, &stderr)
		if code != 0 {
			t.Fatalf("expected exit 0 on trust add, got %d (err: %s)", code, stderr.String())
		}
	}

	// trust list tanpa store
	{
		var stdout, stderr bytes.Buffer
		code := Run([]string{"trust", "list"}, &stdout, &stderr)
		if code != 2 {
			t.Fatalf("expected exit 2 on trust list missing store, got %d", code)
		}
	}

	// trust list sukses
	{
		var stdout, stderr bytes.Buffer
		code := Run([]string{"trust", "list", "--store", storeFile}, &stdout, &stderr)
		if code != 0 {
			t.Fatalf("expected exit 0 on trust list, got %d (err: %s)", code, stderr.String())
		}
	}

	// trust remove tidak ketemu: exit 2
	{
		var stdout, stderr bytes.Buffer
		code := Run([]string{"trust", "remove", "--keyid", "notfound", "--store", storeFile}, &stdout, &stderr)
		if code != 2 {
			t.Fatalf("expected exit 2 on trust remove non-existent keyid, got %d", code)
		}
	}

	// trust remove sukses
	{
		var stdout, stderr bytes.Buffer
		code := Run([]string{"trust", "remove", "--keyid", "knownkey", "--store", storeFile}, &stdout, &stderr)
		if code != 0 {
			t.Fatalf("expected exit 0 on trust remove success, got %d", code)
		}
	}
}
