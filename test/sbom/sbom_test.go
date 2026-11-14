package sbom_test

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

const (
	pkgName = "demo-app"
	version = "1.0.0"
)

var (
	binPath  string
	repoRoot string

	mu      sync.Mutex
	records []record
)

var profiles = []string{"rsa-pss-sha256", "ecdsa-p256-sha256", "ed25519"}

type record struct {
	ID             string `json:"id"`
	Profile        string `json:"profile"`
	Input          string `json:"input"`
	ExpectedStatus string `json:"expected_status"`
	ExpectedExit   int    `json:"expected_exit"`
	ActualStatus   string `json:"actual_status"`
	ActualExit     int    `json:"actual_exit"`
	Result         string `json:"result"`
}

type execResult struct {
	Exit   int
	Stdout string
	Stderr string
}

func (r execResult) status() string {
	var v struct {
		Status string `json:"status"`
	}
	if err := json.Unmarshal([]byte(strings.TrimSpace(r.Stdout)), &v); err != nil {
		return ""
	}
	return v.Status
}

func TestMain(m *testing.M) {
	wd, err := os.Getwd()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	repoRoot = filepath.Clean(filepath.Join(wd, "..", ".."))

	tmp, err := os.MkdirTemp("", "release-signer-sbom-*")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	defer os.RemoveAll(tmp)

	binPath = filepath.Join(tmp, "release-signer")
	cmd := exec.Command("go", "build", "-trimpath", "-o", binPath, "./cmd/release-signer")
	cmd.Dir = repoRoot
	if out, err := cmd.CombinedOutput(); err != nil {
		fmt.Fprintf(os.Stderr, "build failed: %v\n%s\n", err, out)
		os.Exit(1)
	}

	code := m.Run()

	if dir := os.Getenv("RESULTS_DIR"); dir != "" {
		if !filepath.IsAbs(dir) {
			dir = filepath.Join(repoRoot, dir)
		}
		writeResults(dir)
	}
	os.Exit(code)
}

func run(args ...string) execResult {
	cmd := exec.Command(binPath, args...)
	cmd.Dir = repoRoot
	var so, se strings.Builder
	cmd.Stdout, cmd.Stderr = &so, &se
	exit := 0
	if err := cmd.Run(); err != nil {
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			exit = ee.ExitCode()
		} else {
			exit = 1
		}
	}
	return execResult{Exit: exit, Stdout: so.String(), Stderr: se.String()}
}

func must(t *testing.T, args ...string) execResult {
	t.Helper()
	r := run(args...)
	if r.Exit != 0 {
		t.Fatalf("release-signer %s: exit %d\nstdout: %s\nstderr: %s", strings.Join(args, " "), r.Exit, r.Stdout, r.Stderr)
	}
	return r
}

// env adalah satu rilis lengkap: artefak, bundle rilis, SBOM, bundle SBOM, trust store.
type env struct {
	t        *testing.T
	dir      string
	profile  string
	artifact string
	keyPath  string
	trust    string
	relBndl  string
	sbomPath string
	sbomBndl string
}

func (e *env) p(name string) string { return filepath.Join(e.dir, name) }

func newEnv(t *testing.T, profile string) *env {
	t.Helper()
	e := &env{t: t, dir: t.TempDir(), profile: profile}
	e.artifact = e.p("demo-app.tar.gz")
	if err := os.WriteFile(e.artifact, []byte("isi artefak rilis versi satu\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	prefix := e.p("publisher")
	must(t, "keygen", "--algorithm", profile, "--out", prefix)
	e.keyPath = prefix + ".key.pem"
	e.trust = e.p("trust.json")
	must(t, "trust", "add", "--key", prefix+".pub.pem", "--package", pkgName, "--store", e.trust)

	e.relBndl = e.p("release.bundle.json")
	must(t, "sign", "--file", e.artifact, "--package", pkgName, "--version", version, "--key", e.keyPath, "--out", e.relBndl)

	e.sbomPath = e.p("sbom.cdx.json")
	must(t, "sbom", "generate", "--file", e.artifact, "--package", pkgName, "--version", version, "--out", e.sbomPath)
	e.sbomBndl = e.p("sbom.bundle.json")
	must(t, "sbom", "sign", "--sbom", e.sbomPath, "--package", pkgName, "--version", version, "--key", e.keyPath, "--out", e.sbomBndl)
	return e
}

func (e *env) check() execResult {
	return run("sbom", "check",
		"--file", e.artifact, "--bundle", e.relBndl,
		"--sbom", e.sbomPath, "--sbom-bundle", e.sbomBndl,
		"--trust-store", e.trust, "--package", pkgName, "--version", version, "--json")
}

func record1(t *testing.T, id, profile, input, wantStatus string, wantExit int, got execResult) {
	t.Helper()
	gotStatus := got.status()
	result := "PASS"
	if gotStatus != wantStatus || got.Exit != wantExit {
		result = "FAIL"
		t.Errorf("%s/%s: want %s exit %d, got %s exit %d\nstdout: %s\nstderr: %s",
			id, profile, wantStatus, wantExit, gotStatus, got.Exit, got.Stdout, got.Stderr)
	}
	mu.Lock()
	records = append(records, record{id, profile, input, wantStatus, wantExit, gotStatus, got.Exit, result})
	mu.Unlock()
}

// SBOM sah dan artefak sah.
func TestS01Valid(t *testing.T) {
	for _, p := range profiles {
		t.Run(p, func(t *testing.T) {
			e := newEnv(t, p)
			record1(t, "S01", p, "valid SBOM and valid artifact", "OK", 0, e.check())
		})
	}
}

// isi SBOM diubah setelah ditandatangani.
func TestS02SBOMTampered(t *testing.T) {
	e := newEnv(t, "ed25519")
	f, err := os.OpenFile(e.sbomPath, os.O_APPEND|os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString(" "); err != nil {
		t.Fatal(err)
	}
	f.Close()
	record1(t, "S02", "ed25519", "SBOM gets 1 extra byte after sign", "ARTIFACT_MISMATCH", 1, e.check())
}

// artefak rilis diganti dengan yang lain dan ditandatangani ulang secara sah, SBOM lama.
func TestS03ArtifactReplaced(t *testing.T) {
	e := newEnv(t, "ed25519")
	if err := os.WriteFile(e.artifact, []byte("artefak pengganti yang berbeda\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	must(t, "sign", "--force", "--file", e.artifact, "--package", pkgName, "--version", version, "--key", e.keyPath, "--out", e.relBndl)
	record1(t, "S03", "ed25519", "artifact replaced and re-signed, old SBOM", "SBOM_MISMATCH", 1, e.check())
}

// SBOM ditandatangani kunci yang tidak ada di trust store.
func TestS04SBOMUntrustedKey(t *testing.T) {
	e := newEnv(t, "ed25519")
	other := e.p("other")
	must(t, "keygen", "--algorithm", "ed25519", "--out", other)
	must(t, "sbom", "sign", "--force", "--sbom", e.sbomPath, "--package", pkgName, "--version", version,
		"--key", other+".key.pem", "--out", e.sbomBndl)
	record1(t, "S04", "ed25519", "SBOM signed by a key outside the trust store", "KEY_NOT_TRUSTED", 1, e.check())
}

// SBOM tanpa hash SHA-256 ditolak saat sign.
func TestS05SBOMWithoutHash(t *testing.T) {
	e := newEnv(t, "ed25519")
	bad := e.p("nohash.cdx.json")
	doc := `{"bomFormat":"CycloneDX","specVersion":"1.6","version":1,"metadata":{"component":{"type":"application","name":"demo-app","version":"1.0.0"}},"components":[]}`
	if err := os.WriteFile(bad, []byte(doc), 0o644); err != nil {
		t.Fatal(err)
	}
	r := run("sbom", "sign", "--sbom", bad, "--package", pkgName, "--version", version,
		"--key", e.keyPath, "--out", e.p("nohash.bundle.json"))
	want := 2
	result := "PASS"
	if r.Exit != want {
		result = "FAIL"
		t.Errorf("S05: want exit %d, got %d\nstderr: %s", want, r.Exit, r.Stderr)
	}
	if _, err := os.Stat(e.p("nohash.bundle.json")); err == nil {
		result = "FAIL"
		t.Errorf("S05: bundle was written for an SBOM without hash")
	}
	mu.Lock()
	records = append(records, record{"S05", "ed25519", "sbom sign without SHA-256 hash", "(exit 2, no bundle)", want, "", r.Exit, result})
	mu.Unlock()
}

// Tambahan: rilis diubah setelah sign, SBOM sah. Berhenti di verify rilis.
func TestReleaseTamperedStopsFirst(t *testing.T) {
	e := newEnv(t, "ed25519")
	if err := os.WriteFile(e.artifact, []byte("isi artefak rilis versi satu!\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	record1(t, "S06", "ed25519", "release artifact changed after sign", "ARTIFACT_MISMATCH", 1, e.check())
}

// Tambahan: SBOM milik versi lain tidak lolos walau signature sah.
func TestSBOMVersionMismatch(t *testing.T) {
	e := newEnv(t, "ed25519")
	other := e.p("sbom-v2.cdx.json")
	must(t, "sbom", "generate", "--file", e.artifact, "--package", pkgName, "--version", "2.0.0", "--out", other)
	must(t, "sbom", "sign", "--force", "--sbom", other, "--package", pkgName, "--version", version,
		"--key", e.keyPath, "--out", e.sbomBndl)
	e.sbomPath = other
	record1(t, "S07", "ed25519", "SBOM contains version 2.0.0, verified as 1.0.0", "SBOM_MISMATCH", 1, e.check())
}

// Tambahan: flag wajib hilang menghasilkan INPUT_ERROR dan exit 2.
func TestCheckMissingFlag(t *testing.T) {
	r := run("sbom", "check", "--json")
	record1(t, "S08", "-", "sbom check without required flags", "INPUT_ERROR", 2, r)
}

// Tambahan: sbom verify berdiri sendiri.
func TestSBOMVerifyStandalone(t *testing.T) {
	e := newEnv(t, "ecdsa-p256-sha256")
	r := run("sbom", "verify", "--sbom", e.sbomPath, "--bundle", e.sbomBndl,
		"--trust-store", e.trust, "--package", pkgName, "--version", version, "--json")
	record1(t, "S09", "ecdsa-p256-sha256", "standalone sbom verify", "OK", 0, r)
}

func writeResults(dir string) {
	mu.Lock()
	defer mu.Unlock()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return
	}
	var b strings.Builder
	b.WriteString("# SBOM test results (S01 to S09)\n\n")
	b.WriteString("| ID | Profile | Input | Expected | Exit | Actual | Exit | Result |\n")
	b.WriteString("|---|---|---|---|---|---|---|---|\n")
	for _, r := range sorted() {
		fmt.Fprintf(&b, "| %s | %s | %s | %s | %d | %s | %d | %s |\n",
			r.ID, r.Profile, r.Input, r.ExpectedStatus, r.ExpectedExit, r.ActualStatus, r.ActualExit, r.Result)
	}
	_ = os.WriteFile(filepath.Join(dir, "results.md"), []byte(b.String()), 0o644)
	if js, err := json.MarshalIndent(sorted(), "", "  "); err == nil {
		_ = os.WriteFile(filepath.Join(dir, "results.json"), append(js, '\n'), 0o644)
	}
}

func sorted() []record {
	out := append([]record(nil), records...)
	for i := 1; i < len(out); i++ {
		for j := i; j > 0 && (out[j-1].ID > out[j].ID || (out[j-1].ID == out[j].ID && out[j-1].Profile > out[j].Profile)); j-- {
			out[j-1], out[j] = out[j], out[j-1]
		}
	}
	return out
}
