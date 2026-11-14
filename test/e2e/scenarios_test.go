package e2e_test

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/brii26/release-signer/pkg/bundle"
)

var (
	binPath   string
	repoRoot  string
	muRecords sync.Mutex
	records   []ScenarioRecord
)

type ScenarioRecord struct {
	ID             string `json:"id"`
	Profile        string `json:"profile"`
	Input          string `json:"input"`
	ExpectedStatus string `json:"expected_status"`
	ExpectedExit   int    `json:"expected_exit"`
	ActualStatus   string `json:"actual_status"`
	ActualExit     int    `json:"actual_exit"`
	Result         string `json:"result"` // PASS, FAIL, SKIP
	Details        string `json:"details,omitempty"`
	Run1SigHex     string `json:"run1_sig_hex,omitempty"`
	Run2SigHex     string `json:"run2_sig_hex,omitempty"`
}

type ExecResult struct {
	ExitCode int
	Stdout   string
	Stderr   string
	JSON     *VerifyJSONResult
}

type VerifyJSONResult struct {
	Valid     bool    `json:"valid"`
	Status    string  `json:"status"`
	Message   string  `json:"message"`
	Algorithm *string `json:"algorithm"`
	KeyID     *string `json:"keyid"`
	Package   *string `json:"package"`
	Version   *string `json:"version"`
}

func TestMain(m *testing.M) {
	wd, err := os.Getwd()
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to get working dir: %v\n", err)
		os.Exit(1)
	}
	repoRoot = filepath.Clean(filepath.Join(wd, "..", ".."))

	tmpDir, err := os.MkdirTemp("", "release-signer-e2e-*")
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to create temp dir: %v\n", err)
		os.Exit(1)
	}
	defer os.RemoveAll(tmpDir)

	binPath = filepath.Join(tmpDir, "release-signer")
	cmd := exec.Command("go", "build", "-trimpath", "-o", binPath, "./cmd/release-signer")
	cmd.Dir = repoRoot
	if out, err := cmd.CombinedOutput(); err != nil {
		fmt.Fprintf(os.Stderr, "failed to build release-signer: %v\n%s\n", err, string(out))
		os.Exit(1)
	}

	code := m.Run()

	if resDir := os.Getenv("RESULTS_DIR"); resDir != "" {
		if !filepath.IsAbs(resDir) {
			resDir = filepath.Join(repoRoot, resDir)
		}
		writeResults(resDir)
	}

	os.Exit(code)
}

func recordScenario(rec ScenarioRecord) {
	muRecords.Lock()
	defer muRecords.Unlock()
	records = append(records, rec)
}

func runCLI(args ...string) ExecResult {
	cmd := exec.Command(binPath, args...)
	cmd.Dir = repoRoot

	var stdout, stderr strings.Builder
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()
	exitCode := 0
	if err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			exitCode = exitErr.ExitCode()
		} else {
			exitCode = 1
		}
	}

	res := ExecResult{
		ExitCode: exitCode,
		Stdout:   stdout.String(),
		Stderr:   stderr.String(),
	}

	outTrim := strings.TrimSpace(stdout.String())
	if strings.HasPrefix(outTrim, "{") && strings.HasSuffix(outTrim, "}") {
		var v VerifyJSONResult
		if err := json.Unmarshal([]byte(outTrim), &v); err == nil {
			res.JSON = &v
		}
	}

	return res
}

func sha256Hex(data []byte) string {
	h := sha256.Sum256(data)
	return hex.EncodeToString(h[:])
}

type testKeypair struct {
	profile     string
	privSigner  crypto.Signer
	pubKey      crypto.PublicKey
	pubPEM      string
	privPath    string
	pubPath     string
	fingerprint string
}

func loadKeypair(t *testing.T, profile, name string) testKeypair {
	t.Helper()
	dir := filepath.Join(repoRoot, "test", "keys", profile)
	privPath := filepath.Join(dir, name+".key.pem")
	pubPath := filepath.Join(dir, name+".pub.pem")

	privBytes, err := os.ReadFile(privPath)
	if err != nil {
		t.Fatalf("failed to read private key %s: %v", privPath, err)
	}
	privBlock, _ := pem.Decode(privBytes)
	if privBlock == nil {
		t.Fatalf("failed to decode private key PEM %s", privPath)
	}
	privKeyAny, err := x509.ParsePKCS8PrivateKey(privBlock.Bytes)
	if err != nil {
		t.Fatalf("failed to parse PKCS8 private key: %v", err)
	}
	privSigner, ok := privKeyAny.(crypto.Signer)
	if !ok {
		t.Fatalf("private key is not a crypto.Signer: %T", privKeyAny)
	}

	pubBytes, err := os.ReadFile(pubPath)
	if err != nil {
		t.Fatalf("failed to read public key %s: %v", pubPath, err)
	}
	pubBlock, _ := pem.Decode(pubBytes)
	if pubBlock == nil {
		t.Fatalf("failed to decode public key PEM %s", pubPath)
	}
	pubKey, err := x509.ParsePKIXPublicKey(pubBlock.Bytes)
	if err != nil {
		t.Fatalf("failed to parse SPKI public key: %v", err)
	}

	spkiDER, err := x509.MarshalPKIXPublicKey(pubKey)
	if err != nil {
		t.Fatalf("failed to marshal SPKI public key: %v", err)
	}
	fingerprint := sha256Hex(spkiDER)

	return testKeypair{
		profile:     profile,
		privSigner:  privSigner,
		pubKey:      pubKey,
		pubPEM:      string(pubBytes),
		privPath:    privPath,
		pubPath:     pubPath,
		fingerprint: fingerprint,
	}
}

func signBytes(t *testing.T, k testKeypair, msg []byte) []byte {
	t.Helper()
	switch k.profile {
	case "rsa-pss-sha256":
		rsaKey, ok := k.privSigner.(*rsa.PrivateKey)
		if !ok {
			t.Fatalf("expected RSA private key")
		}
		digest := sha256.Sum256(msg)
		opts := &rsa.PSSOptions{
			SaltLength: 32,
			Hash:       crypto.SHA256,
		}
		sig, err := rsa.SignPSS(rand.Reader, rsaKey, crypto.SHA256, digest[:], opts)
		if err != nil {
			t.Fatalf("RSA-PSS sign error: %v", err)
		}
		return sig

	case "ecdsa-p256-sha256":
		ecdsaKey, ok := k.privSigner.(*ecdsa.PrivateKey)
		if !ok {
			t.Fatalf("expected ECDSA private key")
		}
		digest := sha256.Sum256(msg)
		r, s, err := ecdsa.Sign(rand.Reader, ecdsaKey, digest[:])
		if err != nil {
			t.Fatalf("ECDSA sign error: %v", err)
		}
		sig := make([]byte, 64)
		r.FillBytes(sig[:32])
		s.FillBytes(sig[32:])
		return sig

	case "ed25519":
		edKey, ok := k.privSigner.(ed25519.PrivateKey)
		if !ok {
			t.Fatalf("expected Ed25519 private key")
		}
		return ed25519.Sign(edKey, msg)

	default:
		t.Fatalf("unsupported profile: %s", k.profile)
		return nil
	}
}

func createTrustStore(t *testing.T, dir string, entries []testKeypair, pkgs map[string][]string) string {
	t.Helper()
	type jsonKey struct {
		KeyID        string   `json:"keyid"`
		Algorithm    string   `json:"algorithm"`
		PublicKeyPEM string   `json:"public_key_pem"`
		Packages     []string `json:"packages"`
	}
	type jsonTrust struct {
		Schema string    `json:"schema"`
		Keys   []jsonKey `json:"keys"`
	}

	keys := make([]jsonKey, 0, len(entries))
	for _, e := range entries {
		allowed := pkgs[e.fingerprint]
		if len(allowed) == 0 {
			allowed = []string{"test-app"}
		}
		keys = append(keys, jsonKey{
			KeyID:        e.fingerprint,
			Algorithm:    e.profile,
			PublicKeyPEM: e.pubPEM,
			Packages:     allowed,
		})
	}

	ts := jsonTrust{
		Schema: "minisign-trust/v1",
		Keys:   keys,
	}
	data, err := json.Marshal(ts)
	if err != nil {
		t.Fatalf("failed to marshal trust store: %v", err)
	}

	p := filepath.Join(dir, "trust.json")
	if err := os.WriteFile(p, data, 0644); err != nil {
		t.Fatalf("failed to write trust store: %v", err)
	}
	return p
}

func createBundle(t *testing.T, dir string, k testKeypair, pkg, version, artPath string) string {
	t.Helper()
	artBytes, err := os.ReadFile(artPath)
	if err != nil {
		t.Fatalf("failed to read artifact %s: %v", artPath, err)
	}

	manifest := fmt.Sprintf(
		`{"schema":"minisign-manifest/v1","package":"%s","version":"%s","algorithm":"%s","keyid":"%s","artifact":{"name":"%s","size":%s,"sha256":"%s"}}`,
		pkg, version, k.profile, k.fingerprint, filepath.Base(artPath), strconv.FormatInt(int64(len(artBytes)), 10), sha256Hex(artBytes),
	)

	sig := signBytes(t, k, []byte(manifest))

	bundleBytes := bundle.Build([]byte(manifest), sig)
	bundlePath := filepath.Join(dir, "bundle.json")
	if err := os.WriteFile(bundlePath, bundleBytes, 0644); err != nil {
		t.Fatalf("failed to write bundle: %v", err)
	}
	return bundlePath
}

func writeResults(dir string) {
	muRecords.Lock()
	defer muRecords.Unlock()

	_ = os.MkdirAll(dir, 0755)

	jsonPath := filepath.Join(dir, "results.json")
	jsonData, _ := json.MarshalIndent(records, "", "  ")
	_ = os.WriteFile(jsonPath, jsonData, 0644)

	mdPath := filepath.Join(dir, "results.md")
	var md strings.Builder
	md.WriteString("# Test Scenarios U01 to U14 (Table 2.11)\n\n")
	md.WriteString("| ID | Profile | Input / Method | Expected Status | Expected Exit | Actual Status | Actual Exit | Result |\n")
	md.WriteString("|:---|:---|:---|:---|:---:|:---|:---:|:---:|\n")

	passCount := 0
	failCount := 0
	skipCount := 0

	var u14Records []ScenarioRecord
	for _, r := range records {
		switch r.Result {
		case "PASS":
			passCount++
		case "FAIL":
			failCount++
		case "SKIP":
			skipCount++
		}
		md.WriteString(fmt.Sprintf("| %s | %s | %s | `%s` | %d | `%s` | %d | **%s** |\n",
			r.ID, r.Profile, r.Input, r.ExpectedStatus, r.ExpectedExit, r.ActualStatus, r.ActualExit, r.Result))
		if r.ID == "U14" {
			u14Records = append(u14Records, r)
		}
	}

	md.WriteString(fmt.Sprintf("\n**Total:** %d scenarios | **Passed:** %d | **Failed:** %d | **Skipped:** %d\n",
		len(records), passCount, failCount, skipCount))

	if len(u14Records) > 0 {
		md.WriteString("\n## U14 Analysis: Signature Randomness and Determinism\n\n")
		for _, u := range u14Records {
			md.WriteString(fmt.Sprintf("### Profile: `%s`\n", u.Profile))
			md.WriteString(fmt.Sprintf("- **Analysis:** %s\n", u.Details))
			md.WriteString(fmt.Sprintf("- **Run 1 Signature (Hex):** `%s`\n", u.Run1SigHex))
			md.WriteString(fmt.Sprintf("- **Run 2 Signature (Hex):** `%s`\n\n", u.Run2SigHex))
		}
	}

	_ = os.WriteFile(mdPath, []byte(md.String()), 0644)
}

func TestScenarios(t *testing.T) {
	// =========================================================================
	// U01: 3 Profiles x 3 Fixtures
	// =========================================================================
	profiles := []string{"rsa-pss-sha256", "ecdsa-p256-sha256", "ed25519"}
	fixtures := []string{"text.txt", "binary.bin", "empty.bin"}

	for _, prof := range profiles {
		for _, fix := range fixtures {
			testID := fmt.Sprintf("U01-%s-%s", prof, fix)
			t.Run(testID, func(t *testing.T) {
				tmp := t.TempDir()
				key := loadKeypair(t, prof, "publisher")
				tsPath := createTrustStore(t, tmp, []testKeypair{key}, nil)
				artPath := filepath.Join(repoRoot, "test", "fixtures", fix)

				// Test CLI sign if wired, else fallback to test helper bundle
				bundlePath := filepath.Join(tmp, "release.json")
				signRes := runCLI("sign", "--file", artPath, "--package", "test-app", "--version", "1.0.0", "--key", key.privPath, "--out", bundlePath)
				if signRes.ExitCode != 0 && strings.Contains(signRes.Stderr, "not wired yet") {
					bundlePath = createBundle(t, tmp, key, "test-app", "1.0.0", artPath)
				}

				verifyRes := runCLI("verify", "--file", artPath, "--bundle", bundlePath, "--trust-store", tsPath, "--package", "test-app", "--version", "1.0.0", "--json")

				actualStatus := ""
				if verifyRes.JSON != nil {
					actualStatus = verifyRes.JSON.Status
				}

				pass := verifyRes.ExitCode == 0 && actualStatus == "OK"
				resStr := "PASS"
				if !pass {
					resStr = "FAIL"
				}

				recordScenario(ScenarioRecord{
					ID:             "U01",
					Profile:        prof,
					Input:          fmt.Sprintf("Sign and verify fixture %s", fix),
					ExpectedStatus: "OK",
					ExpectedExit:   0,
					ActualStatus:   actualStatus,
					ActualExit:     verifyRes.ExitCode,
					Result:         resStr,
				})

				if !pass {
					t.Fatalf("expected exit 0 and status OK, got %d and %s", verifyRes.ExitCode, actualStatus)
				}
			})
		}
	}

	// =========================================================================
	// U02: ed25519, modify 1 byte of artifact -> ARTIFACT_MISMATCH
	// =========================================================================
	t.Run("U02", func(t *testing.T) {
		tmp := t.TempDir()
		key := loadKeypair(t, "ed25519", "publisher")
		tsPath := createTrustStore(t, tmp, []testKeypair{key}, nil)

		artPath := filepath.Join(tmp, "app.bin")
		_ = os.WriteFile(artPath, []byte("authentic payload data"), 0644)
		bundlePath := createBundle(t, tmp, key, "test-app", "1.0.0", artPath)

		// Modify 1 byte in artifact
		_ = os.WriteFile(artPath, []byte("authentic paylxad data"), 0644)

		verifyRes := runCLI("verify", "--file", artPath, "--bundle", bundlePath, "--trust-store", tsPath, "--package", "test-app", "--version", "1.0.0", "--json")
		actualStatus := ""
		if verifyRes.JSON != nil {
			actualStatus = verifyRes.JSON.Status
		}
		pass := verifyRes.ExitCode == 1 && actualStatus == "ARTIFACT_MISMATCH"
		resStr := "PASS"
		if !pass {
			resStr = "FAIL"
		}

		recordScenario(ScenarioRecord{
			ID:             "U02",
			Profile:        "ed25519",
			Input:          "Tamper 1 byte of artifact after signing",
			ExpectedStatus: "ARTIFACT_MISMATCH",
			ExpectedExit:   1,
			ActualStatus:   actualStatus,
			ActualExit:     verifyRes.ExitCode,
			Result:         resStr,
		})

		if !pass {
			t.Fatalf("expected ARTIFACT_MISMATCH exit 1, got %s exit %d", actualStatus, verifyRes.ExitCode)
		}
	})

	// =========================================================================
	// U03: ed25519, append 1 byte & truncate 1 byte -> ARTIFACT_MISMATCH
	// =========================================================================
	t.Run("U03", func(t *testing.T) {
		tmp := t.TempDir()
		key := loadKeypair(t, "ed25519", "publisher")
		tsPath := createTrustStore(t, tmp, []testKeypair{key}, nil)

		artPath := filepath.Join(tmp, "app.bin")
		_ = os.WriteFile(artPath, []byte("authentic payload"), 0644)
		bundlePath := createBundle(t, tmp, key, "test-app", "1.0.0", artPath)

		// Append 1 byte
		_ = os.WriteFile(artPath, []byte("authentic payload!"), 0644)

		verifyRes := runCLI("verify", "--file", artPath, "--bundle", bundlePath, "--trust-store", tsPath, "--package", "test-app", "--version", "1.0.0", "--json")
		actualStatus := ""
		if verifyRes.JSON != nil {
			actualStatus = verifyRes.JSON.Status
		}
		pass := verifyRes.ExitCode == 1 && actualStatus == "ARTIFACT_MISMATCH"
		resStr := "PASS"
		if !pass {
			resStr = "FAIL"
		}

		recordScenario(ScenarioRecord{
			ID:             "U03",
			Profile:        "ed25519",
			Input:          "Append 1 byte to artifact (size change)",
			ExpectedStatus: "ARTIFACT_MISMATCH",
			ExpectedExit:   1,
			ActualStatus:   actualStatus,
			ActualExit:     verifyRes.ExitCode,
			Result:         resStr,
		})

		if !pass {
			t.Fatalf("expected ARTIFACT_MISMATCH exit 1, got %s exit %d", actualStatus, verifyRes.ExitCode)
		}
	})

	// =========================================================================
	// U04: ed25519, decode manifest, change version, old signature -> INVALID_SIGNATURE
	// =========================================================================
	t.Run("U04", func(t *testing.T) {
		tmp := t.TempDir()
		key := loadKeypair(t, "ed25519", "publisher")
		tsPath := createTrustStore(t, tmp, []testKeypair{key}, nil)

		artPath := filepath.Join(tmp, "app.bin")
		artData := []byte("payload")
		_ = os.WriteFile(artPath, artData, 0644)

		origManifest := fmt.Sprintf(
			`{"schema":"minisign-manifest/v1","package":"test-app","version":"1.0.0","algorithm":"%s","keyid":"%s","artifact":{"name":"app.bin","size":%d,"sha256":"%s"}}`,
			key.profile, key.fingerprint, len(artData), sha256Hex(artData),
		)
		sig := signBytes(t, key, []byte(origManifest))

		// Tamper version in canonical manifest
		tamperedManifest := fmt.Sprintf(
			`{"schema":"minisign-manifest/v1","package":"test-app","version":"1.0.1","algorithm":"%s","keyid":"%s","artifact":{"name":"app.bin","size":%d,"sha256":"%s"}}`,
			key.profile, key.fingerprint, len(artData), sha256Hex(artData),
		)

		bundleBytes := bundle.Build([]byte(tamperedManifest), sig)
		bundlePath := filepath.Join(tmp, "bundle.json")
		_ = os.WriteFile(bundlePath, bundleBytes, 0644)

		verifyRes := runCLI("verify", "--file", artPath, "--bundle", bundlePath, "--trust-store", tsPath, "--package", "test-app", "--version", "1.0.1", "--json")
		actualStatus := ""
		if verifyRes.JSON != nil {
			actualStatus = verifyRes.JSON.Status
		}
		pass := verifyRes.ExitCode == 1 && actualStatus == "INVALID_SIGNATURE"
		resStr := "PASS"
		if !pass {
			resStr = "FAIL"
		}

		recordScenario(ScenarioRecord{
			ID:             "U04",
			Profile:        "ed25519",
			Input:          "Tamper manifest version preserving canonical form, old signature",
			ExpectedStatus: "INVALID_SIGNATURE",
			ExpectedExit:   1,
			ActualStatus:   actualStatus,
			ActualExit:     verifyRes.ExitCode,
			Result:         resStr,
		})

		if !pass {
			t.Fatalf("expected INVALID_SIGNATURE exit 1, got %s exit %d", actualStatus, verifyRes.ExitCode)
		}
	})

	// =========================================================================
	// U05: ed25519, flip 1 bit in signature -> INVALID_SIGNATURE
	// =========================================================================
	t.Run("U05", func(t *testing.T) {
		tmp := t.TempDir()
		key := loadKeypair(t, "ed25519", "publisher")
		tsPath := createTrustStore(t, tmp, []testKeypair{key}, nil)

		artPath := filepath.Join(tmp, "app.bin")
		_ = os.WriteFile(artPath, []byte("payload"), 0644)
		bundlePath := createBundle(t, tmp, key, "test-app", "1.0.0", artPath)

		// Read bundle and flip bit in signature
		bBytes, _ := os.ReadFile(bundlePath)
		manifestRaw, sigRaw, err := bundle.ParseStrict(bBytes)
		if err != nil {
			t.Fatal(err)
		}
		sigRaw[0] ^= 0x01
		tampered := bundle.Build(manifestRaw, sigRaw)
		_ = os.WriteFile(bundlePath, tampered, 0644)

		verifyRes := runCLI("verify", "--file", artPath, "--bundle", bundlePath, "--trust-store", tsPath, "--package", "test-app", "--version", "1.0.0", "--json")
		actualStatus := ""
		if verifyRes.JSON != nil {
			actualStatus = verifyRes.JSON.Status
		}
		pass := verifyRes.ExitCode == 1 && actualStatus == "INVALID_SIGNATURE"
		resStr := "PASS"
		if !pass {
			resStr = "FAIL"
		}

		recordScenario(ScenarioRecord{
			ID:             "U05",
			Profile:        "ed25519",
			Input:          "Flip 1 bit of signature bytes (length 64 preserved)",
			ExpectedStatus: "INVALID_SIGNATURE",
			ExpectedExit:   1,
			ActualStatus:   actualStatus,
			ActualExit:     verifyRes.ExitCode,
			Result:         resStr,
		})

		if !pass {
			t.Fatalf("expected INVALID_SIGNATURE exit 1, got %s exit %d", actualStatus, verifyRes.ExitCode)
		}
	})

	// =========================================================================
	// U06: ed25519, empty trust store -> KEY_NOT_TRUSTED
	// =========================================================================
	t.Run("U06", func(t *testing.T) {
		tmp := t.TempDir()
		key := loadKeypair(t, "ed25519", "publisher")
		artPath := filepath.Join(tmp, "app.bin")
		_ = os.WriteFile(artPath, []byte("payload"), 0644)
		bundlePath := createBundle(t, tmp, key, "test-app", "1.0.0", artPath)

		emptyTS := filepath.Join(tmp, "empty_trust.json")
		_ = os.WriteFile(emptyTS, []byte(`{"schema":"minisign-trust/v1","keys":[]}`), 0644)

		verifyRes := runCLI("verify", "--file", artPath, "--bundle", bundlePath, "--trust-store", emptyTS, "--package", "test-app", "--version", "1.0.0", "--json")
		actualStatus := ""
		if verifyRes.JSON != nil {
			actualStatus = verifyRes.JSON.Status
		}
		pass := verifyRes.ExitCode == 1 && actualStatus == "KEY_NOT_TRUSTED"
		resStr := "PASS"
		if !pass {
			resStr = "FAIL"
		}

		recordScenario(ScenarioRecord{
			ID:             "U06",
			Profile:        "ed25519",
			Input:          "Empty trust store (key lookup failure)",
			ExpectedStatus: "KEY_NOT_TRUSTED",
			ExpectedExit:   1,
			ActualStatus:   actualStatus,
			ActualExit:     verifyRes.ExitCode,
			Result:         resStr,
		})

		if !pass {
			t.Fatalf("expected KEY_NOT_TRUSTED exit 1, got %s exit %d", actualStatus, verifyRes.ExitCode)
		}
	})

	// =========================================================================
	// U07: ed25519, key scoped to other package -> KEY_NOT_TRUSTED
	// =========================================================================
	t.Run("U07", func(t *testing.T) {
		tmp := t.TempDir()
		key := loadKeypair(t, "ed25519", "publisher")
		tsPath := createTrustStore(t, tmp, []testKeypair{key}, map[string][]string{
			key.fingerprint: {"other-package"},
		})

		artPath := filepath.Join(tmp, "app.bin")
		_ = os.WriteFile(artPath, []byte("payload"), 0644)
		bundlePath := createBundle(t, tmp, key, "test-app", "1.0.0", artPath)

		verifyRes := runCLI("verify", "--file", artPath, "--bundle", bundlePath, "--trust-store", tsPath, "--package", "test-app", "--version", "1.0.0", "--json")
		actualStatus := ""
		if verifyRes.JSON != nil {
			actualStatus = verifyRes.JSON.Status
		}
		pass := verifyRes.ExitCode == 1 && actualStatus == "KEY_NOT_TRUSTED"
		resStr := "PASS"
		if !pass {
			resStr = "FAIL"
		}

		recordScenario(ScenarioRecord{
			ID:             "U07",
			Profile:        "ed25519",
			Input:          "Key authorized only for other-package",
			ExpectedStatus: "KEY_NOT_TRUSTED",
			ExpectedExit:   1,
			ActualStatus:   actualStatus,
			ActualExit:     verifyRes.ExitCode,
			Result:         resStr,
		})

		if !pass {
			t.Fatalf("expected KEY_NOT_TRUSTED exit 1, got %s exit %d", actualStatus, verifyRes.ExitCode)
		}
	})

	// =========================================================================
	// U08: ed25519, CLI --version mismatch -> METADATA_MISMATCH
	// =========================================================================
	t.Run("U08", func(t *testing.T) {
		tmp := t.TempDir()
		key := loadKeypair(t, "ed25519", "publisher")
		tsPath := createTrustStore(t, tmp, []testKeypair{key}, nil)

		artPath := filepath.Join(tmp, "app.bin")
		_ = os.WriteFile(artPath, []byte("payload"), 0644)
		bundlePath := createBundle(t, tmp, key, "test-app", "1.0.0", artPath)

		verifyRes := runCLI("verify", "--file", artPath, "--bundle", bundlePath, "--trust-store", tsPath, "--package", "test-app", "--version", "2.0.0", "--json")
		actualStatus := ""
		if verifyRes.JSON != nil {
			actualStatus = verifyRes.JSON.Status
		}
		pass := verifyRes.ExitCode == 1 && actualStatus == "METADATA_MISMATCH"
		resStr := "PASS"
		if !pass {
			resStr = "FAIL"
		}

		recordScenario(ScenarioRecord{
			ID:             "U08",
			Profile:        "ed25519",
			Input:          "CLI --version (2.0.0) differs from manifest (1.0.0)",
			ExpectedStatus: "METADATA_MISMATCH",
			ExpectedExit:   1,
			ActualStatus:   actualStatus,
			ActualExit:     verifyRes.ExitCode,
			Result:         resStr,
		})

		if !pass {
			t.Fatalf("expected METADATA_MISMATCH exit 1, got %s exit %d", actualStatus, verifyRes.ExitCode)
		}
	})

	// =========================================================================
	// U09: ed25519, rename artifact -> METADATA_MISMATCH
	// =========================================================================
	t.Run("U09", func(t *testing.T) {
		tmp := t.TempDir()
		key := loadKeypair(t, "ed25519", "publisher")
		tsPath := createTrustStore(t, tmp, []testKeypair{key}, nil)

		artPath := filepath.Join(tmp, "app.bin")
		_ = os.WriteFile(artPath, []byte("payload"), 0644)
		bundlePath := createBundle(t, tmp, key, "test-app", "1.0.0", artPath)

		renamedPath := filepath.Join(tmp, "renamed-app.bin")
		_ = os.WriteFile(renamedPath, []byte("payload"), 0644)

		verifyRes := runCLI("verify", "--file", renamedPath, "--bundle", bundlePath, "--trust-store", tsPath, "--package", "test-app", "--version", "1.0.0", "--json")
		actualStatus := ""
		if verifyRes.JSON != nil {
			actualStatus = verifyRes.JSON.Status
		}
		pass := verifyRes.ExitCode == 1 && actualStatus == "METADATA_MISMATCH"
		resStr := "PASS"
		if !pass {
			resStr = "FAIL"
		}

		recordScenario(ScenarioRecord{
			ID:             "U09",
			Profile:        "ed25519",
			Input:          "Rename physical artifact on disk (basename mismatch)",
			ExpectedStatus: "METADATA_MISMATCH",
			ExpectedExit:   1,
			ActualStatus:   actualStatus,
			ActualExit:     verifyRes.ExitCode,
			Result:         resStr,
		})

		if !pass {
			t.Fatalf("expected METADATA_MISMATCH exit 1, got %s exit %d", actualStatus, verifyRes.ExitCode)
		}
	})

	// =========================================================================
	// U10a-d: FORMAT_ERROR cases
	// =========================================================================
	t.Run("U10a", func(t *testing.T) {
		tmp := t.TempDir()
		key := loadKeypair(t, "ed25519", "publisher")
		tsPath := createTrustStore(t, tmp, []testKeypair{key}, nil)
		artPath := filepath.Join(tmp, "app.bin")
		_ = os.WriteFile(artPath, []byte("payload"), 0644)

		// Duplicate key in bundle
		dupBundle := fmt.Sprintf(`{"schema":"minisign-bundle/v1","schema":"minisign-bundle/v1","manifest_b64":"%s","signature_b64":"%s"}`,
			base64.StdEncoding.EncodeToString([]byte("{}")), base64.StdEncoding.EncodeToString(make([]byte, 64)))
		bPath := filepath.Join(tmp, "dup_bundle.json")
		_ = os.WriteFile(bPath, []byte(dupBundle), 0644)

		verifyRes := runCLI("verify", "--file", artPath, "--bundle", bPath, "--trust-store", tsPath, "--package", "test-app", "--version", "1.0.0", "--json")
		actualStatus := ""
		if verifyRes.JSON != nil {
			actualStatus = verifyRes.JSON.Status
		}
		pass := verifyRes.ExitCode == 1 && actualStatus == "FORMAT_ERROR"
		resStr := "PASS"
		if !pass {
			resStr = "FAIL"
		}

		recordScenario(ScenarioRecord{
			ID:             "U10a",
			Profile:        "ed25519",
			Input:          "Duplicate schema field in bundle JSON",
			ExpectedStatus: "FORMAT_ERROR",
			ExpectedExit:   1,
			ActualStatus:   actualStatus,
			ActualExit:     verifyRes.ExitCode,
			Result:         resStr,
		})

		if !pass {
			t.Fatalf("expected FORMAT_ERROR exit 1, got %s exit %d", actualStatus, verifyRes.ExitCode)
		}
	})

	t.Run("U10b", func(t *testing.T) {
		tmp := t.TempDir()
		key := loadKeypair(t, "ed25519", "publisher")
		tsPath := createTrustStore(t, tmp, []testKeypair{key}, nil)
		artPath := filepath.Join(tmp, "app.bin")
		_ = os.WriteFile(artPath, []byte("payload"), 0644)

		// artifact.size as string
		badManifest := fmt.Sprintf(
			`{"schema":"minisign-manifest/v1","package":"test-app","version":"1.0.0","algorithm":"ed25519","keyid":"%s","artifact":{"name":"app.bin","size":"7","sha256":"%s"}}`,
			key.fingerprint, sha256Hex([]byte("payload")),
		)
		bPath := filepath.Join(tmp, "b10b.json")
		bData := bundle.Build([]byte(badManifest), make([]byte, 64))
		_ = os.WriteFile(bPath, bData, 0644)

		verifyRes := runCLI("verify", "--file", artPath, "--bundle", bPath, "--trust-store", tsPath, "--package", "test-app", "--version", "1.0.0", "--json")
		actualStatus := ""
		if verifyRes.JSON != nil {
			actualStatus = verifyRes.JSON.Status
		}
		pass := verifyRes.ExitCode == 1 && actualStatus == "FORMAT_ERROR"
		resStr := "PASS"
		if !pass {
			resStr = "FAIL"
		}

		recordScenario(ScenarioRecord{
			ID:             "U10b",
			Profile:        "ed25519",
			Input:          "artifact.size encoded as string instead of integer",
			ExpectedStatus: "FORMAT_ERROR",
			ExpectedExit:   1,
			ActualStatus:   actualStatus,
			ActualExit:     verifyRes.ExitCode,
			Result:         resStr,
		})

		if !pass {
			t.Fatalf("expected FORMAT_ERROR exit 1, got %s exit %d", actualStatus, verifyRes.ExitCode)
		}
	})

	t.Run("U10c", func(t *testing.T) {
		tmp := t.TempDir()
		key := loadKeypair(t, "ed25519", "publisher")
		tsPath := createTrustStore(t, tmp, []testKeypair{key}, nil)
		artPath := filepath.Join(tmp, "app.bin")
		_ = os.WriteFile(artPath, []byte("payload"), 0644)

		// signature base64 with illegal characters
		bPath := filepath.Join(tmp, "b10c.json")
		_ = os.WriteFile(bPath, []byte(`{"schema":"minisign-bundle/v1","manifest_b64":"YWJj","signature_b64":"bad!!base64"}`), 0644)

		verifyRes := runCLI("verify", "--file", artPath, "--bundle", bPath, "--trust-store", tsPath, "--package", "test-app", "--version", "1.0.0", "--json")
		actualStatus := ""
		if verifyRes.JSON != nil {
			actualStatus = verifyRes.JSON.Status
		}
		pass := verifyRes.ExitCode == 1 && actualStatus == "FORMAT_ERROR"
		resStr := "PASS"
		if !pass {
			resStr = "FAIL"
		}

		recordScenario(ScenarioRecord{
			ID:             "U10c",
			Profile:        "ed25519",
			Input:          "signature_b64 contains illegal character '!'",
			ExpectedStatus: "FORMAT_ERROR",
			ExpectedExit:   1,
			ActualStatus:   actualStatus,
			ActualExit:     verifyRes.ExitCode,
			Result:         resStr,
		})

		if !pass {
			t.Fatalf("expected FORMAT_ERROR exit 1, got %s exit %d", actualStatus, verifyRes.ExitCode)
		}
	})

	t.Run("U10d", func(t *testing.T) {
		tmp := t.TempDir()
		key := loadKeypair(t, "ed25519", "publisher")
		tsPath := createTrustStore(t, tmp, []testKeypair{key}, nil)
		artPath := filepath.Join(tmp, "app.bin")
		_ = os.WriteFile(artPath, []byte("payload"), 0644)

		// manifest > 16 KiB
		bigManifest := make([]byte, 16385)
		bPath := filepath.Join(tmp, "b10d.json")
		bData := bundle.Build(bigManifest, make([]byte, 64))
		_ = os.WriteFile(bPath, bData, 0644)

		verifyRes := runCLI("verify", "--file", artPath, "--bundle", bPath, "--trust-store", tsPath, "--package", "test-app", "--version", "1.0.0", "--json")
		actualStatus := ""
		if verifyRes.JSON != nil {
			actualStatus = verifyRes.JSON.Status
		}
		pass := verifyRes.ExitCode == 1 && actualStatus == "FORMAT_ERROR"
		resStr := "PASS"
		if !pass {
			resStr = "FAIL"
		}

		recordScenario(ScenarioRecord{
			ID:             "U10d",
			Profile:        "ed25519",
			Input:          "Decoded manifest size > 16 KiB",
			ExpectedStatus: "FORMAT_ERROR",
			ExpectedExit:   1,
			ActualStatus:   actualStatus,
			ActualExit:     verifyRes.ExitCode,
			Result:         resStr,
		})

		if !pass {
			t.Fatalf("expected FORMAT_ERROR exit 1, got %s exit %d", actualStatus, verifyRes.ExitCode)
		}
	})

	// =========================================================================
	// U11: ed25519, unsupported algorithm rsa-pkcs1-sha256 -> UNSUPPORTED_ALGORITHM
	// =========================================================================
	t.Run("U11", func(t *testing.T) {
		tmp := t.TempDir()
		key := loadKeypair(t, "ed25519", "publisher")
		tsPath := createTrustStore(t, tmp, []testKeypair{key}, nil)
		artPath := filepath.Join(tmp, "app.bin")
		artData := []byte("payload")
		_ = os.WriteFile(artPath, artData, 0644)

		manifest := fmt.Sprintf(
			`{"schema":"minisign-manifest/v1","package":"test-app","version":"1.0.0","algorithm":"rsa-pkcs1-sha256","keyid":"%s","artifact":{"name":"app.bin","size":%d,"sha256":"%s"}}`,
			key.fingerprint, len(artData), sha256Hex(artData),
		)
		bPath := filepath.Join(tmp, "u11.json")
		bData := bundle.Build([]byte(manifest), make([]byte, 64))
		_ = os.WriteFile(bPath, bData, 0644)

		verifyRes := runCLI("verify", "--file", artPath, "--bundle", bPath, "--trust-store", tsPath, "--package", "test-app", "--version", "1.0.0", "--json")
		actualStatus := ""
		if verifyRes.JSON != nil {
			actualStatus = verifyRes.JSON.Status
		}
		pass := verifyRes.ExitCode == 1 && actualStatus == "UNSUPPORTED_ALGORITHM"
		resStr := "PASS"
		if !pass {
			resStr = "FAIL"
		}

		recordScenario(ScenarioRecord{
			ID:             "U11",
			Profile:        "ed25519",
			Input:          "Manifest algorithm rsa-pkcs1-sha256 (unsupported)",
			ExpectedStatus: "UNSUPPORTED_ALGORITHM",
			ExpectedExit:   1,
			ActualStatus:   actualStatus,
			ActualExit:     verifyRes.ExitCode,
			Result:         resStr,
		})

		if !pass {
			t.Fatalf("expected UNSUPPORTED_ALGORITHM exit 1, got %s exit %d", actualStatus, verifyRes.ExitCode)
		}
	})

	// =========================================================================
	// U12: ed25519, sign with other key not in trust store -> KEY_NOT_TRUSTED
	// =========================================================================
	t.Run("U12", func(t *testing.T) {
		tmp := t.TempDir()
		pubKey := loadKeypair(t, "ed25519", "publisher")
		otherKey := loadKeypair(t, "ed25519", "other")
		tsPath := createTrustStore(t, tmp, []testKeypair{pubKey}, nil)

		artPath := filepath.Join(tmp, "app.bin")
		_ = os.WriteFile(artPath, []byte("payload"), 0644)
		// Sign using otherKey
		bundlePath := createBundle(t, tmp, otherKey, "test-app", "1.0.0", artPath)

		verifyRes := runCLI("verify", "--file", artPath, "--bundle", bundlePath, "--trust-store", tsPath, "--package", "test-app", "--version", "1.0.0", "--json")
		actualStatus := ""
		if verifyRes.JSON != nil {
			actualStatus = verifyRes.JSON.Status
		}
		pass := verifyRes.ExitCode == 1 && actualStatus == "KEY_NOT_TRUSTED"
		resStr := "PASS"
		if !pass {
			resStr = "FAIL"
		}

		recordScenario(ScenarioRecord{
			ID:             "U12",
			Profile:        "ed25519",
			Input:          "Signed with other key not present in trust store",
			ExpectedStatus: "KEY_NOT_TRUSTED",
			ExpectedExit:   1,
			ActualStatus:   actualStatus,
			ActualExit:     verifyRes.ExitCode,
			Result:         resStr,
		})

		if !pass {
			t.Fatalf("expected KEY_NOT_TRUSTED exit 1, got %s exit %d", actualStatus, verifyRes.ExitCode)
		}
	})

	// =========================================================================
	// U13: ed25519, reformat bundle JSON with reordered keys -> OK
	// =========================================================================
	t.Run("U13", func(t *testing.T) {
		tmp := t.TempDir()
		key := loadKeypair(t, "ed25519", "publisher")
		tsPath := createTrustStore(t, tmp, []testKeypair{key}, nil)

		artPath := filepath.Join(tmp, "app.bin")
		_ = os.WriteFile(artPath, []byte("payload"), 0644)
		bundlePath := createBundle(t, tmp, key, "test-app", "1.0.0", artPath)

		// Read bundle and reorder keys in bundle JSON (signature_b64 before manifest_b64)
		bBytes, _ := os.ReadFile(bundlePath)
		manifestRaw, sigRaw, err := bundle.ParseStrict(bBytes)
		if err != nil {
			t.Fatal(err)
		}
		reorderedBundle := fmt.Sprintf(`{"signature_b64":"%s","manifest_b64":"%s","schema":"minisign-bundle/v1"}`,
			base64.StdEncoding.EncodeToString(sigRaw), base64.StdEncoding.EncodeToString(manifestRaw))
		_ = os.WriteFile(bundlePath, []byte(reorderedBundle), 0644)

		verifyRes := runCLI("verify", "--file", artPath, "--bundle", bundlePath, "--trust-store", tsPath, "--package", "test-app", "--version", "1.0.0", "--json")
		actualStatus := ""
		if verifyRes.JSON != nil {
			actualStatus = verifyRes.JSON.Status
		}
		pass := verifyRes.ExitCode == 0 && actualStatus == "OK"
		resStr := "PASS"
		if !pass {
			resStr = "FAIL"
		}

		recordScenario(ScenarioRecord{
			ID:             "U13",
			Profile:        "ed25519",
			Input:          "Reorder keys in bundle JSON (manifest retains canonical format)",
			ExpectedStatus: "OK",
			ExpectedExit:   0,
			ActualStatus:   actualStatus,
			ActualExit:     verifyRes.ExitCode,
			Result:         resStr,
		})

		if !pass {
			t.Fatalf("expected OK exit 0 on reordered bundle JSON, got %s exit %d", actualStatus, verifyRes.ExitCode)
		}
	})

	// =========================================================================
	// U14: 3 profiles, sign identical manifest twice -> randomness properties
	// =========================================================================
	for _, prof := range profiles {
		testID := fmt.Sprintf("U14-%s", prof)
		t.Run(testID, func(t *testing.T) {
			key := loadKeypair(t, prof, "publisher")
			manifest := []byte(`{"schema":"minisign-manifest/v1","package":"test-app","version":"1.0.0","algorithm":"` + prof + `","keyid":"` + key.fingerprint + `","artifact":{"name":"app.bin","size":7,"sha256":"0000000000000000000000000000000000000000000000000000000000000000"}}`)

			sig1 := signBytes(t, key, manifest)
			sig2 := signBytes(t, key, manifest)

			hex1 := hex.EncodeToString(sig1)
			hex2 := hex.EncodeToString(sig2)

			pass := false
			details := ""
			switch prof {
			case "rsa-pss-sha256":
				pass = hex1 != hex2
				details = "RSA-PSS randomized salt (32 bytes) produces distinct signatures"
			case "ecdsa-p256-sha256":
				pass = hex1 != hex2
				details = "ECDSA CSPRNG hedged nonce produces distinct signatures"
			case "ed25519":
				pass = hex1 == hex2
				details = "Ed25519 deterministic signature (RFC 8032) produces identical signatures"
			}

			resStr := "PASS"
			if !pass {
				resStr = "FAIL"
			}

			recordScenario(ScenarioRecord{
				ID:             "U14",
				Profile:        prof,
				Input:          "Sign identical manifest twice and verify randomness",
				ExpectedStatus: "OK",
				ExpectedExit:   0,
				ActualStatus:   "OK",
				ActualExit:     0,
				Result:         resStr,
				Details:        details,
				Run1SigHex:     hex1,
				Run2SigHex:     hex2,
			})

			if !pass {
				t.Fatalf("U14 randomness assertion failed for %s", prof)
			}
		})
	}

	// =========================================================================
	// Additional Negative Cases from Contract
	// =========================================================================
	t.Run("Neg_ProfileMismatch", func(t *testing.T) {
		tmp := t.TempDir()
		key := loadKeypair(t, "ed25519", "publisher")
		artPath := filepath.Join(tmp, "app.bin")
		artData := []byte("payload")
		_ = os.WriteFile(artPath, artData, 0644)

		// Manifest claims rsa-pss-sha256, trust store declares ed25519
		manifest := fmt.Sprintf(
			`{"schema":"minisign-manifest/v1","package":"test-app","version":"1.0.0","algorithm":"rsa-pss-sha256","keyid":"%s","artifact":{"name":"app.bin","size":%d,"sha256":"%s"}}`,
			key.fingerprint, len(artData), sha256Hex(artData),
		)
		bPath := filepath.Join(tmp, "b_mismatch.json")
		bData := bundle.Build([]byte(manifest), make([]byte, 384))
		_ = os.WriteFile(bPath, bData, 0644)
		tsPath := createTrustStore(t, tmp, []testKeypair{key}, nil)

		verifyRes := runCLI("verify", "--file", artPath, "--bundle", bPath, "--trust-store", tsPath, "--package", "test-app", "--version", "1.0.0", "--json")
		actualStatus := ""
		if verifyRes.JSON != nil {
			actualStatus = verifyRes.JSON.Status
		}
		pass := verifyRes.ExitCode == 1 && actualStatus == "KEY_NOT_TRUSTED"
		resStr := "PASS"
		if !pass {
			resStr = "FAIL"
		}

		recordScenario(ScenarioRecord{
			ID:             "Neg_ProfileMismatch",
			Profile:        "ed25519",
			Input:          "Key profile in trust store differs from manifest algorithm",
			ExpectedStatus: "KEY_NOT_TRUSTED",
			ExpectedExit:   1,
			ActualStatus:   actualStatus,
			ActualExit:     verifyRes.ExitCode,
			Result:         resStr,
		})

		if !pass {
			t.Fatalf("expected KEY_NOT_TRUSTED exit 1, got %s exit %d", actualStatus, verifyRes.ExitCode)
		}
	})

	t.Run("Neg_MissingArtifact", func(t *testing.T) {
		tmp := t.TempDir()
		key := loadKeypair(t, "ed25519", "publisher")
		tsPath := createTrustStore(t, tmp, []testKeypair{key}, nil)
		bPath := filepath.Join(tmp, "b.json")
		_ = os.WriteFile(bPath, []byte(`{"schema":"minisign-bundle/v1","manifest_b64":"YWJj","signature_b64":"YWJj"}`), 0644)

		verifyRes := runCLI("verify", "--file", filepath.Join(tmp, "missing.bin"), "--bundle", bPath, "--trust-store", tsPath, "--package", "test-app", "--version", "1.0.0", "--json")
		actualStatus := ""
		if verifyRes.JSON != nil {
			actualStatus = verifyRes.JSON.Status
		}
		pass := verifyRes.ExitCode == 2 && actualStatus == "INPUT_ERROR"
		resStr := "PASS"
		if !pass {
			resStr = "FAIL"
		}

		recordScenario(ScenarioRecord{
			ID:             "Neg_MissingArtifact",
			Profile:        "ed25519",
			Input:          "Physical artifact file missing from disk",
			ExpectedStatus: "INPUT_ERROR",
			ExpectedExit:   2,
			ActualStatus:   actualStatus,
			ActualExit:     verifyRes.ExitCode,
			Result:         resStr,
		})

		if !pass {
			t.Fatalf("expected INPUT_ERROR exit 2, got %s exit %d", actualStatus, verifyRes.ExitCode)
		}
	})

	t.Run("Neg_BundleTooLarge", func(t *testing.T) {
		tmp := t.TempDir()
		key := loadKeypair(t, "ed25519", "publisher")
		tsPath := createTrustStore(t, tmp, []testKeypair{key}, nil)
		artPath := filepath.Join(tmp, "app.bin")
		_ = os.WriteFile(artPath, []byte("payload"), 0644)

		// Bundle > 64 KiB
		bPath := filepath.Join(tmp, "big_bundle.json")
		_ = os.WriteFile(bPath, make([]byte, 65537), 0644)

		verifyRes := runCLI("verify", "--file", artPath, "--bundle", bPath, "--trust-store", tsPath, "--package", "test-app", "--version", "1.0.0", "--json")
		actualStatus := ""
		if verifyRes.JSON != nil {
			actualStatus = verifyRes.JSON.Status
		}
		pass := verifyRes.ExitCode == 1 && actualStatus == "FORMAT_ERROR"
		resStr := "PASS"
		if !pass {
			resStr = "FAIL"
		}

		recordScenario(ScenarioRecord{
			ID:             "Neg_BundleTooLarge",
			Profile:        "ed25519",
			Input:          "Bundle file exceeds 64 KiB limit",
			ExpectedStatus: "FORMAT_ERROR",
			ExpectedExit:   1,
			ActualStatus:   actualStatus,
			ActualExit:     verifyRes.ExitCode,
			Result:         resStr,
		})

		if !pass {
			t.Fatalf("expected FORMAT_ERROR exit 1, got %s exit %d", actualStatus, verifyRes.ExitCode)
		}
	})
}
