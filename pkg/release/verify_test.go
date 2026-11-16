package release

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"testing"

	"github.com/brii26/release-signer/pkg/bundle"
)

type testSigner struct {
	algo        string
	signer      crypto.Signer
	pubKey      crypto.PublicKey
	pubPEM      string
	fingerprint string
}

func generateTestSigner(t *testing.T, algo string) *testSigner {
	t.Helper()

	var signer crypto.Signer
	var pub crypto.PublicKey

	switch algo {
	case ProfileRSAPSS:
		k, err := rsa.GenerateKey(rand.Reader, 3072)
		if err != nil {
			t.Fatalf("rsa.GenerateKey: %v", err)
		}
		signer = k
		pub = &k.PublicKey
	case ProfileECDSA:
		k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatalf("ecdsa.GenerateKey: %v", err)
		}
		signer = k
		pub = &k.PublicKey
	case ProfileEd25519:
		pubKey, privKey, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatalf("ed25519.GenerateKey: %v", err)
		}
		signer = privKey
		pub = pubKey
	default:
		t.Fatalf("unknown algo: %s", algo)
	}

	spkiBytes, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		t.Fatalf("MarshalPKIXPublicKey: %v", err)
	}

	pemBlock := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: spkiBytes,
	})

	h := sha256.Sum256(spkiBytes)
	fp := hex.EncodeToString(h[:])

	return &testSigner{
		algo:        algo,
		signer:      signer,
		pubKey:      pub,
		pubPEM:      string(pemBlock),
		fingerprint: fp,
	}
}

func (s *testSigner) sign(t *testing.T, data []byte) []byte {
	t.Helper()
	switch s.algo {
	case ProfileRSAPSS:
		k := s.signer.(*rsa.PrivateKey)
		h := sha256.Sum256(data)
		sig, err := rsa.SignPSS(rand.Reader, k, crypto.SHA256, h[:], &rsa.PSSOptions{SaltLength: 32})
		if err != nil {
			t.Fatalf("SignPSS: %v", err)
		}
		return sig
	case ProfileECDSA:
		k := s.signer.(*ecdsa.PrivateKey)
		h := sha256.Sum256(data)
		r, sInt, err := ecdsa.Sign(rand.Reader, k, h[:])
		if err != nil {
			t.Fatalf("ecdsa.Sign: %v", err)
		}
		rBytes := r.Bytes()
		sBytes := sInt.Bytes()
		out := make([]byte, 64)
		copy(out[32-len(rBytes):32], rBytes)
		copy(out[64-len(sBytes):64], sBytes)
		return out
	case ProfileEd25519:
		k := s.signer.(ed25519.PrivateKey)
		return ed25519.Sign(k, data)
	default:
		t.Fatalf("unknown algo: %s", s.algo)
		return nil
	}
}

func buildFixture(t *testing.T, dir string, s *testSigner, pkgName, version, artName string, artData []byte, allowedPkgs []string) (artPath, bundlePath, trustPath string) {
	t.Helper()

	artPath = filepath.Join(dir, artName)
	if err := os.WriteFile(artPath, artData, 0644); err != nil {
		t.Fatal(err)
	}

	artHash := sha256Hex(artData)
	artSize := int64(len(artData))

	manifestCanonical := fmt.Sprintf(
		`{"schema":"minisign-manifest/v1","package":"%s","version":"%s","algorithm":"%s","keyid":"%s","artifact":{"name":"%s","size":%s,"sha256":"%s"}}`,
		pkgName, version, s.algo, s.fingerprint, artName, strconv.FormatInt(artSize, 10), artHash,
	)

	sigBytes := s.sign(t, []byte(manifestCanonical))

	bundleBytes := bundle.Build([]byte(manifestCanonical), sigBytes)
	bundlePath = filepath.Join(dir, "bundle.json")
	if err := os.WriteFile(bundlePath, bundleBytes, 0644); err != nil {
		t.Fatal(err)
	}

	pkgsJSON := `["` + allowedPkgs[0] + `"`
	for i := 1; i < len(allowedPkgs); i++ {
		pkgsJSON += `,"` + allowedPkgs[i] + `"`
	}
	pkgsJSON += `]`

	escapedPEM := ""
	for i := 0; i < len(s.pubPEM); i++ {
		if s.pubPEM[i] == '\n' {
			escapedPEM += `\n`
		} else {
			escapedPEM += string(s.pubPEM[i])
		}
	}

	trustJSON := fmt.Sprintf(
		`{"schema":"minisign-trust/v1","keys":[{"keyid":"%s","algorithm":"%s","public_key_pem":"%s","packages":%s}]}`,
		s.fingerprint, s.algo, escapedPEM, pkgsJSON,
	)

	trustPath = filepath.Join(dir, "trust.json")
	if err := os.WriteFile(trustPath, []byte(trustJSON), 0644); err != nil {
		t.Fatal(err)
	}

	return artPath, bundlePath, trustPath
}

func TestVerifyHappyPaths(t *testing.T) {
	algos := []string{ProfileRSAPSS, ProfileECDSA, ProfileEd25519}

	for _, algo := range algos {
		t.Run(algo, func(t *testing.T) {
			dir := t.TempDir()
			signer := generateTestSigner(t, algo)

			artPath, bundlePath, trustPath := buildFixture(t, dir, signer, "myapp", "1.0.0", "myapp.bin", []byte("valid artifact content"), []string{"myapp"})

			res := Verify(VerifyInput{
				ArtifactPath:   artPath,
				BundlePath:     bundlePath,
				TrustStorePath: trustPath,
				Package:        "myapp",
				Version:        "1.0.0",
			})

			if !res.Valid || res.Status != StatusOK {
				t.Fatalf("expected OK, got valid=%v status=%s msg=%s", res.Valid, res.Status, res.Message)
			}
			if res.ExitCode() != 0 {
				t.Fatalf("expected exit code 0, got %d", res.ExitCode())
			}
			if res.Algorithm == nil || *res.Algorithm != algo {
				t.Fatalf("expected algorithm %s, got %v", algo, res.Algorithm)
			}
			if res.KeyID == nil || *res.KeyID != signer.fingerprint {
				t.Fatalf("expected keyid %s, got %v", signer.fingerprint, res.KeyID)
			}
		})
	}
}

func TestVerifyArtifactTamper(t *testing.T) {
	dir := t.TempDir()
	signer := generateTestSigner(t, ProfileEd25519)
	artPath, bundlePath, trustPath := buildFixture(t, dir, signer, "app", "1.0.0", "app.bin", []byte("original data"), []string{"app"})

	// ubah 1 byte artifact
	if err := os.WriteFile(artPath, []byte("origjnal data"), 0644); err != nil {
		t.Fatal(err)
	}

	res := Verify(VerifyInput{
		ArtifactPath:   artPath,
		BundlePath:     bundlePath,
		TrustStorePath: trustPath,
		Package:        "app",
		Version:        "1.0.0",
	})

	if res.Valid || res.Status != StatusArtifactMismatch {
		t.Fatalf("expected ARTIFACT_MISMATCH on 1-byte tamper, got %s", res.Status)
	}
	if res.ExitCode() != 1 {
		t.Fatalf("expected exit 1, got %d", res.ExitCode())
	}

	// tambah 1 byte (size mismatch)
	if err := os.WriteFile(artPath, []byte("original data!"), 0644); err != nil {
		t.Fatal(err)
	}
	res2 := Verify(VerifyInput{
		ArtifactPath:   artPath,
		BundlePath:     bundlePath,
		TrustStorePath: trustPath,
		Package:        "app",
		Version:        "1.0.0",
	})
	if res2.Valid || res2.Status != StatusArtifactMismatch {
		t.Fatalf("expected ARTIFACT_MISMATCH on size change, got %s", res2.Status)
	}
}

func TestVerifyInvalidSignature(t *testing.T) {
	dir := t.TempDir()
	signer := generateTestSigner(t, ProfileEd25519)
	artPath, bundlePath, trustPath := buildFixture(t, dir, signer, "app", "1.0.0", "app.bin", []byte("payload"), []string{"app"})

	// parse bundle lalu rusak byte signature
	bundleBytes, err := os.ReadFile(bundlePath)
	if err != nil {
		t.Fatal(err)
	}

	manifestRaw, sigRaw, err := bundle.ParseStrict(bundleBytes)
	if err != nil {
		t.Fatal(err)
	}

	// flip 1 byte signature
	sigRaw[0] ^= 0xFF
	tamperedBundle := bundle.Build(manifestRaw, sigRaw)
	if err := os.WriteFile(bundlePath, tamperedBundle, 0644); err != nil {
		t.Fatal(err)
	}

	res := Verify(VerifyInput{
		ArtifactPath:   artPath,
		BundlePath:     bundlePath,
		TrustStorePath: trustPath,
		Package:        "app",
		Version:        "1.0.0",
	})

	if res.Valid || res.Status != StatusInvalidSignature {
		t.Fatalf("expected INVALID_SIGNATURE on corrupt signature, got %s (msg: %s)", res.Status, res.Message)
	}
	if res.ExitCode() != 1 {
		t.Fatalf("expected exit 1, got %d", res.ExitCode())
	}
}

func TestVerifyKeyNotTrusted(t *testing.T) {
	dir := t.TempDir()
	signer := generateTestSigner(t, ProfileEd25519)

	// sign untuk "app" tapi trust store hanya izinkan "other-app"
	artPath, bundlePath, trustPath := buildFixture(t, dir, signer, "app", "1.0.0", "app.bin", []byte("payload"), []string{"other-app"})

	res := Verify(VerifyInput{
		ArtifactPath:   artPath,
		BundlePath:     bundlePath,
		TrustStorePath: trustPath,
		Package:        "app",
		Version:        "1.0.0",
	})

	if res.Valid || res.Status != StatusKeyNotTrusted {
		t.Fatalf("expected KEY_NOT_TRUSTED when package not in authorized list, got %s", res.Status)
	}
	if res.ExitCode() != 1 {
		t.Fatalf("expected exit 1, got %d", res.ExitCode())
	}
}

func TestVerifyMetadataMismatch(t *testing.T) {
	dir := t.TempDir()
	signer := generateTestSigner(t, ProfileEd25519)
	artPath, bundlePath, trustPath := buildFixture(t, dir, signer, "app", "1.0.0", "app.bin", []byte("payload"), []string{"app"})

	// cek dengan version CLI beda
	res := Verify(VerifyInput{
		ArtifactPath:   artPath,
		BundlePath:     bundlePath,
		TrustStorePath: trustPath,
		Package:        "app",
		Version:        "2.0.0",
	})

	if res.Valid || res.Status != StatusMetadataMismatch {
		t.Fatalf("expected METADATA_MISMATCH on version difference, got %s", res.Status)
	}
	if res.ExitCode() != 1 {
		t.Fatalf("expected exit 1, got %d", res.ExitCode())
	}
}

func TestVerifyNonCanonicalManifest(t *testing.T) {
	dir := t.TempDir()
	signer := generateTestSigner(t, ProfileEd25519)
	artData := []byte("payload")
	artPath := filepath.Join(dir, "app.bin")
	_ = os.WriteFile(artPath, artData, 0644)

	artHash := sha256Hex(artData)
	// spasi ekstra di manifest (melanggar canonical)
	nonCanonicalManifest := fmt.Sprintf(
		`{ "schema": "minisign-manifest/v1", "package": "app", "version": "1.0.0", "algorithm": "%s", "keyid": "%s", "artifact": { "name": "app.bin", "size": %d, "sha256": "%s" } }`,
		signer.algo, signer.fingerprint, len(artData), artHash,
	)

	sigBytes := signer.sign(t, []byte(nonCanonicalManifest))
	bundleData := bundle.Build([]byte(nonCanonicalManifest), sigBytes)
	bundlePath := filepath.Join(dir, "bundle.json")
	_ = os.WriteFile(bundlePath, bundleData, 0644)

	escapedPEM := ""
	for i := 0; i < len(signer.pubPEM); i++ {
		if signer.pubPEM[i] == '\n' {
			escapedPEM += `\n`
		} else {
			escapedPEM += string(signer.pubPEM[i])
		}
	}
	trustJSON := fmt.Sprintf(
		`{"schema":"minisign-trust/v1","keys":[{"keyid":"%s","algorithm":"%s","public_key_pem":"%s","packages":["app"]}]}`,
		signer.fingerprint, signer.algo, escapedPEM,
	)
	trustPath := filepath.Join(dir, "trust.json")
	_ = os.WriteFile(trustPath, []byte(trustJSON), 0644)

	res := Verify(VerifyInput{
		ArtifactPath:   artPath,
		BundlePath:     bundlePath,
		TrustStorePath: trustPath,
		Package:        "app",
		Version:        "1.0.0",
	})

	if res.Valid || res.Status != StatusFormatError {
		t.Fatalf("expected FORMAT_ERROR on non-canonical manifest formatting, got %s (msg: %s)", res.Status, res.Message)
	}
}

func TestVerifyInputErrorMissingFiles(t *testing.T) {
	dir := t.TempDir()
	res := Verify(VerifyInput{
		ArtifactPath:   filepath.Join(dir, "nonexistent.bin"),
		BundlePath:     filepath.Join(dir, "bundle.json"),
		TrustStorePath: filepath.Join(dir, "trust.json"),
		Package:        "app",
		Version:        "1.0.0",
	})

	if res.Valid || res.Status != StatusInputError {
		t.Fatalf("expected INPUT_ERROR when files do not exist, got %s", res.Status)
	}
	if res.ExitCode() != 2 {
		t.Fatalf("expected exit code 2 on INPUT_ERROR, got %d", res.ExitCode())
	}
	if res.Algorithm != nil || res.KeyID != nil || res.Package != nil || res.Version != nil {
		t.Fatalf("metadata fields must be null on INPUT_ERROR, got %+v", res)
	}
}

func TestVerifyUnsupportedAlgorithm(t *testing.T) {
	dir := t.TempDir()
	signer := generateTestSigner(t, ProfileEd25519)
	artData := []byte("payload")
	artPath := filepath.Join(dir, "app.bin")
	_ = os.WriteFile(artPath, artData, 0644)

	// manifest dengan algorithm tidak dikenal
	manifestCanonical := fmt.Sprintf(
		`{"schema":"minisign-manifest/v1","package":"app","version":"1.0.0","algorithm":"unknown-algo","keyid":"%s","artifact":{"name":"app.bin","size":%d,"sha256":"%s"}}`,
		signer.fingerprint, len(artData), sha256Hex(artData),
	)

	bundleData := bundle.Build([]byte(manifestCanonical), make([]byte, 64))
	bundlePath := filepath.Join(dir, "bundle.json")
	_ = os.WriteFile(bundlePath, bundleData, 0644)

	trustJSON := fmt.Sprintf(
		`{"schema":"minisign-trust/v1","keys":[{"keyid":"%s","algorithm":"ed25519","public_key_pem":"%s","packages":["app"]}]}`,
		signer.fingerprint, escapePEM(signer.pubPEM),
	)
	trustPath := filepath.Join(dir, "trust.json")
	_ = os.WriteFile(trustPath, []byte(trustJSON), 0644)

	res := Verify(VerifyInput{
		ArtifactPath:   artPath,
		BundlePath:     bundlePath,
		TrustStorePath: trustPath,
		Package:        "app",
		Version:        "1.0.0",
	})

	if res.Valid || res.Status != StatusUnsupportedAlgorithm {
		t.Fatalf("expected UNSUPPORTED_ALGORITHM, got %s (msg: %s)", res.Status, res.Message)
	}
	if res.ExitCode() != 1 {
		t.Fatalf("expected exit code 1, got %d", res.ExitCode())
	}
	// manifest terparse, jadi field metadata harus terisi
	if res.Algorithm == nil || *res.Algorithm != "unknown-algo" {
		t.Fatalf("expected algorithm in result to be 'unknown-algo', got %v", res.Algorithm)
	}
}

func TestVerifyTrustStoreFormatErrors(t *testing.T) {
	dir := t.TempDir()
	signer := generateTestSigner(t, ProfileEd25519)
	artPath, bundlePath, _ := buildFixture(t, dir, signer, "app", "1.0.0", "app.bin", []byte("payload"), []string{"app"})

	// fingerprint tidak cocok di trust store
	badFp := "0000000000000000000000000000000000000000000000000000000000000000"
	trustJSON := fmt.Sprintf(
		`{"schema":"minisign-trust/v1","keys":[{"keyid":"%s","algorithm":"ed25519","public_key_pem":"%s","packages":["app"]}]}`,
		badFp, escapePEM(signer.pubPEM),
	)
	trustPath := filepath.Join(dir, "bad_trust.json")
	_ = os.WriteFile(trustPath, []byte(trustJSON), 0644)

	res := Verify(VerifyInput{
		ArtifactPath:   artPath,
		BundlePath:     bundlePath,
		TrustStorePath: trustPath,
		Package:        "app",
		Version:        "1.0.0",
	})
	if res.Valid || res.Status != StatusFormatError {
		t.Fatalf("expected FORMAT_ERROR on fingerprint mismatch in trust store, got %s (msg: %s)", res.Status, res.Message)
	}

	// keyid duplikat di trust store
	dupTrustJSON := fmt.Sprintf(
		`{"schema":"minisign-trust/v1","keys":[{"keyid":"%s","algorithm":"ed25519","public_key_pem":"%s","packages":["app"]},{"keyid":"%s","algorithm":"ed25519","public_key_pem":"%s","packages":["app"]}]}`,
		signer.fingerprint, escapePEM(signer.pubPEM), signer.fingerprint, escapePEM(signer.pubPEM),
	)
	dupTrustPath := filepath.Join(dir, "dup_trust.json")
	_ = os.WriteFile(dupTrustPath, []byte(dupTrustJSON), 0644)

	res2 := Verify(VerifyInput{
		ArtifactPath:   artPath,
		BundlePath:     bundlePath,
		TrustStorePath: dupTrustPath,
		Package:        "app",
		Version:        "1.0.0",
	})
	if res2.Valid || res2.Status != StatusFormatError {
		t.Fatalf("expected FORMAT_ERROR on duplicate keyid in trust store, got %s (msg: %s)", res2.Status, res2.Message)
	}
}

func TestVerifyECDSARZero(t *testing.T) {
	dir := t.TempDir()
	signer := generateTestSigner(t, ProfileECDSA)
	artData := []byte("payload")
	artPath := filepath.Join(dir, "app.bin")
	_ = os.WriteFile(artPath, artData, 0644)

	manifestCanonical := fmt.Sprintf(
		`{"schema":"minisign-manifest/v1","package":"app","version":"1.0.0","algorithm":"%s","keyid":"%s","artifact":{"name":"app.bin","size":%d,"sha256":"%s"}}`,
		signer.algo, signer.fingerprint, len(artData), sha256Hex(artData),
	)

	// signature dengan r = 0 (32 byte pertama nol)
	rZeroSig := make([]byte, 64)
	rZeroSig[63] = 1 // s = 1

	bundleData := bundle.Build([]byte(manifestCanonical), rZeroSig)
	bundlePath := filepath.Join(dir, "bundle.json")
	_ = os.WriteFile(bundlePath, bundleData, 0644)

	trustJSON := fmt.Sprintf(
		`{"schema":"minisign-trust/v1","keys":[{"keyid":"%s","algorithm":"%s","public_key_pem":"%s","packages":["app"]}]}`,
		signer.fingerprint, signer.algo, escapePEM(signer.pubPEM),
	)
	trustPath := filepath.Join(dir, "trust.json")
	_ = os.WriteFile(trustPath, []byte(trustJSON), 0644)

	res := Verify(VerifyInput{
		ArtifactPath:   artPath,
		BundlePath:     bundlePath,
		TrustStorePath: trustPath,
		Package:        "app",
		Version:        "1.0.0",
	})

	if res.Valid || res.Status != StatusInvalidSignature {
		t.Fatalf("expected INVALID_SIGNATURE for ECDSA signature with r=0, got %s (msg: %s)", res.Status, res.Message)
	}
}

func TestVerifyBundleTooLarge(t *testing.T) {
	dir := t.TempDir()
	artPath := filepath.Join(dir, "app.bin")
	_ = os.WriteFile(artPath, []byte("ok"), 0644)
	trustPath := filepath.Join(dir, "trust.json")
	_ = os.WriteFile(trustPath, []byte(`{"schema":"minisign-trust/v1","keys":[]}`), 0644)

	// bundle > 64 KiB
	bigData := make([]byte, 65537)
	bundlePath := filepath.Join(dir, "big_bundle.json")
	_ = os.WriteFile(bundlePath, bigData, 0644)

	res := Verify(VerifyInput{
		ArtifactPath:   artPath,
		BundlePath:     bundlePath,
		TrustStorePath: trustPath,
		Package:        "app",
		Version:        "1.0.0",
	})

	if res.Valid || res.Status != StatusFormatError {
		t.Fatalf("expected FORMAT_ERROR on bundle > 64 KiB, got %s (msg: %s)", res.Status, res.Message)
	}
}

func TestVerifyManifestVersionModifiedInvalidSignature(t *testing.T) {
	dir := t.TempDir()
	signer := generateTestSigner(t, ProfileEd25519)
	artData := []byte("payload")
	artPath := filepath.Join(dir, "app.bin")
	_ = os.WriteFile(artPath, artData, 0644)

	// sign manifest asli untuk version 1.0.0
	manifestOrig := fmt.Sprintf(
		`{"schema":"minisign-manifest/v1","package":"app","version":"1.0.0","algorithm":"%s","keyid":"%s","artifact":{"name":"app.bin","size":%d,"sha256":"%s"}}`,
		signer.algo, signer.fingerprint, len(artData), sha256Hex(artData),
	)
	sigBytes := signer.sign(t, []byte(manifestOrig))

	// ubah version ke 1.0.1 (canonical tetap), signature lama dipakai
	manifestTampered := fmt.Sprintf(
		`{"schema":"minisign-manifest/v1","package":"app","version":"1.0.1","algorithm":"%s","keyid":"%s","artifact":{"name":"app.bin","size":%d,"sha256":"%s"}}`,
		signer.algo, signer.fingerprint, len(artData), sha256Hex(artData),
	)

	bundleData := bundle.Build([]byte(manifestTampered), sigBytes)
	bundlePath := filepath.Join(dir, "bundle.json")
	_ = os.WriteFile(bundlePath, bundleData, 0644)

	trustJSON := fmt.Sprintf(
		`{"schema":"minisign-trust/v1","keys":[{"keyid":"%s","algorithm":"%s","public_key_pem":"%s","packages":["app"]}]}`,
		signer.fingerprint, signer.algo, escapePEM(signer.pubPEM),
	)
	trustPath := filepath.Join(dir, "trust.json")
	_ = os.WriteFile(trustPath, []byte(trustJSON), 0644)

	res := Verify(VerifyInput{
		ArtifactPath:   artPath,
		BundlePath:     bundlePath,
		TrustStorePath: trustPath,
		Package:        "app",
		Version:        "1.0.1",
	})

	if res.Valid || res.Status != StatusInvalidSignature {
		t.Fatalf("expected INVALID_SIGNATURE when manifest version tampered, got %s (msg: %s)", res.Status, res.Message)
	}
}

func TestVerifyEmptyTrustStore(t *testing.T) {
	dir := t.TempDir()
	signer := generateTestSigner(t, ProfileEd25519)
	artPath, bundlePath, _ := buildFixture(t, dir, signer, "app", "1.0.0", "app.bin", []byte("payload"), []string{"app"})

	trustPath := filepath.Join(dir, "empty_trust.json")
	_ = os.WriteFile(trustPath, []byte(`{"schema":"minisign-trust/v1","keys":[]}`), 0644)

	res := Verify(VerifyInput{
		ArtifactPath:   artPath,
		BundlePath:     bundlePath,
		TrustStorePath: trustPath,
		Package:        "app",
		Version:        "1.0.0",
	})

	if res.Valid || res.Status != StatusKeyNotTrusted {
		t.Fatalf("expected KEY_NOT_TRUSTED for empty trust store, got %s (msg: %s)", res.Status, res.Message)
	}
}

func TestVerifyUnknownKeySameProfile(t *testing.T) {
	dir := t.TempDir()
	signer1 := generateTestSigner(t, ProfileEd25519)
	signer2 := generateTestSigner(t, ProfileEd25519)

	// sign dengan signer1
	artPath, bundlePath, _ := buildFixture(t, dir, signer1, "app", "1.0.0", "app.bin", []byte("payload"), []string{"app"})

	// trust store hanya punya signer2
	trustJSON := fmt.Sprintf(
		`{"schema":"minisign-trust/v1","keys":[{"keyid":"%s","algorithm":"%s","public_key_pem":"%s","packages":["app"]}]}`,
		signer2.fingerprint, signer2.algo, escapePEM(signer2.pubPEM),
	)
	trustPath := filepath.Join(dir, "trust.json")
	_ = os.WriteFile(trustPath, []byte(trustJSON), 0644)

	res := Verify(VerifyInput{
		ArtifactPath:   artPath,
		BundlePath:     bundlePath,
		TrustStorePath: trustPath,
		Package:        "app",
		Version:        "1.0.0",
	})

	if res.Valid || res.Status != StatusKeyNotTrusted {
		t.Fatalf("expected KEY_NOT_TRUSTED when key is not in store, got %s", res.Status)
	}
}

func TestVerifyKeyProfileMismatch(t *testing.T) {
	dir := t.TempDir()
	signer := generateTestSigner(t, ProfileEd25519)
	artData := []byte("payload")
	artPath := filepath.Join(dir, "app.bin")
	_ = os.WriteFile(artPath, artData, 0644)

	// manifest klaim rsa-pss-sha256 tapi keyid ed25519 signer
	manifestCanonical := fmt.Sprintf(
		`{"schema":"minisign-manifest/v1","package":"app","version":"1.0.0","algorithm":"%s","keyid":"%s","artifact":{"name":"app.bin","size":%d,"sha256":"%s"}}`,
		ProfileRSAPSS, signer.fingerprint, len(artData), sha256Hex(artData),
	)

	bundleData := bundle.Build([]byte(manifestCanonical), make([]byte, 384))
	bundlePath := filepath.Join(dir, "bundle.json")
	_ = os.WriteFile(bundlePath, bundleData, 0644)

	// trust store punya signer dengan ed25519
	trustJSON := fmt.Sprintf(
		`{"schema":"minisign-trust/v1","keys":[{"keyid":"%s","algorithm":"%s","public_key_pem":"%s","packages":["app"]}]}`,
		signer.fingerprint, ProfileEd25519, escapePEM(signer.pubPEM),
	)
	trustPath := filepath.Join(dir, "trust.json")
	_ = os.WriteFile(trustPath, []byte(trustJSON), 0644)

	res := Verify(VerifyInput{
		ArtifactPath:   artPath,
		BundlePath:     bundlePath,
		TrustStorePath: trustPath,
		Package:        "app",
		Version:        "1.0.0",
	})

	if res.Valid || res.Status != StatusKeyNotTrusted {
		t.Fatalf("expected KEY_NOT_TRUSTED when trust store algorithm != manifest algorithm, got %s (msg: %s)", res.Status, res.Message)
	}
}

func TestVerifyArtifactRenamed(t *testing.T) {
	dir := t.TempDir()
	signer := generateTestSigner(t, ProfileEd25519)
	artData := []byte("payload")
	artPath := filepath.Join(dir, "app.bin")
	_ = os.WriteFile(artPath, artData, 0644)

	// artifact di disk diganti nama
	renamedPath := filepath.Join(dir, "renamed-app.bin")
	_ = os.WriteFile(renamedPath, artData, 0644)

	_, bundlePath, trustPath := buildFixture(t, dir, signer, "app", "1.0.0", "app.bin", artData, []string{"app"})

	res := Verify(VerifyInput{
		ArtifactPath:   renamedPath,
		BundlePath:     bundlePath,
		TrustStorePath: trustPath,
		Package:        "app",
		Version:        "1.0.0",
	})

	if res.Valid || res.Status != StatusMetadataMismatch {
		t.Fatalf("expected METADATA_MISMATCH on renamed artifact, got %s", res.Status)
	}
}

func escapePEM(pem string) string {
	res := ""
	for i := 0; i < len(pem); i++ {
		if pem[i] == '\n' {
			res += `\n`
		} else {
			res += string(pem[i])
		}
	}
	return res
}
