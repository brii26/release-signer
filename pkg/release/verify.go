package release

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"regexp"

	"github.com/brii26/release-signer/pkg/bundle"
	"github.com/brii26/release-signer/pkg/manifest"
	"github.com/brii26/release-signer/pkg/strictjson"
)

// Status is the outcome of a verification (Table 2.8).
type Status string

// Verification statuses, in the order the checks run.
const (
	StatusInputError           Status = "INPUT_ERROR"
	StatusFormatError          Status = "FORMAT_ERROR"
	StatusUnsupportedAlgorithm Status = "UNSUPPORTED_ALGORITHM"
	StatusKeyNotTrusted        Status = "KEY_NOT_TRUSTED"
	StatusInvalidSignature     Status = "INVALID_SIGNATURE"
	StatusMetadataMismatch     Status = "METADATA_MISMATCH"
	StatusArtifactMismatch     Status = "ARTIFACT_MISMATCH"
	StatusOK                   Status = "OK"
)

// Profile names as they appear in the manifest algorithm field.
const (
	ProfileRSAPSS  = "rsa-pss-sha256"
	ProfileECDSA   = "ecdsa-p256-sha256"
	ProfileEd25519 = "ed25519"
)

// Size limits in bytes for the files Verify reads.
const (
	MaxBundleSize     = 64 * 1024   // 64 KiB
	MaxManifestSize   = 16 * 1024   // 16 KiB
	MaxTrustStoreSize = 1024 * 1024 // 1 MiB
)

var (
	packageRegex = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,63}$`)
	hex64Regex   = regexp.MustCompile(`^[0-9a-f]{64}$`)
)

// Result is the verification result (Table 2.9). Algorithm, KeyID, Package, and Version
// are nil until the manifest could be read. When Valid is false they only explain the
// failure and must not be treated as trusted data.
type Result struct {
	Valid     bool    `json:"valid"`
	Status    Status  `json:"status"`
	Message   string  `json:"message"`
	Algorithm *string `json:"algorithm"`
	KeyID     *string `json:"keyid"`
	Package   *string `json:"package"`
	Version   *string `json:"version"`
}

// ExitCode maps the status to a process exit code: 0 for OK, 2 for INPUT_ERROR, 1 otherwise.
func (r Result) ExitCode() int {
	if r.Status == StatusOK {
		return 0
	}
	if r.Status == StatusInputError {
		return 2
	}
	return 1
}

// VerifyInput is the input of Verify. Package and Version are the values the user expects.
type VerifyInput struct {
	ArtifactPath   string
	BundlePath     string
	TrustStorePath string
	Package        string
	Version        string
}

type manifestData struct {
	schema       string
	packageName  string
	version      string
	algorithm    string
	keyid        string
	artifactName string
	artifactSize int64
	artifactHash string
}

type trustEntry struct {
	keyid     string
	algorithm string
	pubPEM    string
	packages  []string
	pubKey    crypto.PublicKey
}

// Verify implements the strict 7-stage verification engine specified in Table 2.8.
func Verify(in VerifyInput) Result {
	// =========================================================================
	// INPUT_ERROR
	// Options required, package regex, and input files readable.
	// =========================================================================
	if in.ArtifactPath == "" {
		return resultError(StatusInputError, "artifact path is required", nil)
	}
	if in.BundlePath == "" {
		return resultError(StatusInputError, "bundle path is required", nil)
	}
	if in.TrustStorePath == "" {
		return resultError(StatusInputError, "trust store path is required", nil)
	}
	if in.Package == "" {
		return resultError(StatusInputError, "package name is required", nil)
	}
	if in.Version == "" {
		return resultError(StatusInputError, "version string is required", nil)
	}
	if !packageRegex.MatchString(in.Package) {
		return resultError(StatusInputError, fmt.Sprintf("invalid package name %q (must match ^[a-z0-9][a-z0-9._-]{0,63}$)", in.Package), nil)
	}

	bundleBytes, err := os.ReadFile(in.BundlePath)
	if err != nil {
		return resultError(StatusInputError, fmt.Sprintf("failed to read bundle: %v", err), nil)
	}

	trustStoreBytes, err := os.ReadFile(in.TrustStorePath)
	if err != nil {
		return resultError(StatusInputError, fmt.Sprintf("failed to read trust store: %v", err), nil)
	}

	artifactBytes, err := os.ReadFile(in.ArtifactPath)
	if err != nil {
		return resultError(StatusInputError, fmt.Sprintf("failed to read artifact: %v", err), nil)
	}

	// =========================================================================
	// FORMAT_ERROR
	// Bundle, manifest, canonical check, and trust store parsing.
	// =========================================================================

	// --- 2a. Parse Bundle JSON ---
	manifestRaw, sigRaw, err := bundle.ParseStrict(bundleBytes)
	if err != nil {
		return resultError(StatusFormatError, fmt.Sprintf("bundle format error: %v", err), nil)
	}

	// --- 2b. Parse Manifest JSON & Canonical Check ---
	parsedManifest, err := manifest.ParseStrict(manifestRaw)
	if err != nil {
		return resultError(StatusFormatError, fmt.Sprintf("manifest format error: %v", err), nil)
	}

	m := &manifestData{
		schema:       parsedManifest.Schema,
		packageName:  parsedManifest.Package,
		version:      parsedManifest.Version,
		algorithm:    parsedManifest.Algorithm,
		keyid:        parsedManifest.KeyID,
		artifactName: parsedManifest.Artifact.Name,
		artifactSize: parsedManifest.Artifact.Size,
		artifactHash: parsedManifest.Artifact.SHA256,
	}

	// --- 2c. Parse Trust Store JSON & Keys ---
	trustStoreVal, err := strictjson.Parse(trustStoreBytes, MaxTrustStoreSize)
	if err != nil {
		return resultError(StatusFormatError, fmt.Sprintf("malformed trust store JSON: %v", err), m)
	}

	if err := strictjson.ExpectKeys(trustStoreVal, "schema", "keys"); err != nil {
		return resultError(StatusFormatError, fmt.Sprintf("trust store schema violation: %v", err), m)
	}

	tsSchemaField, _ := trustStoreVal.Field("schema")
	tsSchema, err := strictjson.AsString(tsSchemaField)
	if err != nil || tsSchema != "minisign-trust/v1" {
		return resultError(StatusFormatError, "trust store schema must be 'minisign-trust/v1'", m)
	}

	tsKeysField, _ := trustStoreVal.Field("keys")
	keyEntries, err := strictjson.AsArray(tsKeysField)
	if err != nil {
		return resultError(StatusFormatError, "trust store keys must be an array", m)
	}

	seenKeyIDs := make(map[string]struct{})
	trustEntries := make([]trustEntry, 0, len(keyEntries))

	for _, kVal := range keyEntries {
		if err := strictjson.ExpectKeys(kVal, "keyid", "algorithm", "public_key_pem", "packages"); err != nil {
			return resultError(StatusFormatError, fmt.Sprintf("trust store key entry keys violation: %v", err), m)
		}

		kidF, _ := kVal.Field("keyid")
		kid, err := strictjson.AsString(kidF)
		if err != nil || !hex64Regex.MatchString(kid) {
			return resultError(StatusFormatError, "trust store keyid must be 64 lowercase hex", m)
		}

		if _, dup := seenKeyIDs[kid]; dup {
			return resultError(StatusFormatError, fmt.Sprintf("duplicate keyid %q in trust store", kid), m)
		}
		seenKeyIDs[kid] = struct{}{}

		algoF, _ := kVal.Field("algorithm")
		algo, err := strictjson.AsString(algoF)
		if err != nil {
			return resultError(StatusFormatError, "trust store key algorithm must be a string", m)
		}

		pemF, _ := kVal.Field("public_key_pem")
		pemStr, err := strictjson.AsString(pemF)
		if err != nil {
			return resultError(StatusFormatError, "trust store public_key_pem must be a string", m)
		}

		pkgsF, _ := kVal.Field("packages")
		pkgArr, err := strictjson.AsArray(pkgsF)
		if err != nil || len(pkgArr) == 0 {
			return resultError(StatusFormatError, "trust store packages must be non-empty array", m)
		}

		seenPkgs := make(map[string]struct{})
		pkgs := make([]string, 0, len(pkgArr))
		for _, pVal := range pkgArr {
			pStr, err := strictjson.AsString(pVal)
			if err != nil || !packageRegex.MatchString(pStr) {
				return resultError(StatusFormatError, "invalid package in trust store entry", m)
			}
			if _, dup := seenPkgs[pStr]; dup {
				return resultError(StatusFormatError, fmt.Sprintf("duplicate package %q in key entry", pStr), m)
			}
			seenPkgs[pStr] = struct{}{}
			pkgs = append(pkgs, pStr)
		}

		// Validate PEM and SPKI
		block, rest := pem.Decode([]byte(pemStr))
		if block == nil || block.Type != "PUBLIC KEY" || len(bytes.TrimSpace(rest)) > 0 {
			return resultError(StatusFormatError, fmt.Sprintf("invalid PEM block for keyid %s", kid), m)
		}

		pubKey, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			return resultError(StatusFormatError, fmt.Sprintf("invalid SPKI public key for keyid %s: %v", kid, err), m)
		}

		// Re-export SPKI DER to verify canonical fingerprint
		derBytes, err := x509.MarshalPKIXPublicKey(pubKey)
		if err != nil {
			return resultError(StatusFormatError, fmt.Sprintf("failed to marshal SPKI for keyid %s: %v", kid, err), m)
		}
		computedFingerprint := sha256Hex(derBytes)
		if computedFingerprint != kid {
			return resultError(StatusFormatError, fmt.Sprintf("keyid %s does not match computed public key fingerprint %s", kid, computedFingerprint), m)
		}

		// Validate key algorithm matches declared algorithm profile
		if err := validateKeyAlgorithm(pubKey, algo); err != nil {
			return resultError(StatusFormatError, fmt.Sprintf("key %s parameter mismatch: %v", kid, err), m)
		}

		trustEntries = append(trustEntries, trustEntry{
			keyid:     kid,
			algorithm: algo,
			pubPEM:    pemStr,
			packages:  pkgs,
			pubKey:    pubKey,
		})
	}

	// =========================================================================
	// UNSUPPORTED_ALGORITHM
	// Algorithm in manifest must match one of the 3 supported profiles.
	// =========================================================================
	if m.algorithm != ProfileRSAPSS && m.algorithm != ProfileECDSA && m.algorithm != ProfileEd25519 {
		return resultError(StatusUnsupportedAlgorithm, fmt.Sprintf("algorithm %q is unsupported", m.algorithm), m)
	}

	// =========================================================================
	// KEY_NOT_TRUSTED
	// Keyid in trust store, algorithm matches, package authorized.
	// =========================================================================
	var matchedKey *trustEntry
	for i := range trustEntries {
		if trustEntries[i].keyid == m.keyid {
			matchedKey = &trustEntries[i]
			break
		}
	}

	if matchedKey == nil {
		return resultError(StatusKeyNotTrusted, fmt.Sprintf("keyid %s not found in trust store", m.keyid), m)
	}

	if matchedKey.algorithm != m.algorithm {
		return resultError(StatusKeyNotTrusted, fmt.Sprintf("key profile %q does not match manifest algorithm %q", matchedKey.algorithm, m.algorithm), m)
	}

	packageAllowed := false
	for _, p := range matchedKey.packages {
		if p == in.Package {
			packageAllowed = true
			break
		}
	}
	if !packageAllowed {
		return resultError(StatusKeyNotTrusted, fmt.Sprintf("keyid %s is not authorized for package %q", m.keyid, in.Package), m)
	}

	// =========================================================================
	// INVALID_SIGNATURE
	// Cryptographic verification over raw manifest bytes.
	// =========================================================================
	if err := verifySignature(m.algorithm, matchedKey.pubKey, manifestRaw, sigRaw); err != nil {
		return resultError(StatusInvalidSignature, fmt.Sprintf("signature verification failed: %v", err), m)
	}

	// =========================================================================
	// METADATA_MISMATCH
	// CLI arguments must match manifest metadata.
	// =========================================================================
	if m.packageName != in.Package {
		return resultError(StatusMetadataMismatch, fmt.Sprintf("package name %q does not match manifest package %q", in.Package, m.packageName), m)
	}
	if m.version != in.Version {
		return resultError(StatusMetadataMismatch, fmt.Sprintf("version %q does not match manifest version %q", in.Version, m.version), m)
	}
	if filepath.Base(in.ArtifactPath) != m.artifactName {
		return resultError(StatusMetadataMismatch, fmt.Sprintf("artifact filename %q does not match manifest artifact %q", filepath.Base(in.ArtifactPath), m.artifactName), m)
	}

	// =========================================================================
	// ARTIFACT_MISMATCH
	// Size and SHA-256 hash must match manifest exactly.
	// =========================================================================
	if int64(len(artifactBytes)) != m.artifactSize {
		return resultError(StatusArtifactMismatch, fmt.Sprintf("artifact size %d does not match manifest size %d", len(artifactBytes), m.artifactSize), m)
	}

	computedArtHash := sha256Hex(artifactBytes)
	if computedArtHash != m.artifactHash {
		return resultError(StatusArtifactMismatch, fmt.Sprintf("artifact sha256 %s does not match manifest %s", computedArtHash, m.artifactHash), m)
	}

	// =========================================================================
	// OK
	// All checks passed successfully.
	// =========================================================================
	return Result{
		Valid:     true,
		Status:    StatusOK,
		Message:   "Tanda tangan dan artefak valid.",
		Algorithm: &m.algorithm,
		KeyID:     &m.keyid,
		Package:   &m.packageName,
		Version:   &m.version,
	}
}

func resultError(status Status, message string, m *manifestData) Result {
	res := Result{
		Valid:   false,
		Status:  status,
		Message: message,
	}
	if m != nil {
		res.Algorithm = &m.algorithm
		res.KeyID = &m.keyid
		res.Package = &m.packageName
		res.Version = &m.version
	}
	return res
}

func sha256Hex(data []byte) string {
	h := sha256.Sum256(data)
	return hex.EncodeToString(h[:])
}

func validateKeyAlgorithm(pub crypto.PublicKey, declaredAlgo string) error {
	switch k := pub.(type) {
	case *rsa.PublicKey:
		if declaredAlgo != ProfileRSAPSS {
			return fmt.Errorf("key is RSA but declared algorithm is %s", declaredAlgo)
		}
		if k.N.BitLen() != 3072 {
			return fmt.Errorf("RSA key bit length %d is not 3072", k.N.BitLen())
		}
		if k.E != 65537 {
			return fmt.Errorf("RSA public exponent %d is not 65537", k.E)
		}
		return nil
	case *ecdsa.PublicKey:
		if declaredAlgo != ProfileECDSA {
			return fmt.Errorf("key is ECDSA but declared algorithm is %s", declaredAlgo)
		}
		if k.Curve != elliptic.P256() {
			return fmt.Errorf("ECDSA curve %s is not P-256", k.Curve.Params().Name)
		}
		return nil
	case ed25519.PublicKey:
		if declaredAlgo != ProfileEd25519 {
			return fmt.Errorf("key is Ed25519 but declared algorithm is %s", declaredAlgo)
		}
		return nil
	default:
		return fmt.Errorf("unsupported public key type %T", pub)
	}
}

func verifySignature(algo string, pub crypto.PublicKey, manifestBytes, sigBytes []byte) error {
	switch algo {
	case ProfileRSAPSS:
		rsaPub, ok := pub.(*rsa.PublicKey)
		if !ok {
			return errors.New("expected RSA public key")
		}
		if len(sigBytes) != 384 {
			return fmt.Errorf("RSA-PSS signature length %d != 384", len(sigBytes))
		}
		digest := sha256.Sum256(manifestBytes)
		opts := &rsa.PSSOptions{
			SaltLength: 32,
			Hash:       crypto.SHA256,
		}
		return rsa.VerifyPSS(rsaPub, crypto.SHA256, digest[:], sigBytes, opts)

	case ProfileECDSA:
		ecdsaPub, ok := pub.(*ecdsa.PublicKey)
		if !ok {
			return errors.New("expected ECDSA public key")
		}
		if len(sigBytes) != 64 {
			return fmt.Errorf("ECDSA raw signature length %d != 64", len(sigBytes))
		}
		r := new(big.Int).SetBytes(sigBytes[:32])
		s := new(big.Int).SetBytes(sigBytes[32:])

		// Both r and s must be in [1, n-1]
		n := ecdsaPub.Curve.Params().N
		if r.Sign() <= 0 || s.Sign() <= 0 || r.Cmp(n) >= 0 || s.Cmp(n) >= 0 {
			return errors.New("ECDSA signature r or s out of range [1, n-1]")
		}

		digest := sha256.Sum256(manifestBytes)
		if !ecdsa.Verify(ecdsaPub, digest[:], r, s) {
			return errors.New("ECDSA signature verification failed")
		}
		return nil

	case ProfileEd25519:
		edPub, ok := pub.(ed25519.PublicKey)
		if !ok {
			return errors.New("expected Ed25519 public key")
		}
		if len(sigBytes) != ed25519.SignatureSize {
			return fmt.Errorf("Ed25519 signature length %d != %d", len(sigBytes), ed25519.SignatureSize)
		}
		if !ed25519.Verify(edPub, manifestBytes, sigBytes) {
			return errors.New("Ed25519 signature verification failed")
		}
		return nil

	default:
		return fmt.Errorf("unsupported algorithm: %s", algo)
	}
}
