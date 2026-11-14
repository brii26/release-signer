package release

import (
	"fmt"
	"os"

	"github.com/brii26/release-signer/pkg/bundle"
	"github.com/brii26/release-signer/pkg/manifest"
	"github.com/brii26/release-signer/pkg/sbom"
)

// StatusSBOMMismatch dipakai kalau kedua bundle sah tapi SBOM tidak terikat ke rilis.
const StatusSBOMMismatch Status = "SBOM_MISMATCH"

// SBOMSign menandatangani file SBOM sebagai artefak terpisah. SBOM harus punya
// binding SHA-256 yang valid, kalau tidak ditolak dengan ErrInput.
// SignInput.ArtifactPath berisi path SBOM.
func SBOMSign(in SignInput) (SignOutput, error) {
	info, err := os.Stat(in.ArtifactPath)
	if err != nil {
		return SignOutput{}, inputErr("read sbom: %v", err)
	}
	if info.Size() > sbom.MaxSize {
		return SignOutput{}, inputErr("sbom exceeds %d bytes", sbom.MaxSize)
	}
	data, err := os.ReadFile(in.ArtifactPath)
	if err != nil {
		return SignOutput{}, inputErr("read sbom: %v", err)
	}
	if _, err := sbom.ParseBinding(data); err != nil {
		return SignOutput{}, inputErr("sbom has no valid SHA-256 binding: %v", err)
	}
	return Sign(in)
}

// SBOMVerify memverifikasi bundle SBOM dengan urutan pemeriksaan yang sama
// seperti artefak rilis (Tabel 2.8). VerifyInput.ArtifactPath berisi path SBOM.
func SBOMVerify(in VerifyInput) Result {
	return Verify(in)
}

// CheckInput is the input of SBOMCheck. Package and Version are the values the user expects.
type CheckInput struct {
	ArtifactPath   string
	ReleaseBundle  string
	SBOMPath       string
	SBOMBundle     string
	TrustStorePath string
	Package        string
	Version        string
}

// CheckResult adalah hasil sbom check. Release dan SBOM berisi hasil verify
// masing-masing, nil kalau pemeriksaan itu belum sempat dijalankan.
type CheckResult struct {
	Valid   bool    `json:"valid"`
	Status  Status  `json:"status"`
	Message string  `json:"message"`
	Release *Result `json:"release"`
	SBOM    *Result `json:"sbom"`
}

// ExitCode maps the status to a process exit code: 0 for OK, 2 for INPUT_ERROR, 1 otherwise.
func (r CheckResult) ExitCode() int {
	switch r.Status {
	case StatusOK:
		return 0
	case StatusInputError:
		return 2
	}
	return 1
}

// SBOMCheck memverifikasi bundle rilis, lalu bundle SBOM, lalu mencocokkan
// binding di SBOM dengan manifest rilis. Berhenti di kegagalan pertama.
func SBOMCheck(in CheckInput) CheckResult {
	rel := Verify(VerifyInput{
		ArtifactPath:   in.ArtifactPath,
		BundlePath:     in.ReleaseBundle,
		TrustStorePath: in.TrustStorePath,
		Package:        in.Package,
		Version:        in.Version,
	})
	if rel.Status != StatusOK {
		return CheckResult{Status: rel.Status, Message: "release: " + rel.Message, Release: &rel}
	}

	sb := SBOMVerify(VerifyInput{
		ArtifactPath:   in.SBOMPath,
		BundlePath:     in.SBOMBundle,
		TrustStorePath: in.TrustStorePath,
		Package:        in.Package,
		Version:        in.Version,
	})
	if sb.Status != StatusOK {
		return CheckResult{Status: sb.Status, Message: "sbom: " + sb.Message, Release: &rel, SBOM: &sb}
	}

	fail := func(status Status, format string, args ...any) CheckResult {
		return CheckResult{Status: status, Message: fmt.Sprintf(format, args...), Release: &rel, SBOM: &sb}
	}

	sbomBytes, err := os.ReadFile(in.SBOMPath)
	if err != nil {
		return fail(StatusInputError, "read sbom: %v", err)
	}
	binding, err := sbom.ParseBinding(sbomBytes)
	if err != nil {
		return fail(StatusFormatError, "%v", err)
	}

	relBundle, err := os.ReadFile(in.ReleaseBundle)
	if err != nil {
		return fail(StatusInputError, "read release bundle: %v", err)
	}
	manifestBytes, _, err := bundle.ParseStrict(relBundle)
	if err != nil {
		return fail(StatusFormatError, "%v", err)
	}
	m, err := manifest.ParseStrict(manifestBytes)
	if err != nil {
		return fail(StatusFormatError, "%v", err)
	}

	switch {
	case binding.ArtifactSHA != m.Artifact.SHA256:
		return fail(StatusSBOMMismatch, "sbom SHA-256 does not match the release manifest")
	case binding.ArtifactName != m.Artifact.Name:
		return fail(StatusSBOMMismatch, "sbom artifact name does not match the release manifest")
	case binding.Package != in.Package:
		return fail(StatusSBOMMismatch, "sbom package does not match the expected package")
	case binding.Version != in.Version:
		return fail(StatusSBOMMismatch, "sbom version does not match the expected version")
	}

	return CheckResult{Valid: true, Status: StatusOK, Message: "Rilis, SBOM, dan binding SHA-256 valid.", Release: &rel, SBOM: &sb}
}
