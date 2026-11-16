package release

import (
	"fmt"
	"os"

	"github.com/brii26/release-signer/pkg/bundle"
	"github.com/brii26/release-signer/pkg/manifest"
	"github.com/brii26/release-signer/pkg/sbom"
)

// StatusSBOMMismatch: kedua bundle sah tapi SBOM tidak terikat ke rilis.
const StatusSBOMMismatch Status = "SBOM_MISMATCH"

// SBOMSign sign file SBOM (ArtifactPath) sebagai artifact terpisah, ErrInput kalau binding SHA-256 tidak valid.
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

// SBOMVerify verify bundle SBOM dengan urutan cek sama seperti rilis (Tabel 2.8), ArtifactPath = path SBOM.
func SBOMVerify(in VerifyInput) Result {
	return Verify(in)
}

// CheckInput adalah input SBOMCheck, Package dan Version adalah nilai yang diharapkan user.
type CheckInput struct {
	ArtifactPath   string
	ReleaseBundle  string
	SBOMPath       string
	SBOMBundle     string
	TrustStorePath string
	Package        string
	Version        string
}

// CheckResult hasil sbom check, Release dan SBOM nil kalau cek itu belum jalan.
type CheckResult struct {
	Valid   bool    `json:"valid"`
	Status  Status  `json:"status"`
	Message string  `json:"message"`
	Release *Result `json:"release"`
	SBOM    *Result `json:"sbom"`
}

// ExitCode: 0 untuk OK, 2 untuk INPUT_ERROR, 1 lainnya.
func (r CheckResult) ExitCode() int {
	switch r.Status {
	case StatusOK:
		return 0
	case StatusInputError:
		return 2
	}
	return 1
}

// SBOMCheck verify bundle rilis, lalu SBOM, lalu cocokkan binding SBOM ke manifest, berhenti di gagal pertama.
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
