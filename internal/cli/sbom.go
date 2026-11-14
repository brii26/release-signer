package cli

import (
	"errors"
	"flag"
	"fmt"
	"io"

	"github.com/brii26/release-signer/pkg/bundle"
	"github.com/brii26/release-signer/pkg/release"
	"github.com/brii26/release-signer/pkg/sbom"
)

const sbomUsage = `Usage: release-signer sbom <subcommand> [flags]

Generate, sign, and verify a Software Bill of Materials (CycloneDX JSON) bound to a release artifact.

Subcommands:
  generate   Create an SBOM that contains the SHA-256 of the release artifact
  sign       Sign an SBOM as a separate artifact (same bundle format)
  verify     Verify an SBOM bundle against the trust store
  check      Verify the release bundle and the SBOM bundle, then match the SHA-256

Flags:
  -h, --help   Show help for sbom
`

const sbomGenerateUsage = `Usage: release-signer sbom generate --file <artefak> --package <nama> --version <versi> --out <sbom.cdx.json> [--force]

Create a CycloneDX 1.6 SBOM bound to the SHA-256 of the release artifact.

Flags:
  --file string      Path to the release artifact (required)
  --package string   Package name (required)
  --version string   Release version (required)
  --out string       Path to output SBOM file (required)
  --force            Overwrite output file if it already exists
  -h, --help         Show help for sbom generate
`

const sbomSignUsage = `Usage: release-signer sbom sign --sbom <sbom.cdx.json> --package <nama> --version <versi> --key <private.pem> --out <sbom.bundle.json> [--force]

Sign an SBOM as a separate artifact. The SBOM must contain a valid SHA-256 binding.

Flags:
  --sbom string      Path to SBOM file (required)
  --package string   Package name (required)
  --version string   Release version (required)
  --key string       Path to private key PEM (required)
  --out string       Path to output bundle JSON (required)
  --force            Overwrite output bundle if it already exists
  -h, --help         Show help for sbom sign
`

const sbomVerifyUsage = `Usage: release-signer sbom verify --sbom <sbom.cdx.json> --bundle <sbom.bundle.json> --trust-store <trust.json> --package <nama> --version <versi> [--json]

Verify an SBOM bundle with the same checks and statuses as verify.

Flags:
  --sbom string          Path to SBOM file (required)
  --bundle string        Path to SBOM bundle JSON (required)
  --trust-store string   Path to trust store JSON (required)
  --package string       Expected package name (required)
  --version string       Expected version string (required)
  --json                 Output result as a single JSON object
  -h, --help             Show help for sbom verify
`

const sbomCheckUsage = `Usage: release-signer sbom check --file <artefak> --bundle <release.json> --sbom <sbom.cdx.json> --sbom-bundle <sbom.bundle.json> --trust-store <trust.json> --package <nama> --version <versi> [--json]

Verify the release bundle, verify the SBOM bundle, then check that the SBOM is bound
to the SHA-256 of the release artifact. Stops at the first failure.

Flags:
  --file string          Path to the release artifact (required)
  --bundle string        Path to release bundle JSON (required)
  --sbom string          Path to SBOM file (required)
  --sbom-bundle string   Path to SBOM bundle JSON (required)
  --trust-store string   Path to trust store JSON (required)
  --package string       Expected package name (required)
  --version string       Expected version string (required)
  --json                 Output result as a single JSON object
  -h, --help             Show help for sbom check
`

func runSBOM(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprint(stderr, sbomUsage)
		return 2
	}
	switch args[0] {
	case "--help", "-h", "help":
		fmt.Fprint(stdout, sbomUsage)
		return 0
	case "generate":
		return runSBOMGenerate(args[1:], stdout, stderr)
	case "sign":
		return runSBOMSign(args[1:], stdout, stderr)
	case "verify":
		return runSBOMVerify(args[1:], stdout, stderr)
	case "check":
		return runSBOMCheck(args[1:], stdout, stderr)
	default:
		fmt.Fprintf(stderr, "unknown sbom subcommand %q\n\n%s", args[0], sbomUsage)
		return 2
	}
}

func newFlagSet(name, usage string, stderr io.Writer) *flag.FlagSet {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() { fmt.Fprint(stderr, usage) }
	return fs
}

// parseFlags mengembalikan (selesai, kode). selesai true berarti pemanggil harus langsung return kode.
func parseFlags(fs *flag.FlagSet, args []string) (bool, int) {
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return true, 0
		}
		return true, 2
	}
	return false, 0
}

func runSBOMGenerate(args []string, stdout, stderr io.Writer) int {
	fs := newFlagSet("sbom generate", sbomGenerateUsage, stderr)
	file := fs.String("file", "", "path to release artifact")
	pkgName := fs.String("package", "", "package name")
	version := fs.String("version", "", "release version")
	out := fs.String("out", "", "output SBOM path")
	force := fs.Bool("force", false, "overwrite output")
	if done, code := parseFlags(fs, args); done {
		return code
	}

	if *file == "" || *pkgName == "" || *version == "" || *out == "" {
		fmt.Fprintln(stderr, "error: missing required flags (--file, --package, --version, --out)")
		return 2
	}
	if !packageRegex.MatchString(*pkgName) {
		fmt.Fprintf(stderr, "error: invalid package name %q (must match ^[a-z0-9][a-z0-9._-]{0,63}$)\n", *pkgName)
		return 2
	}
	if !fileExists(*file) {
		fmt.Fprintf(stderr, "error: artifact file %q not found or inaccessible\n", *file)
		return 2
	}
	if !*force && fileExists(*out) {
		fmt.Fprintf(stderr, "error: output file %q already exists; use --force to overwrite\n", *out)
		return 2
	}

	data, err := sbom.Generate(*file, *pkgName, *version)
	if err != nil {
		fmt.Fprintf(stderr, "error: sbom generate failed: %v\n", err)
		return 2
	}
	if err := bundle.WriteFile(*out, data, *force); err != nil {
		fmt.Fprintf(stderr, "error: sbom generate failed: write %v\n", err)
		return 2
	}
	fmt.Fprintf(stderr, "wrote %s\n", *out)
	return 0
}

func runSBOMSign(args []string, stdout, stderr io.Writer) int {
	fs := newFlagSet("sbom sign", sbomSignUsage, stderr)
	sbomPath := fs.String("sbom", "", "path to SBOM")
	pkgName := fs.String("package", "", "package name")
	version := fs.String("version", "", "release version")
	keyPath := fs.String("key", "", "private key path")
	out := fs.String("out", "", "output bundle path")
	force := fs.Bool("force", false, "overwrite output bundle")
	if done, code := parseFlags(fs, args); done {
		return code
	}

	if *sbomPath == "" || *pkgName == "" || *version == "" || *keyPath == "" || *out == "" {
		fmt.Fprintln(stderr, "error: missing required flags (--sbom, --package, --version, --key, --out)")
		return 2
	}
	if !packageRegex.MatchString(*pkgName) {
		fmt.Fprintf(stderr, "error: invalid package name %q (must match ^[a-z0-9][a-z0-9._-]{0,63}$)\n", *pkgName)
		return 2
	}
	if !*force && fileExists(*out) {
		fmt.Fprintf(stderr, "error: output bundle %q already exists; use --force to overwrite\n", *out)
		return 2
	}
	if !fileExists(*sbomPath) {
		fmt.Fprintf(stderr, "error: sbom file %q not found or inaccessible\n", *sbomPath)
		return 2
	}
	if !fileExists(*keyPath) {
		fmt.Fprintf(stderr, "error: private key file %q not found or inaccessible\n", *keyPath)
		return 2
	}

	res, err := release.SBOMSign(release.SignInput{
		ArtifactPath: *sbomPath,
		Package:      *pkgName,
		Version:      *version,
		KeyPath:      *keyPath,
		OutPath:      *out,
		Force:        *force,
	})
	if err != nil {
		fmt.Fprintf(stderr, "error: sbom sign failed: %v\n", err)
		return 2
	}
	fmt.Fprintf(stderr, "signed sbom with %s (%s), wrote %s\n", res.KeyID, res.Profile, res.BundlePath)
	return 0
}

func runSBOMVerify(args []string, stdout, stderr io.Writer) int {
	fs := newFlagSet("sbom verify", sbomVerifyUsage, stderr)
	sbomPath := fs.String("sbom", "", "path to SBOM")
	bundlePath := fs.String("bundle", "", "path to SBOM bundle")
	trustStore := fs.String("trust-store", "", "path to trust store")
	pkgName := fs.String("package", "", "package name")
	version := fs.String("version", "", "release version")
	jsonOutput := fs.Bool("json", false, "json output")
	if done, code := parseFlags(fs, args); done {
		return code
	}

	inputError := func(msg string) int {
		if *jsonOutput {
			writeJSON(stdout, VerifyResult{Status: "INPUT_ERROR", Message: msg})
		}
		fmt.Fprintf(stderr, "error: %s\n", msg)
		return 2
	}
	for _, f := range []struct{ name, val string }{
		{"--sbom", *sbomPath}, {"--bundle", *bundlePath}, {"--trust-store", *trustStore},
		{"--package", *pkgName}, {"--version", *version},
	} {
		if f.val == "" {
			return inputError("missing required flag: " + f.name)
		}
	}
	if !packageRegex.MatchString(*pkgName) {
		return inputError(fmt.Sprintf("invalid package name %q", *pkgName))
	}

	res := release.SBOMVerify(release.VerifyInput{
		ArtifactPath:   *sbomPath,
		BundlePath:     *bundlePath,
		TrustStorePath: *trustStore,
		Package:        *pkgName,
		Version:        *version,
	})
	if *jsonOutput {
		writeJSON(stdout, res)
	} else if res.Status == release.StatusOK {
		fmt.Fprintln(stdout, "OK: Tanda tangan dan SBOM valid.")
	} else {
		fmt.Fprintf(stderr, "FAILED: %s - %s\n", res.Status, res.Message)
	}
	return res.ExitCode()
}

func runSBOMCheck(args []string, stdout, stderr io.Writer) int {
	fs := newFlagSet("sbom check", sbomCheckUsage, stderr)
	file := fs.String("file", "", "path to release artifact")
	relBundle := fs.String("bundle", "", "path to release bundle")
	sbomPath := fs.String("sbom", "", "path to SBOM")
	sbomBundle := fs.String("sbom-bundle", "", "path to SBOM bundle")
	trustStore := fs.String("trust-store", "", "path to trust store")
	pkgName := fs.String("package", "", "package name")
	version := fs.String("version", "", "release version")
	jsonOutput := fs.Bool("json", false, "json output")
	if done, code := parseFlags(fs, args); done {
		return code
	}

	inputError := func(msg string) int {
		if *jsonOutput {
			writeJSON(stdout, release.CheckResult{Status: release.StatusInputError, Message: msg})
		}
		fmt.Fprintf(stderr, "error: %s\n", msg)
		return 2
	}
	for _, f := range []struct{ name, val string }{
		{"--file", *file}, {"--bundle", *relBundle}, {"--sbom", *sbomPath}, {"--sbom-bundle", *sbomBundle},
		{"--trust-store", *trustStore}, {"--package", *pkgName}, {"--version", *version},
	} {
		if f.val == "" {
			return inputError("missing required flag: " + f.name)
		}
	}
	if !packageRegex.MatchString(*pkgName) {
		return inputError(fmt.Sprintf("invalid package name %q", *pkgName))
	}

	res := release.SBOMCheck(release.CheckInput{
		ArtifactPath:   *file,
		ReleaseBundle:  *relBundle,
		SBOMPath:       *sbomPath,
		SBOMBundle:     *sbomBundle,
		TrustStorePath: *trustStore,
		Package:        *pkgName,
		Version:        *version,
	})
	if *jsonOutput {
		writeJSON(stdout, res)
	} else if res.Valid {
		fmt.Fprintln(stdout, "OK: "+res.Message)
	} else {
		fmt.Fprintf(stderr, "FAILED: %s - %s\n", res.Status, res.Message)
	}
	return res.ExitCode()
}
