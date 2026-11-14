package cli

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"regexp"
	"strings"

	"github.com/brii26/release-signer/pkg/keys"
	"github.com/brii26/release-signer/pkg/profile"
	"github.com/brii26/release-signer/pkg/release"
	"github.com/brii26/release-signer/pkg/truststore"
)

var Version = "dev"

const (
	ProfileRSAPSS  = "rsa-pss-sha256"
	ProfileECDSA   = "ecdsa-p256-sha256"
	ProfileEd25519 = "ed25519"
)

var packageRegex = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,63}$`)

// IsValidAlgorithm checks whether the algorithm matches one of the three profiles.
func IsValidAlgorithm(a string) bool {
	return a == ProfileRSAPSS || a == ProfileECDSA || a == ProfileEd25519
}

// Table 2.9 verification result structure.
type VerifyResult struct {
	Valid     bool    `json:"valid"`
	Status    string  `json:"status"`
	Message   string  `json:"message"`
	Algorithm *string `json:"algorithm"`
	KeyID     *string `json:"keyid"`
	Package   *string `json:"package"`
	Version   *string `json:"version"`
}

func (r VerifyResult) ExitCode() int {
	if r.Status == "OK" {
		return 0
	}
	if r.Status == "INPUT_ERROR" {
		return 2
	}
	return 1
}

type KeygenParams struct {
	Algorithm string
	OutPrefix string
	Force     bool
}

type SignParams struct {
	ArtifactPath string
	Package      string
	Version      string
	KeyPath      string
	OutBundle    string
	Force        bool
}

type VerifyParams struct {
	ArtifactPath   string
	BundlePath     string
	TrustStorePath string
	Package        string
	Version        string
	JSON           bool
}

type TrustAddParams struct {
	KeyPath   string
	Package   string
	StorePath string
}

type TrustListParams struct {
	StorePath string
}

type TrustRemoveParams struct {
	KeyID     string
	StorePath string
}

type KeygenHandler func(p KeygenParams, stdout, stderr io.Writer) error
type SignHandler func(p SignParams, stdout, stderr io.Writer) error
type VerifyHandler func(p VerifyParams) VerifyResult
type TrustAddHandler func(p TrustAddParams, stdout, stderr io.Writer) error
type TrustListHandler func(p TrustListParams, stdout, stderr io.Writer) error
type TrustRemoveHandler func(p TrustRemoveParams, stdout, stderr io.Writer) error

var (
	ErrNotFound = errors.New("not found")

	KeygenAction      KeygenHandler      = defaultKeygen
	SignAction        SignHandler        = defaultSign
	VerifyAction      VerifyHandler      = defaultVerify
	TrustAddAction    TrustAddHandler    = defaultTrustAdd
	TrustListAction   TrustListHandler   = defaultTrustList
	TrustRemoveAction TrustRemoveHandler = defaultTrustRemove
)

func defaultKeygen(p KeygenParams, stdout, stderr io.Writer) error {
	prof, ok := profile.Parse(p.Algorithm)
	if !ok {
		return fmt.Errorf("unsupported algorithm profile %q", p.Algorithm)
	}

	signer, err := keys.Generate(prof)
	if err != nil {
		return fmt.Errorf("failed to generate key %w", err)
	}

	privPath, pubPath, err := keys.WriteKeyPair(p.OutPrefix, signer, p.Force)
	if err != nil {
		return err
	}

	kid, err := keys.KeyID(signer.Public())
	if err != nil {
		return fmt.Errorf("failed to compute keyid: %w", err)
	}

	fmt.Fprintln(stdout, kid)
	fmt.Fprintf(stderr, "wrote %s and %s\n", privPath, pubPath)
	return nil
}

func defaultSign(p SignParams, stdout, stderr io.Writer) error {
	out, err := release.Sign(release.SignInput{
		ArtifactPath: p.ArtifactPath,
		Package:      p.Package,
		Version:      p.Version,
		KeyPath:      p.KeyPath,
		OutPath:      p.OutBundle,
		Force:        p.Force,
	})
	if err != nil {
		return err
	}
	fmt.Fprintf(stderr, "signed with %s (%s), wrote %s\n", out.KeyID, out.Profile, out.BundlePath)
	return nil
}

func defaultVerify(p VerifyParams) VerifyResult {
	in := release.VerifyInput{
		ArtifactPath:   p.ArtifactPath,
		BundlePath:     p.BundlePath,
		TrustStorePath: p.TrustStorePath,
		Package:        p.Package,
		Version:        p.Version,
	}
	res := release.Verify(in)
	return VerifyResult{
		Valid:     res.Valid,
		Status:    string(res.Status),
		Message:   res.Message,
		Algorithm: res.Algorithm,
		KeyID:     res.KeyID,
		Package:   res.Package,
		Version:   res.Version,
	}
}

func defaultTrustAdd(p TrustAddParams, stdout, stderr io.Writer) error {
	pubPEM, err := os.ReadFile(p.KeyPath)
	if err != nil {
		return err
	}
	store, err := truststore.LoadOrEmpty(p.StorePath)
	if err != nil {
		return err
	}
	entry, changed, err := store.Add(pubPEM, p.Package)
	if err != nil {
		return err
	}
	if changed {
		if err := store.Save(p.StorePath); err != nil {
			return err
		}
	}
	return printTrustEntry(stdout, entry)
}

func defaultTrustList(p TrustListParams, stdout, stderr io.Writer) error {
	store, err := truststore.Load(p.StorePath)
	if err != nil {
		return err
	}
	for _, entry := range store.Keys {
		if err := printTrustEntry(stdout, entry); err != nil {
			return err
		}
	}
	return nil
}

func defaultTrustRemove(p TrustRemoveParams, stdout, stderr io.Writer) error {
	store, err := truststore.Load(p.StorePath)
	if err != nil {
		return err
	}
	if err := store.Remove(p.KeyID); err != nil {
		return err
	}
	if err := store.Save(p.StorePath); err != nil {
		return err
	}
	_, err = fmt.Fprintf(stdout, "removed keyid=%s\n", p.KeyID)
	return err
}

func printTrustEntry(w io.Writer, entry truststore.Entry) error {
	_, err := fmt.Fprintf(w, "keyid=%s algorithm=%s packages=%s\n",
		entry.KeyID, entry.Algorithm, strings.Join(entry.Packages, ","))
	return err
}

const rootUsage = `release-signer: sign and verify software releases

Usage:
  release-signer <command> [flags]

Commands:
  keygen         Generate a new cryptographic keypair
  sign           Sign a release artifact and create a bundle
  verify         Verify an artifact against a release bundle and trust store
  trust          Manage trusted keys in the trust store
  sbom           Generate, sign, and verify an SBOM bound to a release artifact

Global Flags:
  -h, --help     Show this help message
  --version      Show program version
`

const keygenUsage = `Usage: release-signer keygen --algorithm <profil> --out <prefix> [--force]

Generate a new cryptographic keypair and write <prefix>.key.pem and <prefix>.pub.pem.
Prints keyid (SHA-256 fingerprint) to stdout.

Flags:
  --algorithm string   Algorithm profile: rsa-pss-sha256, ecdsa-p256-sha256, or ed25519 (required)
  --out string         Output keypath prefix (required)
  --force              Overwrite output key files if they already exist
  -h, --help           Show help for keygen
`

const signUsage = `Usage: release-signer sign --file <path> --package <nama> --version <versi> --key <private.pem> --out <bundle.json> [--force]

Sign a release artifact and create a signature bundle JSON.

Flags:
  --file string       Path to artifact file (required)
  --package string    Package name (pattern [a-z0-9][a-z0-9._-]{0,63}) (required)
  --version string    Release version string (required)
  --key string        Path to private key PEM (required)
  --out string        Path to output bundle JSON (required)
  --force             Overwrite output bundle file if it already exists
  -h, --help          Show help for sign
`

const verifyUsage = `Usage: release-signer verify --file <path> --bundle <bundle.json> --trust-store <trust.json> --package <nama> --version <versi> [--json]

Verify an artifact against a release bundle and trust store.

Flags:
  --file string          Path to artifact file (required)
  --bundle string        Path to bundle JSON (required)
  --trust-store string   Path to trust store JSON (required)
  --package string       Expected package name (required)
  --version string       Expected version string (required)
  --json                 Output verification result as single JSON object
  -h, --help             Show help for verify
`

const trustUsage = `Usage: release-signer trust <subcommand> [flags]

Manage trusted keys in the trust store.

Subcommands:
  add       Add a public key to trust store
  list      List trusted keys in trust store
  remove    Remove a key from trust store by keyid

Flags:
  -h, --help   Show help for trust
`

const trustAddUsage = `Usage: release-signer trust add --key <public.pem> --package <nama> --store <trust.json>

Add a public key to the trust store scoped to allowed package.

Flags:
  --key string       Path to public key PEM (required)
  --package string   Package name to authorize (required)
  --store string     Path to trust store JSON (required)
  -h, --help         Show help for trust add
`

const trustListUsage = `Usage: release-signer trust list --store <trust.json>

List all trusted keys and allowed packages in the trust store.

Flags:
  --store string   Path to trust store JSON (required)
  -h, --help       Show help for trust list
`

const trustRemoveUsage = `Usage: release-signer trust remove --keyid <fingerprint> --store <trust.json>

Remove a trusted key from the trust store by keyid.

Flags:
  --keyid string   Key fingerprint (64-char hex) to remove (required)
  --store string   Path to trust store JSON (required)
  -h, --help       Show help for trust remove
`

// Run executes the CLI with the provided arguments and streams.
func Run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprint(stderr, rootUsage)
		return 2
	}

	switch args[0] {
	case "--help", "-h", "help":
		fmt.Fprint(stdout, rootUsage)
		return 0
	case "--version":
		fmt.Fprintln(stdout, Version)
		return 0
	case "keygen":
		return runKeygen(args[1:], stdout, stderr)
	case "sign":
		return runSign(args[1:], stdout, stderr)
	case "verify":
		return runVerify(args[1:], stdout, stderr)
	case "trust":
		return runTrust(args[1:], stdout, stderr)
	case "sbom":
		return runSBOM(args[1:], stdout, stderr)
	default:
		fmt.Fprintf(stderr, "unknown command %q\n\n%s", args[0], rootUsage)
		return 2
	}
}

func runKeygen(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("keygen", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() {
		fmt.Fprint(stderr, keygenUsage)
	}

	algorithm := fs.String("algorithm", "", "algorithm profile")
	outPrefix := fs.String("out", "", "output key prefix")
	force := fs.Bool("force", false, "overwrite output files")

	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}

	if *algorithm == "" {
		fmt.Fprintln(stderr, "error: --algorithm is required")
		return 2
	}
	if !IsValidAlgorithm(*algorithm) {
		fmt.Fprintf(stderr, "error: unsupported algorithm %q (must be %s, %s, or %s)\n",
			*algorithm, ProfileRSAPSS, ProfileECDSA, ProfileEd25519)
		return 2
	}
	if *outPrefix == "" {
		fmt.Fprintln(stderr, "error: --out is required")
		return 2
	}

	if !*force {
		privPath := *outPrefix + ".key.pem"
		pubPath := *outPrefix + ".pub.pem"
		if fileExists(privPath) || fileExists(pubPath) {
			fmt.Fprintf(stderr, "error: output files already exist; use --force to overwrite\n")
			return 2
		}
	}

	params := KeygenParams{
		Algorithm: *algorithm,
		OutPrefix: *outPrefix,
		Force:     *force,
	}

	if err := KeygenAction(params, stdout, stderr); err != nil {
		fmt.Fprintf(stderr, "error: keygen failed: %v\n", err)
		return 2
	}
	return 0
}

func runSign(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("sign", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() {
		fmt.Fprint(stderr, signUsage)
	}

	artifact := fs.String("file", "", "path to artifact")
	pkgName := fs.String("package", "", "package name")
	version := fs.String("version", "", "release version")
	keyPath := fs.String("key", "", "private key path")
	outBundle := fs.String("out", "", "output bundle path")
	force := fs.Bool("force", false, "overwrite output bundle")

	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}

	if *artifact == "" || *pkgName == "" || *version == "" || *keyPath == "" || *outBundle == "" {
		fmt.Fprintln(stderr, "error: missing required flags (--file, --package, --version, --key, --out)")
		return 2
	}

	if !packageRegex.MatchString(*pkgName) {
		fmt.Fprintf(stderr, "error: invalid package name %q (must match ^[a-z0-9][a-z0-9._-]{0,63}$)\n", *pkgName)
		return 2
	}

	if !*force && fileExists(*outBundle) {
		fmt.Fprintf(stderr, "error: output bundle %q already exists; use --force to overwrite\n", *outBundle)
		return 2
	}

	if !fileExists(*artifact) {
		fmt.Fprintf(stderr, "error: artifact file %q not found or inaccessible\n", *artifact)
		return 2
	}

	if !fileExists(*keyPath) {
		fmt.Fprintf(stderr, "error: private key file %q not found or inaccessible\n", *keyPath)
		return 2
	}

	params := SignParams{
		ArtifactPath: *artifact,
		Package:      *pkgName,
		Version:      *version,
		KeyPath:      *keyPath,
		OutBundle:    *outBundle,
		Force:        *force,
	}

	if err := SignAction(params, stdout, stderr); err != nil {
		fmt.Fprintf(stderr, "error: sign failed: %v\n", err)
		return 2
	}
	return 0
}

func runVerify(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("verify", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() {
		fmt.Fprint(stderr, verifyUsage)
	}

	artifact := fs.String("file", "", "path to artifact")
	bundle := fs.String("bundle", "", "path to bundle")
	trustStore := fs.String("trust-store", "", "path to trust store")
	pkgName := fs.String("package", "", "package name")
	version := fs.String("version", "", "release version")
	jsonOutput := fs.Bool("json", false, "json output")

	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}

	emitInputError := func(msg string) int {
		if *jsonOutput {
			res := VerifyResult{
				Valid:   false,
				Status:  "INPUT_ERROR",
				Message: msg,
			}
			writeJSON(stdout, res)
		}
		fmt.Fprintf(stderr, "error: %s\n", msg)
		return 2
	}

	if *artifact == "" {
		return emitInputError("missing required flag: --file")
	}
	if *bundle == "" {
		return emitInputError("missing required flag: --bundle")
	}
	if *trustStore == "" {
		return emitInputError("missing required flag: --trust-store")
	}
	if *pkgName == "" {
		return emitInputError("missing required flag: --package")
	}
	if *version == "" {
		return emitInputError("missing required flag: --version")
	}

	if !packageRegex.MatchString(*pkgName) {
		return emitInputError(fmt.Sprintf("invalid package name %q", *pkgName))
	}

	if !fileExists(*artifact) {
		return emitInputError(fmt.Sprintf("artifact file %q not found or inaccessible", *artifact))
	}
	if !fileExists(*bundle) {
		return emitInputError(fmt.Sprintf("bundle file %q not found or inaccessible", *bundle))
	}
	if !fileExists(*trustStore) {
		return emitInputError(fmt.Sprintf("trust store file %q not found or inaccessible", *trustStore))
	}

	params := VerifyParams{
		ArtifactPath:   *artifact,
		BundlePath:     *bundle,
		TrustStorePath: *trustStore,
		Package:        *pkgName,
		Version:        *version,
		JSON:           *jsonOutput,
	}

	res := VerifyAction(params)

	if *jsonOutput {
		writeJSON(stdout, res)
	} else {
		if res.Status == "OK" {
			fmt.Fprintln(stdout, "OK: Tanda tangan dan artefak valid.")
		} else {
			fmt.Fprintf(stderr, "FAILED: %s - %s\n", res.Status, res.Message)
		}
	}

	return res.ExitCode()
}

func runTrust(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprint(stderr, trustUsage)
		return 2
	}

	switch args[0] {
	case "--help", "-h", "help":
		fmt.Fprint(stdout, trustUsage)
		return 0
	case "add":
		return runTrustAdd(args[1:], stdout, stderr)
	case "list":
		return runTrustList(args[1:], stdout, stderr)
	case "remove":
		return runTrustRemove(args[1:], stdout, stderr)
	default:
		fmt.Fprintf(stderr, "unknown trust command %q\n\n%s", args[0], trustUsage)
		return 2
	}
}

func runTrustAdd(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("trust add", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() {
		fmt.Fprint(stderr, trustAddUsage)
	}

	keyPath := fs.String("key", "", "public key PEM path")
	pkgName := fs.String("package", "", "authorized package name")
	storePath := fs.String("store", "", "trust store path")

	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}

	if *keyPath == "" || *pkgName == "" || *storePath == "" {
		fmt.Fprintln(stderr, "error: missing required flags (--key, --package, --store)")
		return 2
	}

	if !packageRegex.MatchString(*pkgName) {
		fmt.Fprintf(stderr, "error: invalid package name %q\n", *pkgName)
		return 2
	}

	if !fileExists(*keyPath) {
		fmt.Fprintf(stderr, "error: public key file %q not found or inaccessible\n", *keyPath)
		return 2
	}

	params := TrustAddParams{
		KeyPath:   *keyPath,
		Package:   *pkgName,
		StorePath: *storePath,
	}

	if err := TrustAddAction(params, stdout, stderr); err != nil {
		fmt.Fprintf(stderr, "error: trust add failed: %v\n", err)
		return 2
	}
	return 0
}

func runTrustList(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("trust list", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() {
		fmt.Fprint(stderr, trustListUsage)
	}

	storePath := fs.String("store", "", "trust store path")

	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}

	if *storePath == "" {
		fmt.Fprintln(stderr, "error: missing required flag: --store")
		return 2
	}

	if !fileExists(*storePath) {
		fmt.Fprintf(stderr, "error: trust store %q not found or inaccessible\n", *storePath)
		return 2
	}

	params := TrustListParams{
		StorePath: *storePath,
	}

	if err := TrustListAction(params, stdout, stderr); err != nil {
		fmt.Fprintf(stderr, "error: trust list failed: %v\n", err)
		return 2
	}
	return 0
}

func runTrustRemove(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("trust remove", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() {
		fmt.Fprint(stderr, trustRemoveUsage)
	}

	keyID := fs.String("keyid", "", "key fingerprint")
	storePath := fs.String("store", "", "trust store path")

	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}

	if *keyID == "" || *storePath == "" {
		fmt.Fprintln(stderr, "error: missing required flags (--keyid, --store)")
		return 2
	}

	if !fileExists(*storePath) {
		fmt.Fprintf(stderr, "error: trust store %q not found or inaccessible\n", *storePath)
		return 2
	}

	params := TrustRemoveParams{
		KeyID:     *keyID,
		StorePath: *storePath,
	}

	if err := TrustRemoveAction(params, stdout, stderr); err != nil {
		fmt.Fprintf(stderr, "error: trust remove failed: %v\n", err)
		return 2
	}
	return 0
}

func fileExists(p string) bool {
	info, err := os.Stat(p)
	if err != nil {
		return false
	}
	return !info.IsDir()
}

func writeJSON(w io.Writer, val any) {
	b, err := json.Marshal(val)
	if err != nil {
		fmt.Fprintf(w, "{\"valid\":false,\"status\":\"FORMAT_ERROR\",\"message\":\"failed to marshal json\"}\n")
		return
	}
	w.Write(b)
	w.Write([]byte("\n"))
}
