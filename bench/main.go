package main

import (
	"bytes"
	"crypto"
	"crypto/sha256"
	"crypto/x509"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	"github.com/brii26/release-signer/pkg/bundle"
	"github.com/brii26/release-signer/pkg/keys"
	"github.com/brii26/release-signer/pkg/manifest"
	"github.com/brii26/release-signer/pkg/profile"
	"github.com/brii26/release-signer/pkg/sigalg"
	"github.com/brii26/release-signer/pkg/truststore"
)

const measuredSamples = 30
const warmupSamples = 5
const demoPackage = "bench-demo"
const demoVersion = "1.0.0"

var profiles = []profile.Profile{profile.RSAPSS, profile.ECDSA, profile.Ed25519}

// jaga hash in-memory supaya tidak dibuang compiler
var hashSink [sha256.Size]byte

type measurement struct {
	Metric   string          `json:"metric"`
	Profile  profile.Profile `json:"profile"`
	Artifact string          `json:"artifact"`
	statistics
	RawCSV string `json:"raw_csv"`
}

type sizeRecord struct {
	Profile    profile.Profile `json:"profile"`
	Artifact   string          `json:"artifact"`
	PublicDER  int             `json:"public_spki_der_bytes"`
	PrivateDER int             `json:"private_pkcs8_der_bytes"`
	Signature  int             `json:"signature_bytes"`
	Bundle     int             `json:"bundle_file_bytes"`
}

type fileRecord struct {
	Name   string `json:"name"`
	Bytes  int64  `json:"bytes"`
	SHA256 string `json:"sha256"`
}

type report struct {
	Schema       string        `json:"schema"`
	UTC          string        `json:"utc"`
	SourceCommit string        `json:"source_commit"`
	SourceDirty  bool          `json:"source_dirty"`
	Samples      int           `json:"samples"`
	Warmups      int           `json:"warmups"`
	Caveats      []string      `json:"caveats"`
	Files        []fileRecord  `json:"files"`
	Measurements []measurement `json:"measurements"`
	Sizes        []sizeRecord  `json:"sizes"`
}

type config struct {
	DataDir, OutputDir, Binary string
	Profiles                   []profile.Profile
	Artifacts                  []artifactSpec
	Samples, Warmups           int
}

func main() {
	generateOnly := flag.Bool("generate-only", false, "generate deterministic bench/data artifacts, then exit")
	flag.Parse()
	if err := run(*generateOnly); err != nil {
		fmt.Fprintln(os.Stderr, "bench:", err)
		os.Exit(1)
	}
}

func run(generateOnly bool) error {
	if _, err := os.Stat("go.mod"); err != nil {
		return fmt.Errorf("run from the repository root: %w", err)
	}
	missing := generateOnly
	for _, artifact := range standardArtifacts {
		if _, err := os.Stat(filepath.Join("bench/data", artifact.Name)); os.IsNotExist(err) {
			missing = true
		} else if err != nil {
			return err
		}
	}
	if missing {
		if err := generateArtifacts("bench/data", standardArtifacts); err != nil {
			return err
		}
	}
	if generateOnly {
		return nil
	}
	tmp, err := os.MkdirTemp("", "release-signer-bench-*")
	if err != nil {
		return err
	}
	defer os.RemoveAll(tmp)
	commit, err := commandText("git", "rev-parse", "HEAD")
	if err != nil {
		return err
	}
	dirty, err := commandText("git", "status", "--porcelain", "--untracked-files=no")
	if err != nil {
		return err
	}
	binary := filepath.Join(tmp, "release-signer")
	version := "bench-" + commit
	if dirty != "" {
		version += "-dirty"
	}
	if _, err := commandText("go", "build", "-trimpath", "-ldflags", "-s -w -X main.version="+version, "-o", binary, "./cmd/release-signer"); err != nil {
		return err
	}
	r := report{
		Schema: "release-signer-benchmark/v1", UTC: time.Now().UTC().Format(time.RFC3339),
		SourceCommit: commit, SourceDirty: dirty != "", Samples: measuredSamples, Warmups: warmupSamples,
		Caveats: []string{
			"Machine-local measurements before the final release tag; not publication-quality controlled-hardware evidence.",
			"Serial rounds with five warmups and 30 samples, except keygen has 30 samples and no warmups; no CPU pinning, frequency locking, or cache eviction.",
			"Artifacts and demo keys/trust store are prepared outside timing. Demo keys are generated once per profile and held fixed across artifacts and measured rounds, then deleted.",
			"E2E includes subprocess startup, actual filesystem I/O, parsing, hashing, signing/verification, and bundle write/fsync; OS caches may be warm.",
			"Sign/verify microbenchmarks use canonical manifest M, not artifact bytes or a prehash; profile-internal hashing is included.",
		},
	}
	cfg := config{"bench/data", filepath.Join(tmp, "results"), binary, profiles, standardArtifacts, measuredSamples, warmupSamples}
	if err := runSuite(cfg, &r); err != nil {
		return err
	}
	if err := writeReport(cfg.OutputDir, r, binary); err != nil {
		return err
	}
	// publish hasil run yang sukses, run gagal tidak menimpa hasil lama
	if err := os.MkdirAll("results", 0755); err != nil {
		return err
	}
	if err := os.RemoveAll("results/bench"); err != nil {
		return err
	}
	if err := copyResults(cfg.OutputDir, "results/bench"); err != nil {
		return err
	}
	fmt.Println("wrote results/bench (30 samples per CSV; warmups excluded)")
	return nil
}

func runSuite(cfg config, r *report) error {
	if cfg.Samples < 1 || cfg.Warmups < 0 {
		return fmt.Errorf("invalid sample counts")
	}
	if err := os.MkdirAll(filepath.Join(cfg.OutputDir, "raw"), 0755); err != nil {
		return err
	}
	keyDir, err := os.MkdirTemp("", "release-signer-bench-keys-*")
	if err != nil {
		return err
	}
	defer os.RemoveAll(keyDir)
	type demo struct {
		key                    crypto.Signer
		id, keyPath, trustPath string
		publicDER, privateDER  int
	}
	demos := make(map[profile.Profile]demo)
	for _, p := range cfg.Profiles {
		fmt.Fprintf(os.Stderr, "bench: keygen %s\n", p)
		var key crypto.Signer
		err := record(cfg, r, "keygen", p, "none", 0, func() (time.Duration, error) {
			start := time.Now()
			generated, err := keys.Generate(p)
			elapsed := time.Since(start)
			if err != nil {
				return 0, err
			}
			actual, err := keys.ProfileOf(generated.Public())
			if err != nil || actual != p {
				return 0, fmt.Errorf("generated key profile mismatch: %s, %v", actual, err)
			}
			key = generated
			return elapsed, nil
		})
		if err != nil {
			return err
		}
		// pakai ulang key valid terakhir, setup disk/DER/trust tidak diukur
		id, err := keys.KeyID(key.Public())
		if err != nil {
			return err
		}
		keyPath, _, err := keys.WriteKeyPair(filepath.Join(keyDir, string(p)), key, false)
		if err != nil {
			return err
		}
		pub, err := keys.MarshalPublicPEM(key.Public())
		if err != nil {
			return err
		}
		store := &truststore.Store{}
		if _, _, err := store.Add(pub, demoPackage); err != nil {
			return err
		}
		trustPath := filepath.Join(keyDir, string(p)+"-trust.json")
		if err := store.Save(trustPath); err != nil {
			return err
		}
		pubDER, err := x509.MarshalPKIXPublicKey(key.Public())
		if err != nil {
			return err
		}
		privDER, err := x509.MarshalPKCS8PrivateKey(key)
		if err != nil {
			return err
		}
		demos[p] = demo{key, id, keyPath, trustPath, len(pubDER), len(privDER)}
	}
	for _, artifact := range cfg.Artifacts {
		data, digest, err := loadArtifact(cfg.DataDir, artifact)
		if err != nil {
			return err
		}
		r.Files = append(r.Files, fileRecord{artifact.Name, artifact.Size, digest})
		for _, p := range cfg.Profiles {
			fmt.Fprintf(os.Stderr, "bench: %s %s\n", p, artifact.Name)
			d := demos[p]
			m, err := manifest.New(demoPackage, demoVersion, string(p), d.id, artifact.Name, artifact.Size, digest)
			if err != nil {
				return err
			}
			message := m.Canonical()
			sig, err := sigalg.Sign(p, d.key, message)
			if err != nil {
				return err
			}
			if !sigalg.Verify(p, d.key.Public(), message, sig) {
				return fmt.Errorf("initial signature invalid")
			}
			err = record(cfg, r, "hash", p, artifact.Name, cfg.Warmups, func() (time.Duration, error) {
				start := time.Now()
				hashSink = sha256.Sum256(data)
				elapsed := time.Since(start)
				if fmt.Sprintf("%x", hashSink) != digest {
					return 0, fmt.Errorf("hash mismatch")
				}
				return elapsed, nil
			})
			if err != nil {
				return err
			}
			err = record(cfg, r, "sign", p, artifact.Name, cfg.Warmups, func() (time.Duration, error) {
				start := time.Now()
				result, err := sigalg.Sign(p, d.key, message)
				elapsed := time.Since(start)
				if err != nil {
					return 0, err
				}
				if len(result) != p.SignatureLen() || !sigalg.Verify(p, d.key.Public(), message, result) {
					return 0, fmt.Errorf("signature validation failed")
				}
				return elapsed, nil
			})
			if err != nil {
				return err
			}
			err = record(cfg, r, "verify", p, artifact.Name, cfg.Warmups, func() (time.Duration, error) {
				start := time.Now()
				valid := sigalg.Verify(p, d.key.Public(), message, sig)
				elapsed := time.Since(start)
				if !valid {
					return 0, fmt.Errorf("verification failed")
				}
				return elapsed, nil
			})
			if err != nil {
				return err
			}
			bundlePath := filepath.Join(keyDir, string(p)+"-"+artifact.Name+".bundle.json")
			artifactPath, err := filepath.Abs(filepath.Join(cfg.DataDir, artifact.Name))
			if err != nil {
				return err
			}
			signArgs := []string{"sign", "--file", artifactPath, "--package", demoPackage, "--version", demoVersion, "--key", d.keyPath, "--out", bundlePath, "--force"}
			verifyArgs := []string{"verify", "--file", artifactPath, "--bundle", bundlePath, "--trust-store", d.trustPath, "--package", demoPackage, "--version", demoVersion, "--json"}
			check := func() error { _, err := timedCommand(cfg.Binary, verifyArgs, p, d.id); return err }
			err = record(cfg, r, "e2e_sign", p, artifact.Name, cfg.Warmups, func() (time.Duration, error) {
				elapsed, err := timedCommand(cfg.Binary, signArgs, "", "")
				if err != nil {
					return 0, err
				}
				// validasi tiap bundle baru dengan CLI asli di luar timing sign
				if err := check(); err != nil {
					return 0, err
				}
				return elapsed, nil
			})
			if err != nil {
				return err
			}
			err = record(cfg, r, "e2e_verify", p, artifact.Name, cfg.Warmups, func() (time.Duration, error) {
				return timedCommand(cfg.Binary, verifyArgs, p, d.id)
			})
			if err != nil {
				return err
			}
			bundleData, err := os.ReadFile(bundlePath)
			if err != nil {
				return err
			}
			bm, bs, err := bundle.ParseStrict(bundleData)
			if err != nil {
				return err
			}
			if !bytes.Equal(bm, message) || len(bs) != p.SignatureLen() || !sigalg.Verify(p, d.key.Public(), bm, bs) {
				return fmt.Errorf("CLI bundle mismatch")
			}
			r.Sizes = append(r.Sizes, sizeRecord{p, artifact.Name, d.publicDER, d.privateDER, len(bs), len(bundleData)})
		}
	}
	return nil
}

func record(cfg config, r *report, metric string, p profile.Profile, artifact string, warmups int, sample func() (time.Duration, error)) error {
	values := make([]int64, 0, cfg.Samples)
	for i := -warmups; i < cfg.Samples; i++ {
		elapsed, err := sample()
		if err != nil {
			return fmt.Errorf("%s/%s/%s round %d: %w", metric, p, artifact, i, err)
		}
		if i >= 0 {
			values = append(values, elapsed.Nanoseconds())
		}
	}
	stats, err := summarize(values)
	if err != nil {
		return err
	}
	name := filepath.Join("raw", metric+"_"+string(p)+"_"+artifact+".csv")
	var raw bytes.Buffer
	for _, n := range values {
		fmt.Fprintln(&raw, n)
	}
	if err := os.WriteFile(filepath.Join(cfg.OutputDir, name), raw.Bytes(), 0644); err != nil {
		return err
	}
	r.Measurements = append(r.Measurements, measurement{metric, p, artifact, stats, filepath.ToSlash(name)})
	return nil
}

func timedCommand(binary string, args []string, p profile.Profile, keyID string) (time.Duration, error) {
	cmd := exec.Command(binary, args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	start := time.Now()
	err := cmd.Run()
	elapsed := time.Since(start)
	if err != nil {
		return 0, fmt.Errorf("%s: %w: %s", args[0], err, stderr.String())
	}
	if p != "" {
		var result struct {
			Valid                                      bool `json:"valid"`
			Status, Algorithm, KeyID, Package, Version string
		}
		if err := json.Unmarshal(stdout.Bytes(), &result); err != nil {
			return 0, fmt.Errorf("verify JSON: %w", err)
		}
		if !result.Valid || result.Status != "OK" || result.Algorithm != string(p) || result.KeyID != keyID || result.Package != demoPackage || result.Version != demoVersion {
			return 0, fmt.Errorf("unexpected verification result: %s", stdout.String())
		}
	}
	return elapsed, nil
}
