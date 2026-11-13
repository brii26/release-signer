package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
)

func commandText(name string, args ...string) (string, error) {
	out, err := exec.Command(name, args...).CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("%s: %w: %s", name, err, out)
	}
	return strings.TrimSpace(string(out)), nil
}

func writeReport(dir string, r report, binary string) error {
	var files bytes.Buffer
	fmt.Fprintln(&files, "# One shared artifact per size; all profiles read these exact files.")
	fmt.Fprintln(&files, "# sha256 bytes artifact")
	for _, f := range r.Files {
		fmt.Fprintf(&files, "%s %d bench/data/%s\n", f.SHA256, f.Bytes, f.Name)
	}
	if err := os.WriteFile(filepath.Join(dir, "files.txt"), files.Bytes(), 0644); err != nil {
		return err
	}
	data, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(dir, "summary.json"), append(data, '\n'), 0644); err != nil {
		return err
	}
	var md bytes.Buffer
	fmt.Fprintln(&md, "# Local benchmark results")
	fmt.Fprintf(&md, "\nUTC: %s. Source: `%s` (tracked source dirty: %t).\n", r.UTC, r.SourceCommit, r.SourceDirty)
	for _, caveat := range r.Caveats {
		fmt.Fprintf(&md, "\n- %s\n", caveat)
	}
	fmt.Fprintln(&md, "\nRun from the repository root with `make bench` (or `go run ./bench`). See [bench/README.md](../../bench/README.md) for methodology. Binary build and artifact generation are excluded from timing. Library keygen uses `keys.Generate` directly. The e2e sign command also includes the signer's built-in signature self-check. Per-round output checks happen after the timer stops; e2e sign additionally invokes an untimed CLI verify, warming filesystem caches.")
	fmt.Fprintln(&md, "\nRaw CSVs have **no header**: exactly 30 lines, one integer nanosecond duration per line in collection order. Warmups are omitted. Median averages the middle pair; p95 uses nearest rank ceil(0.95 × 30) = 29. Keygen uses artifact `none`; every other metric covers every profile/artifact combination. Durations below are milliseconds; JSON retains nanoseconds.")
	fmt.Fprintln(&md, "\n| Metric | Profile | Artifact | Samples | Median (ms) | p95 (ms) | Raw CSV |\n|---|---|---|---:|---:|---:|---|")
	for _, m := range r.Measurements {
		fmt.Fprintf(&md, "| %s | %s | %s | %d | %.6f | %.6f | [%s](%s) |\n", m.Metric, m.Profile, m.Artifact, m.Samples, m.MedianNS/1e6, float64(m.P95NS)/1e6, filepath.Base(m.RawCSV), m.RawCSV)
	}
	fmt.Fprintln(&md, "\n## Serialized sizes\n\nPrivate and public key sizes are DER PKCS#8 and DER SPKI, respectively; no private key bytes are retained. Bundle sizes are measured from the actual CLI output file, including JSON/base64 overhead and its final newline.")
	fmt.Fprintln(&md, "\n| Profile | Artifact | Public DER (bytes) | Private DER (bytes) | Signature (bytes) | Bundle file (bytes) |\n|---|---|---:|---:|---:|---:|")
	for _, s := range r.Sizes {
		fmt.Fprintf(&md, "| %s | %s | %d | %d | %d | %d |\n", s.Profile, s.Artifact, s.PublicDER, s.PrivateDER, s.Signature, s.Bundle)
	}
	fmt.Fprintln(&md, "\n## Shared artifacts\n\nEvery profile uses these exact byte sequences; digest and size checks precede timing. See [files.txt](files.txt).")
	fmt.Fprintln(&md, "\n| Artifact | Bytes | SHA-256 |\n|---|---:|---|")
	for _, f := range r.Files {
		fmt.Fprintf(&md, "| %s | %d | `%s` |\n", f.Name, f.Bytes, f.SHA256)
	}
	if err := os.WriteFile(filepath.Join(dir, "summary.md"), md.Bytes(), 0644); err != nil {
		return err
	}
	return writeEnvironment(filepath.Join(dir, "env.txt"), r, binary)
}

func writeEnvironment(path string, r report, binary string) error {
	var env bytes.Buffer
	fmt.Fprintf(&env, "UTC: %s\nsource_commit: %s\ntracked_source_dirty: %t\nGOOS: %s\nGOARCH: %s\nruntime.NumCPU (logical cores available): %d\nGOMAXPROCS: %d\n", r.UTC, r.SourceCommit, r.SourceDirty, runtime.GOOS, runtime.GOARCH, runtime.NumCPU(), runtime.GOMAXPROCS(0))
	for _, item := range []struct {
		label, name string
		args        []string
	}{
		{"go version", "go", []string{"version"}}, {"binary version", binary, []string{"--version"}}, {"uname -a", "uname", []string{"-a"}},
	} {
		out, err := commandText(item.name, item.args...)
		if err != nil {
			return err
		}
		fmt.Fprintf(&env, "%s: %s\n", item.label, out)
	}
	for _, path := range []string{"/proc/cpuinfo", "/proc/meminfo", "/etc/os-release"} {
		data, err := os.ReadFile(path)
		fmt.Fprintf(&env, "\n[%s]\n", path)
		if err != nil {
			fmt.Fprintf(&env, "unavailable: %v\n", err)
			continue
		}
		if path == "/proc/cpuinfo" {
			models := make(map[string]bool)
			processors := 0
			for _, line := range strings.Split(string(data), "\n") {
				if strings.HasPrefix(line, "processor\t") {
					processors++
				}
				if strings.HasPrefix(line, "model name") && !models[line] {
					fmt.Fprintln(&env, line)
					models[line] = true
				}
			}
			fmt.Fprintf(&env, "logical processors in /proc/cpuinfo: %d\n", processors)
		} else if path == "/proc/meminfo" {
			for _, line := range strings.Split(string(data), "\n") {
				if strings.HasPrefix(line, "MemTotal:") || strings.HasPrefix(line, "MemAvailable:") {
					fmt.Fprintln(&env, line)
				}
			}
		} else {
			env.Write(data)
		}
	}
	fmt.Fprintln(&env, "\n[caveats]")
	for _, caveat := range r.Caveats {
		fmt.Fprintln(&env, caveat)
	}
	return os.WriteFile(path, env.Bytes(), 0644)
}

func copyResults(from, to string) error {
	return filepath.WalkDir(from, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		rel, err := filepath.Rel(from, path)
		if err != nil {
			return err
		}
		dest := filepath.Join(to, rel)
		if entry.IsDir() {
			return os.MkdirAll(dest, 0755)
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		return os.WriteFile(dest, data, 0644)
	})
}
