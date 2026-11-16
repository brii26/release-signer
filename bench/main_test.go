package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/brii26/release-signer/pkg/profile"
)

func TestSummarize(t *testing.T) {
	ascending := make([]int64, 30)
	for i := range ascending {
		ascending[i] = int64(i + 1)
	}
	for _, tt := range []struct {
		name   string
		values []int64
		median float64
		p95    int64
	}{
		{"one to thirty", ascending, 15.5, 29},
		{"unsorted outlier", []int64{1000000, 2, 5, 1, 3}, 3, 1000000},
		{"single", []int64{7}, 7, 7},
		{"even unsorted", []int64{9, 1, 5, 3}, 4, 9},
	} {
		t.Run(tt.name, func(t *testing.T) {
			before := append([]int64(nil), tt.values...)
			got, err := summarize(tt.values)
			if err != nil || got.MedianNS != tt.median || got.P95NS != tt.p95 || got.Samples != len(tt.values) {
				t.Fatalf("got %+v, %v", got, err)
			}
			if !reflect.DeepEqual(before, tt.values) {
				t.Fatal("sample order mutated")
			}
		})
	}
	for _, values := range [][]int64{nil, {}, {-1}} {
		if _, err := summarize(values); err == nil {
			t.Fatalf("expected error for %v", values)
		}
	}
}

func TestArtifactDeterminism(t *testing.T) {
	for _, size := range []int64{0, 1, 1024, 65537} {
		var first, second bytes.Buffer
		if err := writeArtifact(&first, size); err != nil {
			t.Fatal(err)
		}
		if err := writeArtifact(&second, size); err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(first.Bytes(), second.Bytes()) || int64(first.Len()) != size {
			t.Fatal("non-deterministic output or incorrect size")
		}
		for i, b := range first.Bytes() {
			if b != byte(i) {
				t.Fatalf("incorrect byte at %d", i)
			}
		}
	}
	var small bytes.Buffer
	if err := writeArtifact(&small, 1024); err != nil {
		t.Fatal(err)
	}
	if digest := fmt.Sprintf("%x", sha256.Sum256(small.Bytes())); digest != "785b0751fc2c53dc14a4ce3d800e69ef9ce1009eb327ccf458afe09c242c26c9" {
		t.Fatal(digest)
	}
	dir := t.TempDir()
	spec := artifactSpec{"small.bin", 1024}
	if err := generateArtifacts(dir, []artifactSpec{spec}); err != nil {
		t.Fatal(err)
	}
	if _, _, err := loadArtifact(dir, spec); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, spec.Name)
	data := bytes.Repeat([]byte{0}, 1024)
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := loadArtifact(dir, spec); err == nil {
		t.Fatal("accepted corrupt data")
	}
	if err := os.WriteFile(path, data[:10], 0600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := loadArtifact(dir, spec); err == nil {
		t.Fatal("accepted wrong size")
	}
}

// Smoke test: subprocess asli dengan Ed25519, artifact 1 KiB, 1 warmup, 2 sample, di temp dir.
func TestSmallRun(t *testing.T) {
	root, err := filepath.Abs("..")
	if err != nil {
		t.Fatal(err)
	}
	tmp := t.TempDir()
	binary := filepath.Join(tmp, "release-signer")
	// go test set cwd ke bench, jadi build CLI dari root module
	if _, err := commandText("go", "build", "-o", binary, filepath.Join(root, "cmd/release-signer")); err != nil {
		t.Fatal(err)
	}
	cfg := config{filepath.Join(tmp, "data"), filepath.Join(tmp, "results"), binary, []profile.Profile{profile.Ed25519}, []artifactSpec{{"small.bin", 1024}}, 2, 1}
	if err := generateArtifacts(cfg.DataDir, cfg.Artifacts); err != nil {
		t.Fatal(err)
	}
	r := report{Samples: 2, Warmups: 1}
	if err := runSuite(cfg, &r); err != nil {
		t.Fatal(err)
	}
	if len(r.Measurements) != 6 || len(r.Sizes) != 1 || len(r.Files) != 1 {
		t.Fatalf("incomplete report: %+v", r)
	}
	for _, metric := range r.Measurements {
		raw, err := os.ReadFile(filepath.Join(cfg.OutputDir, metric.RawCSV))
		if err != nil {
			t.Fatal(err)
		}
		if strings.Count(string(raw), "\n") != 2 || metric.Samples != 2 {
			t.Fatalf("warmups leaked into %s", metric.RawCSV)
		}
	}
	if r.Sizes[0].Signature != 64 || r.Sizes[0].PublicDER != 44 || r.Sizes[0].PrivateDER != 48 || r.Sizes[0].Bundle <= 64 {
		t.Fatalf("incorrect sizes: %+v", r.Sizes[0])
	}
	if err := writeReport(cfg.OutputDir, r, binary); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(filepath.Join(cfg.OutputDir, "summary.json"))
	if err != nil {
		t.Fatal(err)
	}
	var decoded report
	if err := json.Unmarshal(data, &decoded); err != nil || len(decoded.Measurements) != 6 {
		t.Fatalf("JSON report: %v", err)
	}
}

// pin kontrak dataset default tanpa jalanin crypto mahal
func TestRecordSampleContract(t *testing.T) {
	cfg := config{OutputDir: t.TempDir(), Samples: measuredSamples, Warmups: warmupSamples}
	if err := os.MkdirAll(filepath.Join(cfg.OutputDir, "raw"), 0755); err != nil {
		t.Fatal(err)
	}
	var r report
	calls := 0
	if err := record(cfg, &r, "hash", profile.Ed25519, "small.bin", cfg.Warmups, func() (time.Duration, error) {
		calls++
		return time.Duration(calls), nil
	}); err != nil {
		t.Fatal(err)
	}
	if calls != 35 {
		t.Fatalf("got %d total rounds", calls)
	}
	data, err := os.ReadFile(filepath.Join(cfg.OutputDir, r.Measurements[0].RawCSV))
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	if len(lines) != 30 {
		t.Fatalf("got %d CSV rows", len(lines))
	}
	for i, line := range lines {
		n, err := strconv.Atoi(line)
		if err != nil || n != i+6 {
			t.Fatalf("row %d: %q (%v)", i, line, err)
		}
	}
	before := len(r.Measurements)
	if err := record(cfg, &r, "failed", profile.Ed25519, "small.bin", 0, func() (time.Duration, error) {
		return 0, errors.New("operation failed")
	}); err == nil {
		t.Fatal("failed operation accepted")
	}
	if len(r.Measurements) != before {
		t.Fatal("failed operation recorded")
	}
}
