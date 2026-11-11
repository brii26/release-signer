package bundle

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/brii26/release-signer/pkg/b64"
	"github.com/brii26/release-signer/pkg/manifest"
)

func sampleManifest(t *testing.T) []byte {
	t.Helper()
	m, err := manifest.New("contoh-app", "1.0.0", "ed25519", strings.Repeat("a", 64),
		"contoh-app.zip", 0, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
	if err != nil {
		t.Fatalf("manifest.New: %v", err)
	}
	return m.Canonical()
}

func TestBuildFormatting(t *testing.T) {
	want := "{\n" +
		"  \"schema\": \"minisign-bundle/v1\",\n" +
		"  \"manifest_b64\": \"e30=\",\n" +
		"  \"signature_b64\": \"AP8=\"\n" +
		"}\n"
	if got := string(Build([]byte("{}"), []byte{0, 0xff})); got != want {
		t.Fatalf("Build() =\n%s\nwant\n%s", got, want)
	}
}

func TestParseStrictRoundTrip(t *testing.T) {
	tests := []struct {
		name     string
		manifest []byte
		sig      []byte
	}{
		{"canonical manifest", sampleManifest(t), bytes.Repeat([]byte{0x7f}, 64)},
		{"empty bytes", nil, nil},
		{"raw bytes", []byte{0, '\n', 0xff, '"', '\\'}, []byte{0, 0xff, '\r'}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			m, sig, err := ParseStrict(Build(tc.manifest, tc.sig))
			if err != nil {
				t.Fatalf("ParseStrict: %v", err)
			}
			if !bytes.Equal(m, tc.manifest) || !bytes.Equal(sig, tc.sig) {
				t.Fatalf("decoded bytes differ: manifest %x, signature %x", m, sig)
			}
		})
	}
}

func TestParseStrictAcceptsReformattedBundle(t *testing.T) {
	m := sampleManifest(t)
	sig := bytes.Repeat([]byte{0xab}, 64)
	pretty := Build(m, sig)
	var compact bytes.Buffer
	if err := json.Compact(&compact, pretty); err != nil {
		t.Fatal(err)
	}
	var indented bytes.Buffer
	if err := json.Indent(&indented, pretty, "", "    "); err != nil {
		t.Fatal(err)
	}
	reversed := fmt.Sprintf(`{"signature_b64":%q,"manifest_b64":%q,"schema":%q}`,
		b64.Encode(sig), b64.Encode(m), Schema)
	for name, data := range map[string][]byte{
		"minified":        compact.Bytes(),
		"four spaces":     indented.Bytes(),
		"reversed fields": []byte(reversed),
		"outer whitespace": append(append([]byte(" \t\r\n"), pretty...),
			[]byte("\t\r\n ")...),
	} {
		t.Run(name, func(t *testing.T) {
			gotManifest, gotSig, err := ParseStrict(data)
			if err != nil {
				t.Fatalf("ParseStrict: %v", err)
			}
			if !bytes.Equal(gotManifest, m) || !bytes.Equal(gotSig, sig) {
				t.Fatal("reformatting changed the decoded bytes")
			}
		})
	}
}

func TestParseStrictRejects(t *testing.T) {
	valid := `{"schema":"minisign-bundle/v1","manifest_b64":"e30=","signature_b64":"c2ln"}`
	swap := func(old, new string) string { return strings.Replace(valid, old, new, 1) }
	tests := []struct {
		name string
		in   string
	}{
		{"extra field", swap(`"schema":`, `"public_key_pem":"untrusted","schema":`)},
		{"missing schema", swap(`"schema":"minisign-bundle/v1",`, ``)},
		{"missing manifest", swap(`"manifest_b64":"e30=",`, ``)},
		{"missing signature", swap(`,"signature_b64":"c2ln"`, ``)},
		{"duplicate schema", swap(`"schema":`, `"schema":"minisign-bundle/v1","schema":`)},
		{"duplicate manifest", swap(`"manifest_b64":`, `"manifest_b64":"e30=","manifest_b64":`)},
		{"duplicate signature", swap(`"signature_b64":`, `"signature_b64":"c2ln","signature_b64":`)},
		{"escaped duplicate", swap(`"schema":`, `"\u0073chema":"minisign-bundle/v1","schema":`)},
		{"wrong schema", swap(`bundle/v1`, `bundle/v2`)},
		{"case sensitive field", swap(`"schema":`, `"Schema":`)},
		{"manifest newline", swap(`"e30="`, `"e30=\n"`)},
		{"signature no padding", swap(`"c2ln"`, `"Zg"`)},
		{"base64 spaces", swap(`"c2ln"`, `"c2 ln"`)},
		{"base64 crlf", swap(`"c2ln"`, `"\r\nc2ln"`)},
		{"base64 url alphabet", swap(`"c2ln"`, `"Zm-_"`)},
		{"base64 excess padding", swap(`"c2ln"`, `"c2ln===="`)},
		{"base64 nonzero pad bits", swap(`"e30="`, `"e31="`)},
		{"invalid syntax", valid[:len(valid)-1]},
		{"trailing object", valid + `{}`},
		{"trailing garbage", valid + `x`},
		{"invalid utf8", swap(`"e30="`, "\"\xff\"")},
		{"bom", "\xEF\xBB\xBF" + valid},
		{"too large", valid + strings.Repeat(" ", MaxSize-len(valid)+1)},
		{"top level array", `[]`},
		{"top level null", `null`},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assertFormatError(t, []byte(tc.in))
		})
	}
	for _, field := range []struct {
		name, value string
	}{
		{"schema", `"minisign-bundle/v1"`},
		{"manifest_b64", `"e30="`},
		{"signature_b64", `"c2ln"`},
	} {
		for _, value := range []string{`null`, `true`, `1`, `{}`, `[]`} {
			t.Run(field.name+" is "+value, func(t *testing.T) {
				assertFormatError(t, []byte(swap(`"`+field.name+`":`+field.value,
					`"`+field.name+`":`+value)))
			})
		}
	}
}

func assertFormatError(t *testing.T, data []byte) {
	t.Helper()
	m, sig, err := ParseStrict(data)
	if !errors.Is(err, ErrFormat) {
		t.Fatalf("ParseStrict error = %v, want ErrFormat", err)
	}
	if m != nil || sig != nil {
		t.Fatal("failed parsing returned partial data")
	}
}

func TestParseStrictSizeLimit(t *testing.T) {
	data := Build([]byte("{}"), []byte("sig"))
	data = append(data, bytes.Repeat([]byte(" "), MaxSize-len(data))...)
	if _, _, err := ParseStrict(data); err != nil {
		t.Fatalf("exactly MaxSize bytes rejected: %v", err)
	}
	assertFormatError(t, append(data, ' '))
}

func TestParseStrictDefersPayloadValidation(t *testing.T) {
	// Parser bundle tidak memvalidasi isi manifest maupun panjang signature.
	m := []byte("{\n  \"not-a-manifest\": true\n}\n")
	for _, size := range []int{0, 63, 64, 65, 384, 385} {
		t.Run(fmt.Sprintf("signature %d bytes", size), func(t *testing.T) {
			sig := bytes.Repeat([]byte{0xab}, size)
			gotManifest, gotSig, err := ParseStrict(Build(m, sig))
			if err != nil {
				t.Fatalf("ParseStrict: %v", err)
			}
			if !bytes.Equal(gotManifest, m) || !bytes.Equal(gotSig, sig) {
				t.Fatal("payload bytes changed")
			}
		})
	}
}

func TestWriteFile(t *testing.T) {
	for _, force := range []bool{false, true} {
		t.Run(fmt.Sprintf("new file force=%t", force), func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "bundle.json")
			data := Build(sampleManifest(t), []byte("sig"))
			if err := WriteFile(path, data, force); err != nil {
				t.Fatal(err)
			}
			assertFileBytes(t, path, data)
			assertNoTempFiles(t, dir)
		})
	}
	t.Run("existing file", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "bundle.json")
		old := []byte("previous contents")
		if err := os.WriteFile(path, old, 0600); err != nil {
			t.Fatal(err)
		}
		data := Build(sampleManifest(t), []byte("new signature"))
		if err := WriteFile(path, data, false); !errors.Is(err, os.ErrExist) {
			t.Fatalf("WriteFile error = %v, want os.ErrExist", err)
		}
		assertFileBytes(t, path, old)
		assertNoTempFiles(t, dir)
		if err := WriteFile(path, data, true); err != nil {
			t.Fatal(err)
		}
		assertFileBytes(t, path, data)
		assertNoTempFiles(t, dir)
	})
}

func TestWriteFileSymlink(t *testing.T) {
	for _, dangling := range []bool{false, true} {
		t.Run(fmt.Sprintf("dangling=%t", dangling), func(t *testing.T) {
			dir := t.TempDir()
			target := filepath.Join(dir, "target.json")
			old := []byte("symlink target")
			if !dangling {
				if err := os.WriteFile(target, old, 0600); err != nil {
					t.Fatal(err)
				}
			}
			path := filepath.Join(dir, "bundle.json")
			if err := os.Symlink(target, path); err != nil {
				t.Fatal(err)
			}
			data := Build([]byte("{}"), []byte("sig"))
			if err := WriteFile(path, data, false); !errors.Is(err, os.ErrExist) {
				t.Fatalf("WriteFile error = %v, want os.ErrExist", err)
			}
			if got, err := os.Readlink(path); err != nil || got != target {
				t.Fatalf("symlink changed: %q, %v", got, err)
			}
			if err := WriteFile(path, data, true); err != nil {
				t.Fatal(err)
			}
			assertFileBytes(t, path, data)
			if dangling {
				if _, err := os.Lstat(target); !errors.Is(err, os.ErrNotExist) {
					t.Fatalf("unexpected target: %v", err)
				}
			} else {
				assertFileBytes(t, target, old)
			}
			assertNoTempFiles(t, dir)
		})
	}
}

func TestWriteFileFailure(t *testing.T) {
	t.Run("missing parent", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "missing", "bundle.json")
		if err := WriteFile(path, []byte("bundle"), false); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("WriteFile error = %v, want os.ErrNotExist", err)
		}
		assertNoTempFiles(t, dir)
	})
	t.Run("rename fails", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "bundle.json")
		if err := os.Mkdir(path, 0700); err != nil {
			t.Fatal(err)
		}
		sentinel := filepath.Join(path, "keep")
		old := []byte("preserved")
		if err := os.WriteFile(sentinel, old, 0600); err != nil {
			t.Fatal(err)
		}
		if err := WriteFile(path, []byte("bundle"), true); err == nil {
			t.Fatal("WriteFile over directory succeeded")
		}
		assertFileBytes(t, sentinel, old)
		assertNoTempFiles(t, dir)
	})
}

func TestWriteFileConcurrentNoOverwrite(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bundle.json")
	start := make(chan struct{})
	type result struct {
		data []byte
		err  error
	}
	const writers = 8
	results := make(chan result, writers)
	for i := range writers {
		data := bytes.Repeat([]byte{byte(i)}, 1024)
		go func() {
			<-start
			results <- result{data, WriteFile(path, data, false)}
		}()
	}
	close(start)
	var winner []byte
	successes := 0
	for range writers {
		r := <-results
		if r.err == nil {
			successes++
			winner = r.data
		} else if !errors.Is(r.err, os.ErrExist) {
			t.Errorf("WriteFile error = %v, want os.ErrExist", r.err)
		}
	}
	if successes != 1 {
		t.Fatalf("successful writes = %d, want 1", successes)
	}
	assertFileBytes(t, path, winner)
	assertNoTempFiles(t, dir)
}

func assertFileBytes(t *testing.T, path string, want []byte) {
	t.Helper()
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("%s contains %q, want %q", path, got, want)
	}
}

func assertNoTempFiles(t *testing.T, dir string) {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), ".bundle-") {
			t.Errorf("temporary file left behind: %s", entry.Name())
		}
	}
}
