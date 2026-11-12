package truststore_test

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/brii26/release-signer/pkg/keys"
	"github.com/brii26/release-signer/pkg/profile"
	"github.com/brii26/release-signer/pkg/truststore"
)

func newEntry(t *testing.T, p profile.Profile) truststore.Entry {
	t.Helper()
	priv, err := keys.Generate(p)
	if err != nil {
		t.Fatal(err)
	}
	pubPEM, err := keys.MarshalPublicPEM(priv.Public())
	if err != nil {
		t.Fatal(err)
	}
	keyID, err := keys.KeyID(priv.Public())
	if err != nil {
		t.Fatal(err)
	}
	return truststore.Entry{
		KeyID: keyID, Algorithm: p, PublicKeyPEM: string(pubPEM),
		Packages: []string{"app"}, Public: priv.Public(),
	}
}

func encodedStore(t *testing.T, entries ...truststore.Entry) []byte {
	t.Helper()
	if entries == nil {
		entries = []truststore.Entry{}
	}
	wire := struct {
		Schema string             `json:"schema"`
		Keys   []truststore.Entry `json:"keys"`
	}{truststore.Schema, entries}
	data, err := json.Marshal(wire)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func writeStore(t *testing.T, data []byte) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "trust.json")
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	return path
}

func readFile(t *testing.T, path string) []byte {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func TestLoadSaveProfiles(t *testing.T) {
	store := &truststore.Store{}
	for _, p := range []profile.Profile{profile.RSAPSS, profile.ECDSA, profile.Ed25519} {
		store.Keys = append(store.Keys, newEntry(t, p))
	}
	path := filepath.Join(t.TempDir(), "trust.json")
	if err := store.Save(path); err != nil {
		t.Fatal(err)
	}
	loaded, err := truststore.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(loaded.Keys) != 3 {
		t.Fatalf("entries = %d, want 3", len(loaded.Keys))
	}
	for i, want := range store.Keys {
		got, ok := loaded.Lookup(want.KeyID)
		if !ok || got.Algorithm != want.Algorithm || got.PublicKeyPEM != want.PublicKeyPEM ||
			!got.Allows("app") || got.Allows("other") || got.Public == nil {
			t.Fatalf("entry %d changed: %+v", i, got)
		}
		keyID, err := keys.KeyID(got.Public)
		if err != nil || keyID != want.KeyID {
			t.Fatalf("parsed public key fingerprint = %q, %v", keyID, err)
		}
	}
	before := readFile(t, path)
	if err := loaded.Save(path); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, readFile(t, path)) {
		t.Fatal("unchanged store saved differently")
	}
	var wire map[string]json.RawMessage
	if err := json.Unmarshal(before, &wire); err != nil || len(wire) != 2 {
		t.Fatalf("invalid store envelope: %v", err)
	}
	var entries []map[string]json.RawMessage
	if err := json.Unmarshal(wire["keys"], &entries); err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if len(entry) != 4 || entry["keyid"] == nil || entry["algorithm"] == nil ||
			entry["public_key_pem"] == nil || entry["packages"] == nil {
			t.Fatalf("unexpected serialized entry: %v", entry)
		}
	}
}

func TestEmptyStore(t *testing.T) {
	path := writeStore(t, []byte(`{"schema":"minisign-trust/v1","keys":[]}`))
	store, err := truststore.Load(path)
	if err != nil || len(store.Keys) != 0 {
		t.Fatalf("Load empty store = %+v, %v", store, err)
	}
	if _, ok := store.Lookup(strings.Repeat("a", 64)); ok {
		t.Fatal("empty store trusts a key")
	}
	if err := store.Remove(strings.Repeat("a", 64)); !errors.Is(err, truststore.ErrNotFound) {
		t.Fatalf("Remove error = %v, want ErrNotFound", err)
	}
	if err := (&truststore.Store{}).Save(path); err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(readFile(t, path), []byte(`"keys": []`)) {
		t.Fatal("zero-value store serialized keys as null")
	}
}

func TestLoadErrors(t *testing.T) {
	path := filepath.Join(t.TempDir(), "missing.json")
	if store, err := truststore.Load(path); store != nil || !errors.Is(err, truststore.ErrIO) ||
		!errors.Is(err, os.ErrNotExist) {
		t.Fatalf("Load missing file = %+v, %v", store, err)
	}
	store, err := truststore.LoadOrEmpty(path)
	if err != nil || store == nil || len(store.Keys) != 0 {
		t.Fatalf("LoadOrEmpty = %+v, %v", store, err)
	}
	if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("LoadOrEmpty created a file: %v", err)
	}
	if err := os.Symlink(path, path+".link"); err != nil {
		t.Fatal(err)
	}
	if _, err := truststore.LoadOrEmpty(path + ".link"); !errors.Is(err, truststore.ErrIO) {
		t.Fatalf("dangling symlink error = %v, want ErrIO", err)
	}
	if _, err := truststore.LoadOrEmpty(filepath.Dir(path)); !errors.Is(err, truststore.ErrIO) {
		t.Fatalf("directory error = %v, want ErrIO", err)
	}
	badPath := writeStore(t, []byte("{}"))
	for _, load := range []func(string) (*truststore.Store, error){truststore.Load, truststore.LoadOrEmpty} {
		if got, err := load(badPath); got != nil || !errors.Is(err, truststore.ErrFormat) || errors.Is(err, truststore.ErrIO) {
			t.Fatalf("invalid store = %+v, %v", got, err)
		}
	}
	t.Run("unreadable store", func(t *testing.T) {
		if os.Geteuid() == 0 {
			t.Skip("root bypasses file read permissions")
		}
		path := writeStore(t, encodedStore(t))
		if err := os.Chmod(path, 0000); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() {
			if err := os.Chmod(path, 0600); err != nil {
				t.Error(err)
			}
		})
		for _, load := range []func(string) (*truststore.Store, error){truststore.Load, truststore.LoadOrEmpty} {
			if store, err := load(path); store != nil || !errors.Is(err, truststore.ErrIO) ||
				!errors.Is(err, os.ErrPermission) {
				t.Fatalf("unreadable store = %+v, %v", store, err)
			}
		}
	})
}

func TestLoadRejects(t *testing.T) {
	entry := newEntry(t, profile.Ed25519)
	valid := string(encodedStore(t, entry))
	swap := func(old, new string) string { return strings.Replace(valid, old, new, 1) }
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	rsaPEM, err := keys.MarshalPublicPEM(&rsaKey.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	weakRSA := entry
	weakRSA.Algorithm = profile.RSAPSS
	weakRSA.PublicKeyPEM = string(rsaPEM)
	tests := []struct{ name, data string }{
		{"wrong schema", swap("minisign-trust/v1", "minisign-trust/v2")},
		{"missing schema", swap(`"schema":"minisign-trust/v1",`, ``)},
		{"extra top field", swap(`"schema":`, `"extra":true,"schema":`)},
		{"duplicate top field", swap(`"schema":`, `"schema":"minisign-trust/v1","schema":`)},
		{"escaped duplicate", swap(`"keyid":`, `"\u006beyid":"x","keyid":`)},
		{"duplicate entry field", swap(`"algorithm":`, `"algorithm":"ed25519","algorithm":`)},
		{"extra entry field", swap(`"algorithm":`, `"extra":1,"algorithm":`)},
		{"missing entry field", swap(`"algorithm":"ed25519",`, ``)},
		{"case sensitive field", swap(`"keyid":`, `"KeyID":`)},
		{"keyid fingerprint mismatch", swap(entry.KeyID, flipHex(entry.KeyID))},
		{"uppercase keyid", swap(entry.KeyID, strings.Repeat("A", 64))},
		{"short keyid", swap(entry.KeyID, "abcd")},
		{"algorithm mismatch", swap(`"algorithm":"ed25519"`, `"algorithm":"ecdsa-p256-sha256"`)},
		{"unknown algorithm", swap(`"algorithm":"ed25519"`, `"algorithm":"unknown"`)},
		{"invalid pem", swap(string(mustJSON(t, entry.PublicKeyPEM)), `"bad pem"`)},
		{"packages empty", swap(`["app"]`, `[]`)},
		{"wildcard", swap(`["app"]`, `["*"]`)},
		{"duplicate package", swap(`["app"]`, `["app","app"]`)},
		{"package null", swap(`["app"]`, `[null]`)},
		{"package number", swap(`["app"]`, `[1]`)},
		{"package bool", swap(`["app"]`, `[true]`)},
		{"package object", swap(`["app"]`, `[{}]`)},
		{"uppercase package", swap(`["app"]`, `["App"]`)},
		{"leading underscore", swap(`["app"]`, `["_app"]`)},
		{"package too long", swap(`["app"]`, `["`+strings.Repeat("a", 65)+`"]`)},
		{"duplicate keyid", string(encodedStore(t, entry, entry))},
		{"rsa 2048", string(encodedStore(t, weakRSA))},
		{"bom", "\xEF\xBB\xBF" + valid},
		{"invalid utf8", swap(`["app"]`, "[\"\xff\"]")},
		{"trailing object", valid + "{}"},
		{"trailing garbage", valid + "x"},
		{"invalid syntax", valid[:len(valid)-1]},
		{"top level array", "[]"},
		{"top level null", "null"},
	}
	for _, field := range []struct{ name, value string }{
		{"schema", `"minisign-trust/v1"`},
		{"keys", string(mustJSON(t, []truststore.Entry{entry}))},
		{"keyid", `"` + entry.KeyID + `"`},
		{"algorithm", `"ed25519"`},
		{"public_key_pem", string(mustJSON(t, entry.PublicKeyPEM))},
		{"packages", `["app"]`},
	} {
		for _, wrong := range []string{`null`, `true`, `1`, `{}`} {
			tests = append(tests, struct{ name, data string }{
				field.name + " is " + wrong,
				swap(`"`+field.name+`":`+field.value, `"`+field.name+`":`+wrong),
			})
		}
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			store, err := truststore.Load(writeStore(t, []byte(tc.data)))
			if store != nil || !errors.Is(err, truststore.ErrFormat) {
				t.Fatalf("Load = %+v, %v; want nil, ErrFormat", store, err)
			}
		})
	}
}

func mustJSON(t *testing.T, value any) []byte {
	t.Helper()
	data, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func flipHex(s string) string {
	if s[0] == '0' {
		return "1" + s[1:]
	}
	return "0" + s[1:]
}

func TestAddMergeAndRemove(t *testing.T) {
	entry := newEntry(t, profile.Ed25519)
	store := &truststore.Store{}
	got, changed, err := store.Add([]byte(entry.PublicKeyPEM), "app")
	if err != nil || !changed || got.KeyID != entry.KeyID || got.Public == nil {
		t.Fatalf("Add = %+v, %t, %v", got, changed, err)
	}
	path := filepath.Join(t.TempDir(), "trust.json")
	if err := store.Save(path); err != nil {
		t.Fatal(err)
	}
	before := readFile(t, path)
	crlf := strings.ReplaceAll(entry.PublicKeyPEM, "\n", "\r\n")
	if _, changed, err := store.Add([]byte(crlf), "app"); err != nil || changed {
		t.Fatalf("duplicate Add = %t, %v", changed, err)
	}
	if err := store.Save(path); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, readFile(t, path)) {
		t.Fatal("idempotent Add changed serialized bytes")
	}
	got, changed, err = store.Add([]byte(crlf), "other.app")
	if err != nil || !changed || len(store.Keys) != 1 || len(got.Packages) != 2 ||
		!got.Allows("app") || !got.Allows("other.app") || got.Allows("other") {
		t.Fatalf("merge = %+v, %t, %v", got, changed, err)
	}
	other := newEntry(t, profile.ECDSA)
	if _, changed, err := store.Add([]byte(other.PublicKeyPEM), "app"); err != nil || !changed {
		t.Fatalf("second key Add = %t, %v", changed, err)
	}
	if err := store.Remove(entry.KeyID); err != nil {
		t.Fatal(err)
	}
	if _, ok := store.Lookup(entry.KeyID); ok {
		t.Fatal("removed key still found")
	}
	if _, ok := store.Lookup(other.KeyID); !ok {
		t.Fatal("Remove deleted another key")
	}
	if err := store.Remove(entry.KeyID); !errors.Is(err, truststore.ErrNotFound) {
		t.Fatalf("Remove error = %v, want ErrNotFound", err)
	}
}

func TestAddRejectsWithoutMutation(t *testing.T) {
	entry := newEntry(t, profile.Ed25519)
	store := &truststore.Store{Keys: []truststore.Entry{entry}}
	before := encodedStore(t, store.Keys...)
	for _, pkg := range []string{"", "*", "App", "_app", "-app", ".app", "app name", strings.Repeat("a", 65)} {
		if _, changed, err := store.Add([]byte(entry.PublicKeyPEM), pkg); changed || !errors.Is(err, truststore.ErrFormat) {
			t.Fatalf("Add(%q) = %t, %v", pkg, changed, err)
		}
	}
	if _, changed, err := store.Add([]byte("bad pem"), "app"); changed || !errors.Is(err, truststore.ErrFormat) {
		t.Fatalf("Add invalid key = %t, %v", changed, err)
	}
	if !bytes.Equal(before, encodedStore(t, store.Keys...)) {
		t.Fatal("failed Add mutated the store")
	}
	for _, pkg := range []string{"a", "app.name_-", strings.Repeat("a", 64)} {
		if _, changed, err := store.Add([]byte(entry.PublicKeyPEM), pkg); err != nil || !changed {
			t.Fatalf("Add boundary %q = %t, %v", pkg, changed, err)
		}
	}
}

func TestSaveFailurePreservesStore(t *testing.T) {
	entry := newEntry(t, profile.Ed25519)
	store := &truststore.Store{Keys: []truststore.Entry{entry}}
	t.Run("read only directory", func(t *testing.T) {
		if os.Geteuid() == 0 {
			t.Skip("root bypasses directory write permissions")
		}
		dir := t.TempDir()
		path := filepath.Join(dir, "trust.json")
		if err := store.Save(path); err != nil {
			t.Fatal(err)
		}
		before := readFile(t, path)
		if err := os.Chmod(dir, 0500); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() {
			if err := os.Chmod(dir, 0700); err != nil {
				t.Error(err)
			}
		})
		if err := store.Save(path); !errors.Is(err, truststore.ErrIO) || !errors.Is(err, os.ErrPermission) {
			t.Fatalf("Save error = %v, want ErrIO and permission error", err)
		}
		if !bytes.Equal(before, readFile(t, path)) {
			t.Fatal("failed Save changed existing store")
		}
		assertNoTemps(t, dir)
	})
	t.Run("rename failure", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "trust.json")
		if err := os.Mkdir(path, 0700); err != nil {
			t.Fatal(err)
		}
		sentinel := filepath.Join(path, "keep")
		if err := os.WriteFile(sentinel, []byte("preserved"), 0600); err != nil {
			t.Fatal(err)
		}
		if err := store.Save(path); !errors.Is(err, truststore.ErrIO) {
			t.Fatalf("Save error = %v, want ErrIO", err)
		}
		if string(readFile(t, sentinel)) != "preserved" {
			t.Fatal("existing destination changed")
		}
		assertNoTemps(t, dir)
	})
	t.Run("invalid in-memory entry", func(t *testing.T) {
		path := writeStore(t, []byte("old bytes"))
		bad := entry
		bad.Packages = nil
		if err := (&truststore.Store{Keys: []truststore.Entry{bad}}).Save(path); !errors.Is(err, truststore.ErrFormat) {
			t.Fatalf("Save error = %v, want ErrFormat", err)
		}
		if string(readFile(t, path)) != "old bytes" {
			t.Fatal("validation failure changed existing file")
		}
		assertNoTemps(t, filepath.Dir(path))
	})
	t.Run("missing parent", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "missing", "trust.json")
		if err := store.Save(path); !errors.Is(err, truststore.ErrIO) || !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("Save error = %v, want ErrIO and not-exist error", err)
		}
	})
}

func assertNoTemps(t *testing.T, dir string) {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), ".trust-") {
			t.Errorf("temporary file left behind: %s", entry.Name())
		}
	}
}
