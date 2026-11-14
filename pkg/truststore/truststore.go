// Package truststore mengelola kunci publik tepercaya dan izin per paket.
package truststore

import (
	"crypto"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"slices"

	"github.com/brii26/release-signer/pkg/keys"
	"github.com/brii26/release-signer/pkg/profile"
	"github.com/brii26/release-signer/pkg/strictjson"
)

// Schema is the fixed schema value of a trust store file.
const Schema = "minisign-trust/v1"

// Errors returned by the trust store functions. Callers match them with errors.Is.
var (
	ErrFormat   = errors.New("trust store format error")
	ErrIO       = errors.New("trust store io error")
	ErrNotFound = errors.New("keyid not found")
)

var (
	reKeyID   = regexp.MustCompile(`^[0-9a-f]{64}$`)
	rePackage = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,63}$`)
)

// Entry is one trusted public key together with the packages it may sign.
// Public is the parsed key and is never written to JSON.
type Entry struct {
	KeyID        string           `json:"keyid"`
	Algorithm    profile.Profile  `json:"algorithm"`
	PublicKeyPEM string           `json:"public_key_pem"`
	Packages     []string         `json:"packages"`
	Public       crypto.PublicKey `json:"-"`
}

// Store is a validated trust store. An empty store trusts no key.
type Store struct {
	Keys []Entry
}

// Load membaca dan memvalidasi seluruh store tanpa mengubah file.
func Load(path string) (*Store, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, ioErr(err)
	}
	return parse(data)
}

// LoadOrEmpty khusus untuk trust add. File rusak, tidak terbaca, atau symlink
// yang targetnya hilang tetap ditolak; hanya path baru menjadi store kosong.
func LoadOrEmpty(path string) (*Store, error) {
	s, err := Load(path)
	if errors.Is(err, os.ErrNotExist) {
		if _, statErr := os.Lstat(path); errors.Is(statErr, os.ErrNotExist) {
			return &Store{Keys: []Entry{}}, nil
		}
	}
	return s, err
}

// Lookup returns the entry whose keyid is keyID.
func (s *Store) Lookup(keyID string) (*Entry, bool) {
	if s != nil {
		for i := range s.Keys {
			if s.Keys[i].KeyID == keyID {
				return &s.Keys[i], true
			}
		}
	}
	return nil, false
}

// Allows reports whether the key may sign package pkg (exact match, no wildcard).
func (e *Entry) Allows(pkg string) bool {
	return e != nil && slices.Contains(e.Packages, pkg)
}

// Add mengembalikan changed=false jika pasangan keyid dan paket sudah ada.
func (s *Store) Add(pubPEM []byte, pkg string) (Entry, bool, error) {
	if s == nil {
		return Entry{}, false, formatErr("nil store")
	}
	if !rePackage.MatchString(pkg) {
		return Entry{}, false, formatErr("invalid package name %q", pkg)
	}
	pub, algorithm, err := keys.ParsePublicPEM(pubPEM)
	if err != nil {
		return Entry{}, false, formatErr("public_key_pem: %v", err)
	}
	keyID, err := keys.KeyID(pub)
	if err != nil {
		return Entry{}, false, formatErr("keyid: %v", err)
	}
	if entry, ok := s.Lookup(keyID); ok {
		if entry.Allows(pkg) {
			return *entry, false, nil
		}
		entry.Packages = append(entry.Packages, pkg)
		return *entry, true, nil
	}
	entry := Entry{
		KeyID: keyID, Algorithm: algorithm, PublicKeyPEM: string(pubPEM),
		Packages: []string{pkg}, Public: pub,
	}
	s.Keys = append(s.Keys, entry)
	return entry, true, nil
}

// Remove deletes the entry with the given keyid, or returns ErrNotFound.
func (s *Store) Remove(keyID string) error {
	if s != nil {
		for i := range s.Keys {
			if s.Keys[i].KeyID == keyID {
				s.Keys = slices.Delete(s.Keys, i, i+1)
				return nil
			}
		}
	}
	return fmt.Errorf("%w: %s", ErrNotFound, keyID)
}

// Save memvalidasi ulang field yang diserialisasi sebelum mengganti file secara
// atomik. Public hanya cache hasil parse dan tidak pernah masuk JSON.
func (s *Store) Save(path string) error {
	if s == nil {
		return formatErr("nil store")
	}
	entries, err := validateEntries(s.Keys)
	if err != nil {
		return err
	}
	wire := struct {
		Schema string  `json:"schema"`
		Keys   []Entry `json:"keys"`
	}{Schema, entries}
	data, err := json.MarshalIndent(wire, "", "  ")
	if err != nil {
		return formatErr("%v", err)
	}
	data = append(data, '\n')

	f, err := os.CreateTemp(filepath.Dir(path), ".trust-*.tmp")
	if err != nil {
		return ioErr(err)
	}
	defer os.Remove(f.Name())
	defer f.Close()
	if _, err := f.Write(data); err != nil {
		return ioErr(err)
	}
	if err := f.Sync(); err != nil {
		return ioErr(err)
	}
	if err := f.Close(); err != nil {
		return ioErr(err)
	}
	if err := os.Rename(f.Name(), path); err != nil {
		return ioErr(err)
	}
	return nil
}

func parse(data []byte) (*Store, error) {
	// Spek tidak menetapkan batas ukuran trust store seperti pada bundle.
	root, err := strictjson.Parse(data, len(data))
	if err != nil {
		return nil, formatErr("%v", err)
	}
	if err := strictjson.ExpectKeys(root, "schema", "keys"); err != nil {
		return nil, formatErr("%v", err)
	}
	schemaValue, _ := root.Field("schema")
	schema, err := strictjson.AsString(schemaValue)
	if err != nil || schema != Schema {
		return nil, formatErr("schema must be %q", Schema)
	}
	keysValue, _ := root.Field("keys")
	values, err := strictjson.AsArray(keysValue)
	if err != nil {
		return nil, formatErr("keys: %v", err)
	}
	entries := make([]Entry, 0, len(values))
	for i, value := range values {
		entry, err := parseEntry(value)
		if err != nil {
			return nil, formatErr("keys[%d]: %v", i, err)
		}
		entries = append(entries, entry)
	}
	entries, err = validateEntries(entries)
	if err != nil {
		return nil, err
	}
	return &Store{Keys: entries}, nil
}

func parseEntry(value strictjson.Value) (Entry, error) {
	if err := strictjson.ExpectKeys(value, "keyid", "algorithm", "public_key_pem", "packages"); err != nil {
		return Entry{}, err
	}
	var entry Entry
	var algorithm string
	for _, field := range []struct {
		key  string
		into *string
	}{
		{"keyid", &entry.KeyID},
		{"algorithm", &algorithm},
		{"public_key_pem", &entry.PublicKeyPEM},
	} {
		v, _ := value.Field(field.key)
		s, err := strictjson.AsString(v)
		if err != nil {
			return Entry{}, fmt.Errorf("%s: %w", field.key, err)
		}
		*field.into = s
	}
	entry.Algorithm = profile.Profile(algorithm)
	packagesValue, _ := value.Field("packages")
	packages, err := strictjson.AsArray(packagesValue)
	if err != nil {
		return Entry{}, err
	}
	for _, v := range packages {
		pkg, err := strictjson.AsString(v)
		if err != nil {
			return Entry{}, fmt.Errorf("packages: %w", err)
		}
		entry.Packages = append(entry.Packages, pkg)
	}
	return entry, nil
}

func validateEntries(entries []Entry) ([]Entry, error) {
	validated := make([]Entry, 0, len(entries))
	seen := make(map[string]bool, len(entries))
	for i, entry := range entries {
		if !reKeyID.MatchString(entry.KeyID) || seen[entry.KeyID] {
			return nil, formatErr("keys[%d]: invalid or duplicate keyid", i)
		}
		seen[entry.KeyID] = true
		if _, ok := profile.Parse(string(entry.Algorithm)); !ok {
			return nil, formatErr("keys[%d]: unknown algorithm", i)
		}
		pub, algorithm, err := keys.ParsePublicPEM([]byte(entry.PublicKeyPEM))
		if err != nil {
			return nil, formatErr("keys[%d]: public_key_pem: %v", i, err)
		}
		if algorithm != entry.Algorithm {
			return nil, formatErr("keys[%d]: algorithm does not match public key", i)
		}
		keyID, err := keys.KeyID(pub)
		if err != nil || keyID != entry.KeyID {
			return nil, formatErr("keys[%d]: keyid does not match public key", i)
		}
		if len(entry.Packages) == 0 {
			return nil, formatErr("keys[%d]: packages must not be empty", i)
		}
		packages := make(map[string]bool, len(entry.Packages))
		for _, pkg := range entry.Packages {
			if !rePackage.MatchString(pkg) || packages[pkg] {
				return nil, formatErr("keys[%d]: invalid or duplicate package %q", i, pkg)
			}
			packages[pkg] = true
		}
		entry.Public = pub
		validated = append(validated, entry)
	}
	return validated, nil
}

func formatErr(format string, args ...any) error {
	return fmt.Errorf("%w: %s", ErrFormat, fmt.Sprintf(format, args...))
}

func ioErr(err error) error {
	return fmt.Errorf("%w: %w", ErrIO, err)
}
