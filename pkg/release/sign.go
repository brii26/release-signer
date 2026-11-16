package release

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/brii26/release-signer/pkg/bundle"
	"github.com/brii26/release-signer/pkg/keys"
	"github.com/brii26/release-signer/pkg/manifest"
	"github.com/brii26/release-signer/pkg/profile"
	"github.com/brii26/release-signer/pkg/sigalg"
)

// ErrInput membungkus semua error Sign karena input, I/O, atau environment (exit 2).
var ErrInput = errors.New("input error")

// SignInput adalah input Sign, profile diambil dari private key di KeyPath.
type SignInput struct {
	ArtifactPath string
	Package      string
	Version      string
	KeyPath      string
	OutPath      string
	Force        bool
}

// SignOutput: keyid, profile, byte manifest yang di-sign, dan path bundle.
type SignOutput struct {
	KeyID      string
	Profile    profile.Profile
	Manifest   []byte
	BundlePath string
}

// Sign baca artifact, bikin dan sign manifest, tulis bundle ke OutPath, artifact tidak diubah.
func Sign(in SignInput) (SignOutput, error) {
	keyPEM, err := os.ReadFile(in.KeyPath)
	if err != nil {
		return SignOutput{}, inputErr("read private key: %v", err)
	}
	// Pesan generik, error dari parser bisa memuat label PEM.
	priv, prof, err := keys.ParsePrivatePEM(keyPEM)
	if err != nil {
		return SignOutput{}, inputErr("key file is not a valid PKCS#8 key of a supported profile")
	}
	keyID, err := keys.KeyID(priv.Public())
	if err != nil {
		return SignOutput{}, inputErr("compute keyid: %v", err)
	}

	name := filepath.Base(in.ArtifactPath)
	// validasi metadata dulu supaya artifact besar tidak di-hash sia-sia
	if _, err := manifest.New(in.Package, in.Version, string(prof), keyID, name, 0, strings.Repeat("0", 64)); err != nil {
		return SignOutput{}, inputErr("%v", err)
	}

	size, sum, err := hashFile(in.ArtifactPath)
	if err != nil {
		return SignOutput{}, inputErr("read artifact: %v", err)
	}
	m, err := manifest.New(in.Package, in.Version, string(prof), keyID, name, size, sum)
	if err != nil {
		return SignOutput{}, inputErr("%v", err)
	}
	msg := m.Canonical()
	if len(msg) > manifest.MaxSize {
		return SignOutput{}, inputErr("manifest exceeds %d bytes", manifest.MaxSize)
	}

	sig, err := sigalg.Sign(prof, priv, msg)
	if err != nil {
		return SignOutput{}, inputErr("sign: %v", err)
	}
	if !sigalg.Verify(prof, priv.Public(), msg, sig) {
		return SignOutput{}, inputErr("signature self-check failed")
	}

	if err := bundle.WriteFile(in.OutPath, bundle.Build(msg, sig), in.Force); err != nil {
		return SignOutput{}, inputErr("write bundle: %v", err)
	}
	return SignOutput{KeyID: keyID, Profile: prof, Manifest: msg, BundlePath: in.OutPath}, nil
}

func hashFile(path string) (int64, string, error) {
	f, err := os.Open(path)
	if err != nil {
		return 0, "", err
	}
	defer f.Close()

	h := sha256.New()
	n, err := io.Copy(h, f)
	if err != nil {
		return 0, "", err
	}
	return n, hex.EncodeToString(h.Sum(nil)), nil
}

func inputErr(format string, args ...any) error {
	return fmt.Errorf("%w: %s", ErrInput, fmt.Sprintf(format, args...))
}
