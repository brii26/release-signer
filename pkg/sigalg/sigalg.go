package sigalg

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"errors"
	"fmt"
	"math/big"

	"github.com/brii26/release-signer/pkg/profile"
)

// Sign hitung signature msg sesuai profile p dengan priv.
func Sign(p profile.Profile, priv crypto.Signer, msg []byte) ([]byte, error) {
	if priv == nil {
		return nil, errors.New("private key is nil")
	}

	switch p {
	case profile.RSAPSS:
		rsaPriv, ok := priv.(*rsa.PrivateKey)
		if !ok || rsaPriv == nil || rsaPriv.N == nil {
			return nil, fmt.Errorf("expected *rsa.PrivateKey, got %T", priv)
		}
		if rsaPriv.N.BitLen() != 3072 || rsaPriv.E != 65537 {
			return nil, fmt.Errorf("invalid RSA key parameters: bitLen=%d, e=%d", rsaPriv.N.BitLen(), rsaPriv.E)
		}
		h := sha256.Sum256(msg)
		opts := &rsa.PSSOptions{
			SaltLength: 32,
			Hash:       crypto.SHA256,
		}
		return rsa.SignPSS(rand.Reader, rsaPriv, crypto.SHA256, h[:], opts)

	case profile.ECDSA:
		ecdsaPriv, ok := priv.(*ecdsa.PrivateKey)
		if !ok || ecdsaPriv == nil || ecdsaPriv.Curve == nil || ecdsaPriv.Curve.Params() == nil {
			return nil, fmt.Errorf("expected *ecdsa.PrivateKey, got %T", priv)
		}
		if ecdsaPriv.Curve.Params().Name != "P-256" {
			return nil, fmt.Errorf("expected P-256 curve, got %s", ecdsaPriv.Curve.Params().Name)
		}
		h := sha256.Sum256(msg)
		r, s, err := ecdsa.Sign(rand.Reader, ecdsaPriv, h[:])
		if err != nil {
			return nil, fmt.Errorf("ecdsa sign failed: %w", err)
		}
		sig := make([]byte, 64)
		r.FillBytes(sig[:32])
		s.FillBytes(sig[32:])
		return sig, nil

	case profile.Ed25519:
		edPriv, ok := priv.(ed25519.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("expected ed25519.PrivateKey, got %T", priv)
		}
		if len(edPriv) != ed25519.PrivateKeySize {
			return nil, fmt.Errorf("invalid ed25519 private key size %d", len(edPriv))
		}
		return ed25519.Sign(edPriv, msg), nil

	default:
		return nil, fmt.Errorf("unsupported profile: %s", p)
	}
}

// Verify cek sig untuk msg di bawah pub, false kalau invalid, tidak cocok, atau panjang salah.
func Verify(p profile.Profile, pub crypto.PublicKey, msg, sig []byte) bool {
	if pub == nil || len(sig) != p.SignatureLen() {
		return false
	}

	switch p {
	case profile.RSAPSS:
		rsaPub, ok := pub.(*rsa.PublicKey)
		if !ok || rsaPub == nil || rsaPub.N == nil || rsaPub.N.BitLen() != 3072 || rsaPub.E != 65537 {
			return false
		}
		h := sha256.Sum256(msg)
		opts := &rsa.PSSOptions{
			SaltLength: 32,
			Hash:       crypto.SHA256,
		}
		return rsa.VerifyPSS(rsaPub, crypto.SHA256, h[:], sig, opts) == nil

	case profile.ECDSA:
		ecdsaPub, ok := pub.(*ecdsa.PublicKey)
		if !ok || ecdsaPub == nil || ecdsaPub.Curve == nil || ecdsaPub.Curve.Params() == nil {
			return false
		}
		if ecdsaPub.Curve.Params().Name != "P-256" {
			return false
		}
		r := new(big.Int).SetBytes(sig[:32])
		s := new(big.Int).SetBytes(sig[32:])
		n := ecdsaPub.Curve.Params().N
		if r.Sign() <= 0 || s.Sign() <= 0 || r.Cmp(n) >= 0 || s.Cmp(n) >= 0 {
			return false
		}
		h := sha256.Sum256(msg)
		return ecdsa.Verify(ecdsaPub, h[:], r, s)

	case profile.Ed25519:
		edPub, ok := pub.(ed25519.PublicKey)
		if !ok || len(edPub) != ed25519.PublicKeySize {
			return false
		}
		return ed25519.Verify(edPub, msg, sig)

	default:
		return false
	}
}
