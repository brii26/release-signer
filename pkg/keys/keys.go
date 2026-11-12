package keys

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"os"

	"github.com/brii26/release-signer/pkg/profile"
)

func Generate(p profile.Profile) (crypto.Signer, error) {
	switch p {
	case profile.RSAPSS:
		return rsa.GenerateKey(rand.Reader, 3072)
	case profile.ECDSA:
		return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	case profile.Ed25519:
		_, priv, err := ed25519.GenerateKey(rand.Reader)
		return priv, err
	default:
		return nil, fmt.Errorf("unsupported profile: %s", p)
	}
}

func MarshalPrivatePEM(k crypto.Signer) ([]byte, error) {
	der, err := x509.MarshalPKCS8PrivateKey(k)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal pkcs8 private key: %w", err)
	}
	block := &pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: der,
	}
	return pem.EncodeToMemory(block), nil
}

func MarshalPublicPEM(pub crypto.PublicKey) ([]byte, error) {
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal spki public key: %w", err)
	}
	block := &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: der,
	}
	return pem.EncodeToMemory(block), nil
}

func ParsePrivatePEM(data []byte) (crypto.Signer, profile.Profile, error) {
	block, err := decodePEM(data, "PRIVATE KEY")
	if err != nil {
		return nil, "", err
	}
	priv, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, "", fmt.Errorf("failed to parse pkcs8 private key: %w", err)
	}
	signer, ok := priv.(crypto.Signer)
	if !ok {
		return nil, "", fmt.Errorf("private key type %T does not implement crypto.Signer", priv)
	}
	pub := signer.Public()
	p, err := ProfileOf(pub)
	if err != nil {
		return nil, "", err
	}
	return signer, p, nil
}

func ParsePublicPEM(data []byte) (crypto.PublicKey, profile.Profile, error) {
	block, err := decodePEM(data, "PUBLIC KEY")
	if err != nil {
		return nil, "", err
	}
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, "", fmt.Errorf("failed to parse spki public key: %w", err)
	}
	pub = pub.(crypto.PublicKey)
	p, err := ProfileOf(pub)
	if err != nil {
		return nil, "", err
	}
	return pub, p, nil
}

func decodePEM(data []byte, expectedType string) (*pem.Block, error) {
	block, rest := pem.Decode(data)
	if block == nil {
		return nil, errors.New("no PEM block found")
	}
	if block.Type != expectedType {
		return nil, fmt.Errorf("unexpected PEM type %q, expected %q", block.Type, expectedType)
	}
	if len(bytes.TrimSpace(rest)) > 0 {
		return nil, errors.New("trailing data after PEM block")
	}
	return block, nil
}

func ProfileOf(pub crypto.PublicKey) (profile.Profile, error) {
	if pub == nil {
		return "", errors.New("public key is nil")
	}
	switch k := pub.(type) {
	case *rsa.PublicKey:
		if k.N.BitLen() != 3072 {
			return "", fmt.Errorf("RSA modulus bit length %d != 3072", k.N.BitLen())
		}
		if k.E != 65537 {
			return "", fmt.Errorf("RSA public exponent %d != 65537", k.E)
		}
		return profile.RSAPSS, nil
	case *ecdsa.PublicKey:
		if k.Curve != elliptic.P256() {
			return "", fmt.Errorf("ECDSA curve %s is not P-256", k.Curve.Params().Name)
		}
		return profile.ECDSA, nil
	case ed25519.PublicKey:
		if len(k) != ed25519.PublicKeySize {
			return "", fmt.Errorf("invalid Ed25519 public key length %d", len(k))
		}
		return profile.Ed25519, nil
	default:
		return "", fmt.Errorf("unsupported key type: %T", pub)
	}
}

func KeyID(pub crypto.PublicKey) (string, error) {
	if pub == nil {
		return "", errors.New("public key is nil")
	}
	if _, err := ProfileOf(pub); err != nil {
		return "", err
	}
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return "", fmt.Errorf("failed to marshal public key: %w", err)
	}
	h := sha256.Sum256(der)
	return hex.EncodeToString(h[:]), nil
}

func WriteKeyPair(prefix string, k crypto.Signer, force bool) (privPath, pubPath string, err error) {
	flags := os.O_WRONLY | os.O_CREATE
	if !force {
		flags |= os.O_EXCL
	} else {
		flags |= os.O_TRUNC
	}

	keyFile := prefix + ".key.pem"
	pubFile := prefix + ".pub.pem"

	privPEM, err := MarshalPrivatePEM(k)
	if err != nil {
		return "", "", err
	}
	pubPEM, err := MarshalPublicPEM(k.Public())
	if err != nil {
		return "", "", err
	}

	f, err := os.OpenFile(keyFile, flags, 0600)
	if err != nil {
		return "", "", fmt.Errorf("failed to open private key file: %w", err)
	}
	if _, err := f.Write(privPEM); err != nil {
		f.Close()
		return "", "", fmt.Errorf("failed to write private key: %w", err)
	}
	if err := f.Close(); err != nil {
		return "", "", err
	}

	p, err := os.OpenFile(pubFile, flags, 0644)
	if err != nil {
		return "", "", fmt.Errorf("failed to open public key file: %w", err)
	}
	if _, err := p.Write(pubPEM); err != nil {
		p.Close()
		return "", "", fmt.Errorf("failed to write public key: %w", err)
	}
	if err := p.Close(); err != nil {
		return "", "", err
	}

	return keyFile, pubFile, nil
}
