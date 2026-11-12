package keys_test

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"

	"github.com/brii26/release-signer/pkg/keys"
	"github.com/brii26/release-signer/pkg/profile"
)

func TestGenerateAndroundtripPEM(t *testing.T) {
	profiles := []profile.Profile{
		profile.RSAPSS,
		profile.ECDSA,
		profile.Ed25519,
	}

	for _, p := range profiles {
		t.Run(string(p), func(t *testing.T) {
			signer, err := keys.Generate(p)
			if err != nil {
				t.Fatalf("Generate failed: %v", err)
			}

			privPEM, err := keys.MarshalPrivatePEM(signer)
			if err != nil {
				t.Fatalf("MarshalPrivatePEM failed: %v", err)
			}

			pubPEM, err := keys.MarshalPublicPEM(signer.Public())
			if err != nil {
				t.Fatalf("MarshalPublicPEM failed: %v", err)
			}

			_, privProf, err := keys.ParsePrivatePEM(privPEM)
			if err != nil {
				t.Fatalf("ParsePrivatePEM failed: %v", err)
			}
			if privProf != p {
				t.Errorf("ParsePrivatePEM profile = %s, want %s", privProf, p)
			}

			parsedPub, pubProf, err := keys.ParsePublicPEM(pubPEM)
			if err != nil {
				t.Fatalf("ParsePublicPEM failed: %v", err)
			}
			if pubProf != p {
				t.Errorf("ParsePublicPEM profile = %s, want %s", pubProf, p)
			}

			origKeyID, err := keys.KeyID(signer.Public())
			if err != nil {
				t.Fatalf("KeyID(singer.Public)) failed: %v", err)
			}

			parsedKeyID, err := keys.KeyID(parsedPub)
			if origKeyID != parsedKeyID {
				t.Fatalf("KeyID(parsedPub) failed: %v", err)
			}
			if len(origKeyID) != 64 {
				t.Errorf("KeyID len = %d, want 64", len(origKeyID))
			}
		})
	}
}

func TestPEMLineEndingsAndFolding(t *testing.T) {
	signer, err := keys.Generate(profile.Ed25519)
	if err != nil {
		t.Fatalf("Generate failed: %v", err)
	}

	pubPEM, err := keys.MarshalPublicPEM(signer.Public())
	if err != nil {
		t.Fatalf("MarshalPublicPEM failed: %v", err)
	}

	baseKeyID, err := keys.KeyID(signer.Public())
	if err != nil {
		t.Fatalf("KeyID failed: %v", err)
	}

	crlfPEM := bytes.ReplaceAll(pubPEM, []byte("\n"), []byte("\r\n"))
	pubFromCRLF, _, err := keys.ParsePublicPEM(crlfPEM)
	if err != nil {
		t.Fatalf("ParsePublicPEM CRLF failed: %v", err)
	}

	keyIDFromCRLF, err := keys.KeyID(pubFromCRLF)
	if err != nil {
		t.Fatalf("KeyID CRLF failed: %v", err)
	}
	if keyIDFromCRLF != baseKeyID {
		t.Errorf("CRLF KeyID changed: got %s, want %s", keyIDFromCRLF, baseKeyID)
	}
}

func TestProfileOf_Rejections(t *testing.T) {
	rsa2048, _ := rsa.GenerateKey(rand.Reader, 2048)
	if _, err := keys.ProfileOf(&rsa2048.PublicKey); err == nil {
		t.Error("expected error for RSA 2048, got nil")
	}

	rsaBadE := &rsa.PublicKey{N: rsa2048.N, E: 3}
	if _, err := keys.ProfileOf(rsaBadE); err == nil {
		t.Error("expected error for RSA e=3, got nil")
	}

	ec384, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if _, err := keys.ProfileOf(&ec384.PublicKey); err == nil {
		t.Error("expected error for ECDSA P-384, got nil")
	}

	if _, err := keys.ProfileOf(nil); err == nil {
		t.Error("expected error for nil public key, got nil")
	}
}

func TestParsePEM_Rejections(t *testing.T) {
	rsaKey, _ := rsa.GenerateKey(rand.Reader, 3072)
	pkcs1DER := x509.MarshalPKCS1PrivateKey(rsaKey)
	pkcs1PEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: pkcs1DER})

	if _, _, err := keys.ParsePrivatePEM(pkcs1PEM); err == nil {
		t.Error("expected error for PKCS#1 RSA PRIVATE KEY label, got nil")
	}

	validPubPEM, _ := keys.MarshalPublicPEM(&rsaKey.PublicKey)
	tamperedPEM := append(validPubPEM, []byte("EXTRA GARBAGE DATA")...)
	if _, _, err := keys.ParsePublicPEM(tamperedPEM); err == nil {
		t.Error("expected error for trailing data after PEM block, got nil")
	}
}

func TestWriteKeyPair(t *testing.T) {
	tmpDir := t.TempDir()
	prefix := filepath.Join(tmpDir, "testkey")

	signer, err := keys.Generate(profile.Ed25519)
	if err != nil {
		t.Fatalf("Generate failed: %v", err)
	}

	privPath, pubPath, err := keys.WriteKeyPair(prefix, signer, false)
	if err != nil {
		t.Fatalf("WriteKeyPair failed: %v", err)
	}

	privInfo, err := os.Stat(privPath)
	if err != nil {
		t.Fatalf("stat privPath failed: %v", err)
	}
	if perm := privInfo.Mode().Perm(); perm != 0600 {
		t.Errorf("privKey permissions = %o, want 0600", perm)
	}

	pubInfo, err := os.Stat(pubPath)
	if err != nil {
		t.Fatalf("stat pubPath failed: %v", err)
	}
	if perm := pubInfo.Mode().Perm(); perm != 0644 {
		t.Errorf("pubKey permissions = %o, want 0644", perm)
	}

	if _, _, err := keys.WriteKeyPair(prefix, signer, false); err == nil {
		t.Error("expected error when writing to existing files without force, got nil")
	}

	if _, _, err := keys.WriteKeyPair(prefix, signer, true); err != nil {
		t.Errorf("expected success with force=true, got error: %v", err)
	}
}
