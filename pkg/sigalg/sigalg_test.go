package sigalg_test

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/hex"
	"math/big"
	"testing"

	"github.com/brii26/release-signer/pkg/keys"
	"github.com/brii26/release-signer/pkg/profile"
	"github.com/brii26/release-signer/pkg/sigalg"
)

func TestSignAndVerifyRoundtrip(t *testing.T) {
	profiles := []profile.Profile{
		profile.RSAPSS,
		profile.ECDSA,
		profile.Ed25519,
	}

	testMessages := [][]byte{
		[]byte("hello world"),
		[]byte(""),
		bytes.Repeat([]byte("A"), 10000),
	}

	for _, p := range profiles {
		t.Run(string(p), func(t *testing.T) {
			signer, err := keys.Generate(p)
			if err != nil {
				t.Fatalf("keys.Generate failed: %v", err)
			}

			for _, msg := range testMessages {
				sig, err := sigalg.Sign(p, signer, msg)
				if err != nil {
					t.Fatalf("Sign failed: %v", err)
				}

				if len(sig) != p.SignatureLen() {
					t.Fatalf("signature len = %d, want %d", len(sig), p.SignatureLen())
				}

				if !sigalg.Verify(p, signer.Public(), msg, sig) {
					t.Fatalf("Verify failed on valid signature")
				}

				// Verify fails on altered message
				tamperedMsg := append([]byte("tamper:"), msg...)
				if sigalg.Verify(p, signer.Public(), tamperedMsg, sig) {
					t.Errorf("Verify succeeded on altered message")
				}
			}
		})
	}
}

func TestSignatureTamperBitFlip(t *testing.T) {
	profiles := []profile.Profile{
		profile.RSAPSS,
		profile.ECDSA,
		profile.Ed25519,
	}

	msg := []byte("important release manifest payload")

	for _, p := range profiles {
		t.Run(string(p), func(t *testing.T) {
			signer, err := keys.Generate(p)
			if err != nil {
				t.Fatalf("keys.Generate failed: %v", err)
			}

			sig, err := sigalg.Sign(p, signer, msg)
			if err != nil {
				t.Fatalf("Sign failed: %v", err)
			}

			// Flip a bit in the middle of the signature
			corruptedSig := make([]byte, len(sig))
			copy(corruptedSig, sig)
			corruptedSig[len(sig)/2] ^= 0x01

			if sigalg.Verify(p, signer.Public(), msg, corruptedSig) {
				t.Errorf("Verify should return false when signature bit is flipped")
			}
		})
	}
}

func TestSignatureLengthMismatch(t *testing.T) {
	profiles := []profile.Profile{
		profile.RSAPSS,
		profile.ECDSA,
		profile.Ed25519,
	}

	msg := []byte("payload")

	for _, p := range profiles {
		t.Run(string(p), func(t *testing.T) {
			signer, err := keys.Generate(p)
			if err != nil {
				t.Fatalf("keys.Generate failed: %v", err)
			}

			sig, err := sigalg.Sign(p, signer, msg)
			if err != nil {
				t.Fatalf("Sign failed: %v", err)
			}

			// Truncated by 1 byte
			if sigalg.Verify(p, signer.Public(), msg, sig[:len(sig)-1]) {
				t.Errorf("Verify should reject truncated signature")
			}

			// Extended by 1 byte
			extendedSig := append(sig, 0x00)
			if sigalg.Verify(p, signer.Public(), msg, extendedSig) {
				t.Errorf("Verify should reject extended signature")
			}
		})
	}
}

func TestDoubleHashingGuards(t *testing.T) {
	msg := []byte("release manifest bytes")
	h := sha256.Sum256(msg)
	h2 := sha256.Sum256(h[:])

	// 1. RSA double hash check
	rsaKey, err := keys.Generate(profile.RSAPSS)
	if err != nil {
		t.Fatal(err)
	}
	rsaSig, err := sigalg.Sign(profile.RSAPSS, rsaKey, msg)
	if err != nil {
		t.Fatal(err)
	}
	rsaPub := rsaKey.Public().(*rsa.PublicKey)
	opts := &rsa.PSSOptions{SaltLength: 32, Hash: crypto.SHA256}

	// Must pass over single hash h[:]
	if err := rsa.VerifyPSS(rsaPub, crypto.SHA256, h[:], rsaSig, opts); err != nil {
		t.Errorf("rsa.VerifyPSS over h[:] failed: %v", err)
	}
	// Must fail over double hash h2[:]
	if err := rsa.VerifyPSS(rsaPub, crypto.SHA256, h2[:], rsaSig, opts); err == nil {
		t.Errorf("rsa.VerifyPSS unexpectedly succeeded over double hash h2[:]")
	}

	// 2. ECDSA double hash check
	ecKey, err := keys.Generate(profile.ECDSA)
	if err != nil {
		t.Fatal(err)
	}
	ecSig, err := sigalg.Sign(profile.ECDSA, ecKey, msg)
	if err != nil {
		t.Fatal(err)
	}
	ecPub := ecKey.Public().(*ecdsa.PublicKey)
	r := new(big.Int).SetBytes(ecSig[:32])
	s := new(big.Int).SetBytes(ecSig[32:])

	// Must pass over single hash h[:]
	if !ecdsa.Verify(ecPub, h[:], r, s) {
		t.Errorf("ecdsa.Verify over h[:] failed")
	}
	// Must fail over double hash h2[:]
	if ecdsa.Verify(ecPub, h2[:], r, s) {
		t.Errorf("ecdsa.Verify unexpectedly succeeded over double hash h2[:]")
	}
}

func TestRSAPSSRejectNon32ByteSalt(t *testing.T) {
	rsaKey, err := keys.Generate(profile.RSAPSS)
	if err != nil {
		t.Fatal(err)
	}
	msg := []byte("test message")
	h := sha256.Sum256(msg)

	// Create non-compliant signature with salt length = 20 (PKCS#1 v2.1 default)
	badOpts := &rsa.PSSOptions{SaltLength: 20, Hash: crypto.SHA256}
	badSig, err := rsa.SignPSS(rand.Reader, rsaKey.(*rsa.PrivateKey), crypto.SHA256, h[:], badOpts)
	if err != nil {
		t.Fatalf("SignPSS failed: %v", err)
	}

	// sigalg.Verify strictly requires salt length 32 and must reject this
	if sigalg.Verify(profile.RSAPSS, rsaKey.Public(), msg, badSig) {
		t.Errorf("sigalg.Verify should reject RSA-PSS signature with 20-byte salt")
	}
}

func TestECDSABoundaries(t *testing.T) {
	ecKey, err := keys.Generate(profile.ECDSA)
	if err != nil {
		t.Fatal(err)
	}
	pub := ecKey.Public().(*ecdsa.PublicKey)
	n := pub.Curve.Params().N
	msg := []byte("message")

	// Case 1: r = 0
	sigZeroR := make([]byte, 64)
	new(big.Int).SetInt64(1).FillBytes(sigZeroR[32:]) // s = 1
	if sigalg.Verify(profile.ECDSA, pub, msg, sigZeroR) {
		t.Errorf("Verify should reject r = 0")
	}

	// Case 2: s = 0
	sigZeroS := make([]byte, 64)
	new(big.Int).SetInt64(1).FillBytes(sigZeroS[:32]) // r = 1
	if sigalg.Verify(profile.ECDSA, pub, msg, sigZeroS) {
		t.Errorf("Verify should reject s = 0")
	}

	// Case 3: r = n
	sigNR := make([]byte, 64)
	n.FillBytes(sigNR[:32])
	new(big.Int).SetInt64(1).FillBytes(sigNR[32:])
	if sigalg.Verify(profile.ECDSA, pub, msg, sigNR) {
		t.Errorf("Verify should reject r = n")
	}

	// Case 4: s = n
	sigNS := make([]byte, 64)
	new(big.Int).SetInt64(1).FillBytes(sigNS[:32])
	n.FillBytes(sigNS[32:])
	if sigalg.Verify(profile.ECDSA, pub, msg, sigNS) {
		t.Errorf("Verify should reject s = n")
	}
}

func TestRFC8032TestVector1(t *testing.T) {
	// RFC 8032 Section 7.1 TEST 1
	seedHex := "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"
	expectedSigHex := "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"

	seed, err := hex.DecodeString(seedHex)
	if err != nil {
		t.Fatal(err)
	}

	privKey := ed25519.NewKeyFromSeed(seed)
	pubKey := privKey.Public().(ed25519.PublicKey)

	msg := []byte{} // empty message for TEST 1
	sig, err := sigalg.Sign(profile.Ed25519, privKey, msg)
	if err != nil {
		t.Fatalf("Sign failed: %v", err)
	}

	gotSigHex := hex.EncodeToString(sig)
	if gotSigHex != expectedSigHex {
		t.Fatalf("RFC 8032 signature mismatch:\ngot:  %s\nwant: %s", gotSigHex, expectedSigHex)
	}

	if !sigalg.Verify(profile.Ed25519, pubKey, msg, sig) {
		t.Errorf("RFC 8032 signature verification failed")
	}
}

func TestRFC6979TestVectorA25(t *testing.T) {
	// RFC 6979 Section A.2.5 (P-256, SHA-256, message "sample")
	// Public key coordinates:
	uxHex := "60FED4BA255A9D31C961EB74C6356D68C049B8923B61FA6CE669622E60F29FB6"
	uyHex := "7903FE1008B8BC99A41AE9E95628BC64F2F1B20C2D7E9F5177A3C294D4462299"

	rHex := "EFD48B2AACB6A8FD1140DD9CD45E81D69D2C877B56AAF991C34D0EA84EAF3716"
	sHex := "F7CB1C942D657C41D436C7A1B6E29F65F3E900DBB9AFF4064DC4AB2F843ACDA8"

	ux, _ := new(big.Int).SetString(uxHex, 16)
	uy, _ := new(big.Int).SetString(uyHex, 16)
	r, _ := new(big.Int).SetString(rHex, 16)
	s, _ := new(big.Int).SetString(sHex, 16)

	pub := &ecdsa.PublicKey{
		Curve: elliptic.P256(),
		X:     ux,
		Y:     uy,
	}

	sig := make([]byte, 64)
	r.FillBytes(sig[:32])
	s.FillBytes(sig[32:])

	msg := []byte("sample")
	if !sigalg.Verify(profile.ECDSA, pub, msg, sig) {
		t.Errorf("RFC 6979 A.2.5 signature verification failed")
	}
}

func TestSignatureDeterminismAcrossRuns(t *testing.T) {
	// Basis for U14 scenario:
	// RSA-PSS uses random salt -> signatures differ.
	// ECDSA uses CSPRNG/hedged nonce -> signatures differ.
	// Ed25519 is PureEdDSA deterministic -> signatures are identical.
	msg := []byte("consistent manifest message")

	// 1. RSA-PSS
	rsaKey, err := keys.Generate(profile.RSAPSS)
	if err != nil {
		t.Fatal(err)
	}
	rsaSig1, _ := sigalg.Sign(profile.RSAPSS, rsaKey, msg)
	rsaSig2, _ := sigalg.Sign(profile.RSAPSS, rsaKey, msg)
	if bytes.Equal(rsaSig1, rsaSig2) {
		t.Errorf("RSA-PSS signatures unexpectedly identical across runs")
	}
	if !sigalg.Verify(profile.RSAPSS, rsaKey.Public(), msg, rsaSig1) || !sigalg.Verify(profile.RSAPSS, rsaKey.Public(), msg, rsaSig2) {
		t.Errorf("RSA-PSS verification failed")
	}

	// 2. ECDSA
	ecKey, err := keys.Generate(profile.ECDSA)
	if err != nil {
		t.Fatal(err)
	}
	ecSig1, _ := sigalg.Sign(profile.ECDSA, ecKey, msg)
	ecSig2, _ := sigalg.Sign(profile.ECDSA, ecKey, msg)
	if bytes.Equal(ecSig1, ecSig2) {
		t.Errorf("ECDSA signatures unexpectedly identical across runs (hedged randomness expected)")
	}
	if !sigalg.Verify(profile.ECDSA, ecKey.Public(), msg, ecSig1) || !sigalg.Verify(profile.ECDSA, ecKey.Public(), msg, ecSig2) {
		t.Errorf("ECDSA verification failed")
	}

	// 3. Ed25519
	edKey, err := keys.Generate(profile.Ed25519)
	if err != nil {
		t.Fatal(err)
	}
	edSig1, _ := sigalg.Sign(profile.Ed25519, edKey, msg)
	edSig2, _ := sigalg.Sign(profile.Ed25519, edKey, msg)
	if !bytes.Equal(edSig1, edSig2) {
		t.Errorf("Ed25519 signatures differed across runs (deterministic PureEdDSA expected)")
	}
	if !sigalg.Verify(profile.Ed25519, edKey.Public(), msg, edSig1) {
		t.Errorf("Ed25519 verification failed")
	}
}
