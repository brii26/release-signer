package keys_test

import (
	"fmt"

	"github.com/brii26/release-signer/pkg/keys"
	"github.com/brii26/release-signer/pkg/profile"
)

// Generate key pair, export private key ke PKCS#8 PEM, lalu baca balik.
func ExampleParsePrivatePEM() {
	signer, err := keys.Generate(profile.Ed25519)
	if err != nil {
		panic(err)
	}
	pemBytes, err := keys.MarshalPrivatePEM(signer)
	if err != nil {
		panic(err)
	}
	_, prof, err := keys.ParsePrivatePEM(pemBytes)
	if err != nil {
		panic(err)
	}
	fmt.Println(prof)
	// Output: ed25519
}

// keyid = SHA-256 hex lowercase dari DER SPKI, jadi selalu 64 karakter.
func ExampleKeyID() {
	signer, err := keys.Generate(profile.ECDSA)
	if err != nil {
		panic(err)
	}
	id, err := keys.KeyID(signer.Public())
	if err != nil {
		panic(err)
	}
	fmt.Println(len(id))
	// Output: 64
}
