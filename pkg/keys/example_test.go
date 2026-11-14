package keys_test

import (
	"fmt"

	"github.com/brii26/release-signer/pkg/keys"
	"github.com/brii26/release-signer/pkg/profile"
)

// Generate a key pair, export the private key as PKCS#8 PEM, and read it back.
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

// The keyid is the lowercase hex SHA-256 of the DER SPKI, so it is always 64 characters.
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
