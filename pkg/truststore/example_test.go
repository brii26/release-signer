package truststore_test

import (
	"fmt"

	"github.com/brii26/release-signer/pkg/keys"
	"github.com/brii26/release-signer/pkg/profile"
	"github.com/brii26/release-signer/pkg/truststore"
)

// A key is trusted only for the packages it was added for.
func ExampleStore_Add() {
	signer, err := keys.Generate(profile.Ed25519)
	if err != nil {
		panic(err)
	}
	pub, err := keys.MarshalPublicPEM(signer.Public())
	if err != nil {
		panic(err)
	}

	store := &truststore.Store{}
	entry, changed, err := store.Add(pub, "demo-app")
	if err != nil {
		panic(err)
	}
	fmt.Println(changed, entry.Allows("demo-app"), entry.Allows("other-app"))

	_, changed, _ = store.Add(pub, "demo-app")
	fmt.Println(changed) // adding the same key and package again changes nothing
	// Output:
	// true true false
	// false
}
