package b64_test

import (
	"fmt"

	"github.com/brii26/release-signer/pkg/b64"
)

// Input yang bukan Base64 canonical ditolak, termasuk newline di dalamnya.
func ExampleDecodeStrict() {
	ok, _ := b64.DecodeStrict("Zm9v")
	fmt.Println(string(ok))
	_, err := b64.DecodeStrict("Zm9v\n")
	fmt.Println(err != nil)
	// Output:
	// foo
	// true
}
