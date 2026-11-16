package strictjson_test

import (
	"errors"
	"fmt"

	"github.com/brii26/release-signer/pkg/strictjson"
)

// Duplicate key jadi error, bukan diam-diam ambil nilai terakhir.
func ExampleParse() {
	_, err := strictjson.Parse([]byte(`{"a":1,"a":2}`), 1024)
	fmt.Println(errors.Is(err, strictjson.ErrDuplicateKey))
	// Output: true
}
