package sbom_test

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/brii26/release-signer/pkg/sbom"
)

// Generate an SBOM for an artifact and read its binding back.
func ExampleParseBinding() {
	dir, err := os.MkdirTemp("", "sbom-example-")
	if err != nil {
		panic(err)
	}
	defer os.RemoveAll(dir)

	artifact := filepath.Join(dir, "empty.bin")
	if err := os.WriteFile(artifact, nil, 0o644); err != nil {
		panic(err)
	}
	doc, err := sbom.Generate(artifact, "demo-app", "1.0.0")
	if err != nil {
		panic(err)
	}
	b, err := sbom.ParseBinding(doc)
	if err != nil {
		panic(err)
	}
	fmt.Println(b.Package, b.Version, b.ArtifactName)
	fmt.Println(b.ArtifactSHA)
	// Output:
	// demo-app 1.0.0 empty.bin
	// e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
}
