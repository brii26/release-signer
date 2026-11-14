package release_test

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/brii26/release-signer/pkg/keys"
	"github.com/brii26/release-signer/pkg/profile"
	"github.com/brii26/release-signer/pkg/release"
	"github.com/brii26/release-signer/pkg/sbom"
	"github.com/brii26/release-signer/pkg/truststore"
)

// fixture creates a signing key, a trust store that allows it for demo-app, and an artifact.
func fixture(dir string) (key, store, artifact, pubPEM string) {
	signer, err := keys.Generate(profile.Ed25519)
	if err != nil {
		panic(err)
	}
	priv, _ := keys.MarshalPrivatePEM(signer)
	pub, _ := keys.MarshalPublicPEM(signer.Public())

	key = filepath.Join(dir, "publisher.key.pem")
	if err := os.WriteFile(key, priv, 0o600); err != nil {
		panic(err)
	}
	s := &truststore.Store{}
	if _, _, err := s.Add(pub, "demo-app"); err != nil {
		panic(err)
	}
	store = filepath.Join(dir, "trust.json")
	if err := s.Save(store); err != nil {
		panic(err)
	}
	artifact = filepath.Join(dir, "demo-app.tar.gz")
	if err := os.WriteFile(artifact, []byte("release contents"), 0o644); err != nil {
		panic(err)
	}
	return key, store, artifact, string(pub)
}

// Sign an artifact and verify the bundle against a trust store.
func ExampleVerify() {
	dir, _ := os.MkdirTemp("", "release-example-")
	defer os.RemoveAll(dir)
	key, store, artifact, _ := fixture(dir)
	bundlePath := filepath.Join(dir, "release.json")

	if _, err := release.Sign(release.SignInput{
		ArtifactPath: artifact, Package: "demo-app", Version: "1.0.0",
		KeyPath: key, OutPath: bundlePath,
	}); err != nil {
		panic(err)
	}

	res := release.Verify(release.VerifyInput{
		ArtifactPath: artifact, BundlePath: bundlePath, TrustStorePath: store,
		Package: "demo-app", Version: "1.0.0",
	})
	fmt.Println(res.Valid, res.Status, res.ExitCode())

	// A different expected version is rejected, even though the signature is valid.
	res = release.Verify(release.VerifyInput{
		ArtifactPath: artifact, BundlePath: bundlePath, TrustStorePath: store,
		Package: "demo-app", Version: "2.0.0",
	})
	fmt.Println(res.Valid, res.Status, res.ExitCode())
	// Output:
	// true OK 0
	// false METADATA_MISMATCH 1
}

// Sign a release and its SBOM separately, then check that they belong together.
func ExampleSBOMCheck() {
	dir, _ := os.MkdirTemp("", "sbom-example-")
	defer os.RemoveAll(dir)
	key, store, artifact, _ := fixture(dir)
	relBundle := filepath.Join(dir, "release.json")
	sbomPath := filepath.Join(dir, "sbom.cdx.json")
	sbomBundle := filepath.Join(dir, "sbom.bundle.json")

	if _, err := release.Sign(release.SignInput{
		ArtifactPath: artifact, Package: "demo-app", Version: "1.0.0", KeyPath: key, OutPath: relBundle,
	}); err != nil {
		panic(err)
	}
	doc, err := sbom.Generate(artifact, "demo-app", "1.0.0")
	if err != nil {
		panic(err)
	}
	if err := os.WriteFile(sbomPath, doc, 0o644); err != nil {
		panic(err)
	}
	if _, err := release.SBOMSign(release.SignInput{
		ArtifactPath: sbomPath, Package: "demo-app", Version: "1.0.0", KeyPath: key, OutPath: sbomBundle,
	}); err != nil {
		panic(err)
	}

	res := release.SBOMCheck(release.CheckInput{
		ArtifactPath: artifact, ReleaseBundle: relBundle,
		SBOMPath: sbomPath, SBOMBundle: sbomBundle,
		TrustStorePath: store, Package: "demo-app", Version: "1.0.0",
	})
	fmt.Println(res.Valid, res.Status)
	// Output: true OK
}
