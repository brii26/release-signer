# Usage examples

## CLI

```sh
release-signer keygen --algorithm ed25519 --out keys/publisher
release-signer trust add --key keys/publisher.pub.pem --package demo-app --store trust.json
release-signer sign --file demo-app.tar.gz --package demo-app --version 1.0.0 \
  --key keys/publisher.key.pem --out release.json
release-signer verify --file demo-app.tar.gz --bundle release.json \
  --trust-store trust.json --package demo-app --version 1.0.0 --json
```

Output of `verify --json` for a valid release:

```json
{"valid":true,"status":"OK","message":"...","algorithm":"ed25519","keyid":"<64 hex>","package":"demo-app","version":"1.0.0"}
```

One byte of the artifact changed after signing:

```json
{"valid":false,"status":"ARTIFACT_MISMATCH","message":"...","algorithm":"ed25519","keyid":"<64 hex>","package":"demo-app","version":"1.0.0"}
```

The exit code is 1. For a file that does not exist, the status is `INPUT_ERROR`, the exit code is 2, and the metadata fields are `null`.

## Go modules

Sign, then verify:

```go
import (
    "github.com/brii26/release-signer/pkg/release"
)

out, err := release.Sign(release.SignInput{
    ArtifactPath: "demo-app.tar.gz",
    Package:      "demo-app",
    Version:      "1.0.0",
    KeyPath:      "keys/publisher.key.pem",
    OutPath:      "release.json",
})
if err != nil {
    return err // wrapped in release.ErrInput, equivalent to exit code 2
}
_ = out.KeyID

res := release.Verify(release.VerifyInput{
    ArtifactPath:   "demo-app.tar.gz",
    BundlePath:     "release.json",
    TrustStorePath: "trust.json",
    Package:        "demo-app",
    Version:        "1.0.0",
})
if res.Status != release.StatusOK {
    return fmt.Errorf("rejected: %s: %s", res.Status, res.Message)
}
```

Runnable examples live in each package's `example_test.go` (`go test ./pkg/...`) and appear in the package reference.

## Strict parser

```go
_, err := strictjson.Parse([]byte(`{"a":1,"a":2}`), 1024)
errors.Is(err, strictjson.ErrDuplicateKey) // true
```

## Signed SBOM

See the Examples section of [Signed SBOM](sbom.md).
