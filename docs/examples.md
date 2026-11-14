# Contoh penggunaan

## CLI

```sh
release-signer keygen --algorithm ed25519 --out keys/publisher
release-signer trust add --key keys/publisher.pub.pem --package demo-app --store trust.json
release-signer sign --file demo-app.tar.gz --package demo-app --version 1.0.0 \
  --key keys/publisher.key.pem --out release.json
release-signer verify --file demo-app.tar.gz --bundle release.json \
  --trust-store trust.json --package demo-app --version 1.0.0 --json
```

Keluaran `verify --json` untuk rilis yang sah:

```json
{"valid":true,"status":"OK","message":"...","algorithm":"ed25519","keyid":"<64 hex>","package":"demo-app","version":"1.0.0"}
```

Satu byte artefak diubah setelah sign:

```json
{"valid":false,"status":"ARTIFACT_MISMATCH","message":"...","algorithm":"ed25519","keyid":"<64 hex>","package":"demo-app","version":"1.0.0"}
```

Exit code-nya 1. Untuk berkas yang tidak ada, statusnya `INPUT_ERROR`, exit 2, dan field metadata `null`.

## Modul Go

Sign lalu verify:

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
    return err // dibungkus release.ErrInput, setara exit code 2
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

Contoh yang bisa dijalankan sebagai test ada di berkas `example_test.go` tiap package (`go test ./pkg/...`) dan tampil di referensi package.

## Parser strict

```go
_, err := strictjson.Parse([]byte(`{"a":1,"a":2}`), 1024)
errors.Is(err, strictjson.ErrDuplicateKey) // true
```

## Signed SBOM

Lihat bagian Contoh di [Signed SBOM](sbom.md).
