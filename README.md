<div align="center">
   <img width="100%" src="https://capsule-render.vercel.app/api?type=waving&height=260&color=0:1F6FEB,100:0B2A5B&text=release-signer&fontColor=FFFFFF&fontSize=62&desc=IF4020%20Cryptography%20Assignment%203&descAlignY=76&descSize=17&descColor=C9D8F5" />
</div>

<div align="center">
   <br/>
   <img src="https://img.shields.io/badge/Go-1.27-00ADD8?style=for-the-badge&logo=go&logoColor=white" />
   <img src="https://img.shields.io/badge/Docker-distroless-2496ED?style=for-the-badge&logo=docker&logoColor=white" />
   <img src="https://img.shields.io/badge/GitHub%20Actions-CI%2FCD-2088FF?style=for-the-badge&logo=githubactions&logoColor=white" />
   <img src="https://img.shields.io/badge/GHCR-image-181717?style=for-the-badge&logo=github&logoColor=white" />
   <img src="https://img.shields.io/badge/CycloneDX-1.6-4A9FD8?style=for-the-badge" />
</div>

---

## About

`release-signer` is a CLI for signing and verifying software releases. An artifact is described by a release manifest in canonical JSON, the manifest and its signature are wrapped in one Base64 bundle, and verification uses a local trust store owned by the recipient. Three algorithm profiles are supported: `rsa-pss-sha256`, `ecdsa-p256-sha256`, and `ed25519`.

A signature only proves authenticity and integrity of the artifact. It does not guarantee that the software is free of malware or vulnerabilities.

Main features:

- **Sign and verify**
  The manifest records the package, version, algorithm, keyid, and the name, size, and SHA-256 of the artifact. Verify stops at the first failure with a fixed status and exit code.
- **Trust store**
  A public key is trusted per package through `trust add`. The bundle never carries a public key, and `verify` never writes the trust store.
- **Container and pipeline**
  A distroless image runs on CI/CD runners, referenced by `sha256` digest, with no network and no TTY.
- **Signed SBOM (bonus)**
  A CycloneDX SBOM is signed as a separate artifact and bound to the SHA-256 of the release artifact.
- **API documentation (bonus)**
  Go module and CLI reference hosted on GitHub Pages: https://brii26.github.io/release-signer/

---

## Tech Stack

| Layer | Technology |
|:---|:---|
| Language | Go 1.27 |
| Cryptography | `crypto/rsa`, `crypto/ecdsa`, `crypto/ed25519`, `crypto/sha256` (standard library) |
| Encoding | `encoding/base64`, custom strict JSON parser (`pkg/strictjson`) |
| Container | Docker, base image `distroless/static-debian12:nonroot` |
| Registry | GitHub Container Registry (GHCR) |
| CI/CD | GitHub Actions |
| SBOM | CycloneDX 1.6 (JSON) |
| API docs | gomarkdoc v1.1.0, MkDocs Material 9.5.50, GitHub Pages |
| Interop tests | OpenSSL 3, Python 3 with `cryptography==50.0.2`, uv |

## Dependencies

| Component | Version | Used for | Documentation |
|:---|:---|:---|:---|
| Go standard library | 1.27 | The whole program. `go.mod` has no third-party dependency. | https://pkg.go.dev/std |
| golang (build base image) | `alpine`, pinned by digest | Build stage of the `Dockerfile` | https://hub.docker.com/_/golang |
| distroless static | `debian12:nonroot`, pinned by digest | Runtime image | https://github.com/GoogleContainerTools/distroless |
| gomarkdoc | v1.1.0 | API reference (documentation only) | https://github.com/princjef/gomarkdoc |
| MkDocs Material | 9.5.50 | Documentation site (documentation only) | https://squidfunnel.github.io/mkdocs-material/ |
| OpenSSL | 3.x | Interoperability tests only | https://docs.openssl.org/3.0/ |
| Python `cryptography` | 50.0.2 | Interoperability tests only | https://cryptography.io/en/latest/ |

The program has no runtime dependency other than the binary itself.

---

## Profile to Library API Mapping

| Profile | Hash | Signature | Go API | Signature size |
|:---|:---|:---|:---|:---|
| `rsa-pss-sha256` | SHA-256 over the manifest bytes | RSASSA-PSS, MGF1-SHA-256, 32 byte salt | `rsa.SignPSS`, `rsa.VerifyPSS` with `rsa.PSSOptions{SaltLength: 32}` | 384 bytes (RSA 3072 bit, e = 65537) |
| `ecdsa-p256-sha256` | SHA-256 over the manifest bytes | ECDSA P-256 | `ecdsa.Sign`, `ecdsa.Verify` | 64 bytes, `r \|\| s` with 32 byte big-endian each |
| `ed25519` | none (no prehash) | Pure Ed25519 (RFC 8032), not Ed25519ph | `ed25519.Sign`, `ed25519.Verify` | 64 bytes |

Key format: private key is PKCS#8 PEM (`PRIVATE KEY`, mode `0600`), public key is SubjectPublicKeyInfo PEM (`PUBLIC KEY`). The keyid is `hex_lower(SHA256(DER SPKI))`.

## File Formats

Summary only, see [`docs/formats.md`](docs/formats.md) for the full specification.

| File | Schema | Limit | Content |
|:---|:---|:---|:---|
| Release manifest | `minisign-manifest/v1` | 16 KiB | `package`, `version`, `algorithm`, `keyid`, `artifact{name,size,sha256}`. Canonical: no whitespace, fixed field order. |
| Bundle | `minisign-bundle/v1` | 64 KiB | `manifest_b64`, `signature_b64` (strict Base64 per RFC 4648). |
| Trust store | `minisign-trust/v1` | | `keys[]` with `keyid`, `algorithm`, `public_key_pem`, `packages`. |
| SBOM | CycloneDX 1.6 | 1 MiB | Artifact SHA-256 in `metadata.component.hashes`. See [`docs/sbom.md`](docs/sbom.md). |

Parsers reject duplicate fields, extra fields, `null`, and wrong types.

---

## Subcommands

All commands are non-interactive. Parameter reference: [`docs/cli.md`](docs/cli.md). Status and exit codes: [`docs/status.md`](docs/status.md).

```sh
# generate a key pair
release-signer keygen --algorithm ed25519 --out keys/publisher

# trust a public key for one package
release-signer trust add --key keys/publisher.pub.pem --package demo-app --store trust.json
release-signer trust list --store trust.json
release-signer trust remove --keyid <64 hex> --store trust.json

# sign
release-signer sign --file demo-app.tar.gz --package demo-app --version 1.0.0 \
  --key keys/publisher.key.pem --out release.json

# verify
release-signer verify --file demo-app.tar.gz --bundle release.json \
  --trust-store trust.json --package demo-app --version 1.0.0 --json
```

Output of `verify --json`:

```json
{"valid":true,"status":"OK","message":"...","algorithm":"ed25519","keyid":"<64 hex>","package":"demo-app","version":"1.0.0"}
```

| Exit code | Meaning |
|:---:|:---|
| 0 | `OK` |
| 1 | Verify rejected (`FORMAT_ERROR`, `UNSUPPORTED_ALGORITHM`, `KEY_NOT_TRUSTED`, `INVALID_SIGNATURE`, `METADATA_MISMATCH`, `ARTIFACT_MISMATCH`, `SBOM_MISMATCH`) |
| 2 | Usage, I/O, or environment error (`INPUT_ERROR`) |

Signed SBOM (bonus):

```sh
release-signer sbom generate --file demo-app.tar.gz --package demo-app --version 1.0.0 --out sbom.cdx.json
release-signer sbom sign --sbom sbom.cdx.json --package demo-app --version 1.0.0 \
  --key keys/publisher.key.pem --out sbom.bundle.json
release-signer sbom verify --sbom sbom.cdx.json --bundle sbom.bundle.json \
  --trust-store trust.json --package demo-app --version 1.0.0 --json
release-signer sbom check --file demo-app.tar.gz --bundle release.json \
  --sbom sbom.cdx.json --sbom-bundle sbom.bundle.json \
  --trust-store trust.json --package demo-app --version 1.0.0 --json
```

---

## Running on a CI/CD Runner

### Pulling the image

The image is pinned by digest, never by the `latest` tag. The current value is in [`ci/image.env`](ci/image.env).

```sh
. ./ci/image.env
docker pull "$IMAGE"
```

| Program version | Repository tag | Image | Digest |
|:---|:---|:---|:---|
| 1.0.0 | `v1.0.0` (created at release) | `ghcr.io/brii26/release-signer` | `sha256:0853d9e4bbca739361262b45623d6be1e6cc977bb4001b49f27f2f611e8d2c07` (current pin, updated at final verification) |

The image is built from the `Dockerfile` at the tagged commit by the [`publish-image.yml`](.github/workflows/publish-image.yml) workflow whenever a `v*` tag is pushed.

### Using it in a workflow

The user workflow is [`.github/workflows/release-pipeline.yml`](.github/workflows/release-pipeline.yml), with the jobs `prepare`, `sign`, `verify`, and `deploy`. Deploy only runs when verify passes.

```sh
docker run --rm --network none --user "$(id -u):$(id -g)" \
  -v "$PWD/dist:/input:ro" -v "$PWD/out:/output" -v "$KEY_FILE:/key.pem:ro" \
  "$IMAGE" sign --file /input/demo-app.tar.gz --package demo-app --version 1.0.0 \
  --key /key.pem --out /output/release.json </dev/null
```

Pipeline rules:

- The private key comes only from a GitHub Secret (`SIGNING_KEY_*`), is written to a temporary file under `RUNNER_TEMP`, and is removed by a `trap`.
- The `verify` and `deploy` jobs have no access to the signing secrets.
- The trust store comes from the repository ([`ci/trust.json`](ci/trust.json)), not from the bundle.
- `keygen` and `trust add` never run automatically in the release pipeline.
- The verify result is judged by its exit code. There is no `|| true` or `continue-on-error`.

### Integration test evidence

Scenarios C01 to C05 are run by [`ci-integration.yml`](.github/workflows/ci-integration.yml). The configuration, sanitized logs, JSON output, deploy marker evidence, and workflow run links are in [`results/ci/README.md`](results/ci/README.md).

---

## Running Outside a CI/CD Runner

Prerequisite: Go 1.27.

```sh
git clone https://github.com/brii26/release-signer.git
cd release-signer
make build                      # produces bin/release-signer
./bin/release-signer --version
```

Or through a container:

```sh
make docker VERSION=1.0.0
docker run --rm release-signer:1.0.0 --help
```

A complete local flow is shown in [Subcommands](#subcommands).

---

## Repeating the Tests

| Command | Content | Result |
|:---|:---|:---|
| `make test` | Unit tests for all packages (`go test -race ./...`) | stdout |
| `make vet` and `make fmt-check` | Static analysis and formatting | stdout |
| `make scenarios` | Scenarios U01 to U14 and negative cases for the three profiles | [`results/scenarios/`](results/scenarios/results.md) |
| `make sbom-test` | Scenarios S01 to S09 for the signed SBOM | [`results/sbom/`](results/sbom/results.md) |
| `make interop` | Interoperability with OpenSSL and Python (needs OpenSSL, uv) | [`results/interop/`](results/interop/results.md) |
| `make bench` | Benchmark of keygen, hash, sign, verify, and e2e | [`results/bench/`](results/bench/summary.md) |
| `make docs` | API reference and MkDocs site (needs `mkdocs`) | `site/` |

Scenarios C01 to C05 run through GitHub Actions (`ci-integration`), not on a local machine.

Key pairs dedicated to testing are in [`test/keys/`](test/keys/README.md) and [`ci/keys/`](ci/keys/). They are for tests only and must never be used for real services. Text, binary, and empty file fixtures are in [`test/fixtures/`](test/fixtures/).

---

## Project Structure

```
release-signer/
├── cmd/release-signer/   entry point
├── internal/cli/         argument parsing and subcommands
├── pkg/
│   ├── profile/          profile names and signature lengths
│   ├── keys/             keygen, PEM, keyid
│   ├── sigalg/           sign and verify per profile
│   ├── strictjson/       strict JSON parser
│   ├── b64/              strict Base64
│   ├── manifest/         canonical release manifest
│   ├── bundle/           JSON bundle
│   ├── truststore/       trust store
│   ├── release/          sign, verify, and SBOM check flow
│   └── sbom/             CycloneDX SBOM
├── test/                 e2e, interop, sbom, fixtures, keys
├── bench/                benchmark
├── results/              test results (scenarios, interop, bench, ci, sbom)
├── ci/                   image.env, release.env, trust.json, test public keys
├── docs/                 API and security documentation (MkDocs source)
├── doc/                  PDF report
├── .github/workflows/    test, publish-image, release-pipeline, ci-integration, docs
└── Dockerfile
```

## Documentation

- API docs: https://brii26.github.io/release-signer/
- Security analysis and threat model: [`docs/security.md`](docs/security.md)
- PDF report: see the [`doc/`](doc/) folder

---

## Authors

<div align="center">

| NIM | Name |
|:---:|:---|
| 13523126 | Brian Ricardo Tamin |
| 13523061 | Darrel Adinarya Sunanda |
| 13523147 | Frederiko Eldad Mugiyono |

</div>

---

<div align="center">
   <img width="100%" src="https://capsule-render.vercel.app/api?type=waving&height=120&color=0:0B2A5B,100:1F6FEB&section=footer" />
</div>
