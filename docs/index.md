# release-signer API

`release-signer` signs and verifies software releases with RSA-PSS, ECDSA P-256, and Ed25519. This documentation covers two "APIs" you can use:

- **Go modules** under `pkg/...`, used by the CLI and importable by other Go programs.
- **The CLI**, used by CI/CD pipelines through the container image. Stdout, stderr, and the exit code are its contract.

## Overview

```text
artifact --hash--> manifest (canonical JSON) --sign--> bundle (manifest + signature, Base64)
bundle + artifact + trust store + (expected package, version) --verify--> status + exit code
```

A signature only proves authenticity and integrity. It is not a guarantee that the software is free of malware or vulnerabilities.

## Module map

| Package | Purpose | Main functions |
|---|---|---|
| [`pkg/profile`](api/pkg/profile.md) | Algorithm profile names and signature lengths | `Parse`, `SignatureLen` |
| [`pkg/keys`](api/pkg/keys.md) | Keygen, PEM PKCS#8 and SPKI, keyid | `Generate`, `ParsePrivatePEM`, `KeyID` |
| [`pkg/sigalg`](api/pkg/sigalg.md) | Sign and verify per profile | `Sign`, `Verify` |
| [`pkg/strictjson`](api/pkg/strictjson.md) | JSON parser that rejects duplicate keys | `Parse`, `ExpectKeys` |
| [`pkg/b64`](api/pkg/b64.md) | Strict RFC 4648 Base64 | `Encode`, `DecodeStrict` |
| [`pkg/manifest`](api/pkg/manifest.md) | Canonical release manifest | `New`, `Canonical`, `ParseStrict` |
| [`pkg/bundle`](api/pkg/bundle.md) | JSON bundle (manifest + signature) | `Build`, `ParseStrict`, `WriteFile` |
| [`pkg/truststore`](api/pkg/truststore.md) | Per-package trust store, atomic save | `Load`, `Add`, `Remove`, `Save` |
| [`pkg/release`](api/pkg/release.md) | Sign, verify, and SBOM flow | `Sign`, `Verify`, `SBOMCheck` |
| [`pkg/sbom`](api/pkg/sbom.md) | CycloneDX SBOM bound to the artifact SHA-256 | `Generate`, `ParseBinding` |

The reference for each package is generated from doc comments with [gomarkdoc](https://github.com/princjef/gomarkdoc). For usage see [Examples](examples.md), for data formats see [Data formats](formats.md), and for statuses and exit codes see [Status and exit codes](status.md).

## Conventions

- Every string that is signed or compared is ASCII. Hashes and keyids are lowercase hexadecimal.
- The signed manifest is the exact byte output of `Canonical()`. Verification uses the manifest bytes stored in the bundle, not a re-serialized copy.
- Every parse function is strict: duplicate fields, extra fields, `null`, and wrong types are rejected.
- `Verify` stops at the first failure and never tries another key, profile, or trust store.
