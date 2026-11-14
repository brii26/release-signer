# Integration Test and CI/CD Pipeline Results (Section 2.9)

## Pinned Image Reference
- **Registry image:** `ghcr.io/brii26/release-signer@sha256:6bf0609bd7d5692361e16a3c8658826489cdd8eed04d07c43167969e742ee612`
- **Pinning configuration:** [`ci/image.env`](../../ci/image.env)
- **Demo release metadata:** [`ci/release.env`](../../ci/release.env) (`PACKAGE=demo-app`, `VERSION=1.0.0`)
- **CI trust store:** [`ci/trust.json`](../../ci/trust.json) (3 demo public key profiles from [`ci/keys/`](../../ci/keys/))

## Workflow Run Links
- **Publish Container Image (`publish-image.yml`, with SBOM):** https://github.com/brii26/release-signer/actions/runs/43632671905
- **Release Pipeline (`release-pipeline.yml`, C01 to C05 baseline):** https://github.com/brii26/release-signer/actions/runs/43633254738
- **CI Integration Tests C01 to C05 (`ci-integration.yml`):** https://github.com/brii26/release-signer/actions/runs/43633254734

## Summary of Scenarios C01 to C05 (Table 2.15)
Every scenario runs in an isolated container (`--network none --user "$(id -u):$(id -g)" </dev/null`) with no TTY and without rebuilding the binary from source.

| ID | Profile | Scenario | Expected | Actual | Deploy marker | Evidence |
|:---|:---|:---|:---|:---|:---|:---|
| C01 | `rsa-pss-sha256` | Sign and verify a valid artifact | exit `0`, `OK` | exit `0`, `OK` | Present (`deployed.marker`, `deployed-rsa-pss-sha256.marker`) | [`C01/rsa-pss-sha256/`](./C01/rsa-pss-sha256/) |
| C01 | `ecdsa-p256-sha256` | Sign and verify a valid artifact | exit `0`, `OK` | exit `0`, `OK` | Present (`deployed.marker`, `deployed-ecdsa-p256-sha256.marker`) | [`C01/ecdsa-p256-sha256/`](./C01/ecdsa-p256-sha256/) |
| C01 | `ed25519` | Sign and verify a valid artifact | exit `0`, `OK` | exit `0`, `OK` | Present (`deployed.marker`, `deployed-ed25519.marker`) | [`C01/ed25519/`](./C01/ed25519/) |
| C02 | `ed25519` | Artifact changed by 1 byte (offset 10) after sign | exit `1`, `ARTIFACT_MISMATCH` | exit `1`, `ARTIFACT_MISMATCH` | Absent | [`C02/`](./C02/) |
| C03 | `ed25519` | Verify with an empty trust store and with a store limited to `other-app` | exit `1`, `KEY_NOT_TRUSTED` | exit `1` (both), `KEY_NOT_TRUSTED` | Absent | [`C03/`](./C03/) |
| C04 | `ed25519` | Verify with `--file /input/tidak-ada.tar.gz` | exit `2`, `INPUT_ERROR` | exit `2`, `INPUT_ERROR` | Absent | [`C04/`](./C04/) |
| C05 | `ed25519` | `keygen`, `trust add`, `sign`, `verify` (`--user`, `--network none`, no TTY) | exit `0`, `stat -c %u out/* == $(id -u)` | exit `0`, every file owned by the runner user (UID `1001`) | N/A | [`C05/`](./C05/) |
