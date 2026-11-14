# Hasil Uji Integrasi dan Pipeline CI/CD (Bagian 2.9)

## Referensi Image Terpin
- **Registry Image:** `ghcr.io/brii26/release-signer@sha256:0853d9e4bbca739361262b45623d6be1e6cc977bb4001b49f27f2f611e8d2c07`
- **Konfigurasi Pinning:** [`ci/image.env`](../../ci/image.env)
- **Metadata Rilis Demo:** [`ci/release.env`](../../ci/release.env) (`PACKAGE=demo-app`, `VERSION=1.0.0`)
- **Trust Store CI:** [`ci/trust.json`](../../ci/trust.json) (3 profil kunci publik demo dari [`ci/keys/`](../../ci/keys/))

## Tautan Workflow Run
- **Publish Container Image (`publish-image.yml`, dengan SBOM):** https://github.com/brii26/release-signer/actions/runs/43603853444
- **Release Pipeline (`release-pipeline.yml`, baseline C01–C05):** https://github.com/brii26/release-signer/actions/runs/43601016383
- **CI Integration Tests C01–C05 (`ci-integration.yml`):** https://github.com/brii26/release-signer/actions/runs/43601016404

## Ringkasan Skenario C01 sampai C05 (Tabel 2.15)
Seluruh skenario dijalankan pada container terisolasi (`--network none --user "$(id -u):$(id -g)" </dev/null`) tanpa TTY dan tanpa membangun ulang binary dari source.

| ID | Profil | Skenario | Expected | Actual | Marker Deploy | Bukti |
|:---|:---|:---|:---|:---|:---|:---|
| C01 | `rsa-pss-sha256` | Sign & verify artefak sah | exit `0`, `OK` | exit `0`, `OK` | Ada (`deployed.marker`, `deployed-rsa-pss-sha256.marker`) | [`C01/rsa-pss-sha256/`](./C01/rsa-pss-sha256/) |
| C01 | `ecdsa-p256-sha256` | Sign & verify artefak sah | exit `0`, `OK` | exit `0`, `OK` | Ada (`deployed.marker`, `deployed-ecdsa-p256-sha256.marker`) | [`C01/ecdsa-p256-sha256/`](./C01/ecdsa-p256-sha256/) |
| C01 | `ed25519` | Sign & verify artefak sah | exit `0`, `OK` | exit `0`, `OK` | Ada (`deployed.marker`, `deployed-ed25519.marker`) | [`C01/ed25519/`](./C01/ed25519/) |
| C02 | `ed25519` | Artefak diubah 1 byte (offset 10) setelah sign | exit `1`, `ARTIFACT_MISMATCH` | exit `1`, `ARTIFACT_MISMATCH` | Tidak ada | [`C02/`](./C02/) |
| C03 | `ed25519` | Verify dengan trust store kosong & trust store khusus `other-app` | exit `1`, `KEY_NOT_TRUSTED` | exit `1` (keduanya), `KEY_NOT_TRUSTED` | Tidak ada | [`C03/`](./C03/) |
| C04 | `ed25519` | Verify dengan `--file /input/tidak-ada.tar.gz` | exit `2`, `INPUT_ERROR` | exit `2`, `INPUT_ERROR` | Tidak ada | [`C04/`](./C04/) |
| C05 | `ed25519` | `keygen`, `trust add`, `sign`, `verify` (`--user`, `--network none`, no TTY) | exit `0`, `stat -c %u out/* == $(id -u)` | exit `0`, seluruh file ber-UID `1000` | N/A | [`C05/`](./C05/) |
