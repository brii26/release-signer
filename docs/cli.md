# Referensi CLI

Semua perintah non-interaktif: tidak ada prompt, tidak butuh TTY, dan tidak membaca stdin. Kesalahan ditulis ke stderr. Untuk `--help` dan `--version` tersedia di semua level.

| Perintah | Parameter | Keluaran |
|---|---|---|
| `keygen` | `--algorithm <profil>` `--out <prefix>` `[--force]` | `<prefix>.key.pem`, `<prefix>.pub.pem`. Keyid dicetak ke stdout. |
| `sign` | `--file <path>` `--package <nama>` `--version <versi>` `--key <private.pem>` `--out <bundle.json>` `[--force]` | Bundle di `--out`. Profil ditentukan dari kunci privat. |
| `verify` | `--file <path>` `--bundle <bundle.json>` `--trust-store <trust.json>` `--package <nama>` `--version <versi>` `[--json]` | Hasil verifikasi. Dengan `--json`, satu objek JSON di stdout. |
| `trust add` | `--key <public.pem>` `--package <nama>` `--store <trust.json>` | Mencetak keyid, algoritma, dan paket yang diizinkan. Store dibuat kalau belum ada. Idempoten. |
| `trust list` | `--store <trust.json>` | Daftar keyid, profil, dan paket. |
| `trust remove` | `--keyid <fingerprint>` `--store <trust.json>` | Entri dihapus. Keyid tidak ditemukan: exit 2. |
| `sbom generate` | `--file` `--package` `--version` `--out` `[--force]` | SBOM CycloneDX. Lihat [Signed SBOM](sbom.md). |
| `sbom sign` | `--sbom` `--package` `--version` `--key` `--out` `[--force]` | Bundle SBOM. |
| `sbom verify` | `--sbom` `--bundle` `--trust-store` `--package` `--version` `[--json]` | Hasil verifikasi SBOM. |
| `sbom check` | `--file` `--bundle` `--sbom` `--sbom-bundle` `--trust-store` `--package` `--version` `[--json]` | Hasil gabungan rilis, SBOM, dan binding. |

## Tipe parameter

| Parameter | Tipe | Ketentuan |
|---|---|---|
| `--algorithm` | string | `rsa-pss-sha256`, `ecdsa-p256-sha256`, atau `ed25519`. |
| `--package` | string | `[a-z0-9][a-z0-9._-]{0,63}`. |
| `--version` | string | `[A-Za-z0-9][A-Za-z0-9._+-]{0,63}`. |
| `--file`, `--bundle`, `--key`, `--out`, `--store`, `--trust-store`, `--sbom`, `--sbom-bundle` | path | Berkas lokal. |
| `--keyid` | string | 64 karakter heksadesimal huruf kecil. |
| `--force` | boolean | Satu-satunya cara menimpa private key, bundle, atau SBOM yang sudah ada. |
| `--json` | boolean | Hasil sebagai satu objek JSON. |

## Aturan keluaran

- `verify --json` menulis tepat satu objek JSON diikuti satu newline ke stdout. Untuk `INPUT_ERROR` (opsi kurang, berkas tidak ada) objek JSON tetap ditulis.
- Pesan kesalahan dan informasi tambahan hanya ke stderr.
- Private key tidak pernah dicetak atau dicatat.
- Output yang sudah ada tanpa `--force` menghasilkan kesalahan jelas dan exit 2, tanpa menimpa berkas lama.
- Exit code mengikuti [Status dan exit code](status.md).

## Pemakaian via container

```sh
docker run --rm --network none --user "$(id -u):$(id -g)" \
  -v "$PWD/dist:/input:ro" -v "$PWD/out:/output" -v "$KEY_FILE:/run/signing.key.pem:ro" \
  "$IMAGE" sign --file /input/demo-app.tar.gz --package demo-app --version 1.0.0 \
  --key /run/signing.key.pem --out /output/release.json
```

`$IMAGE` selalu dikunci dengan digest (`ghcr.io/brii26/release-signer@sha256:...`). Exit code container sama dengan exit code program.
