# Status dan exit code

## Urutan pemeriksaan `verify`

Berhenti di kegagalan pertama.

| No | Status jika gagal | Pemeriksaan |
|---|---|---|
| 1 | `INPUT_ERROR` | Opsi wajib ada, `--package` valid, semua berkas masukan bisa dibaca. |
| 2 | `FORMAT_ERROR` | Struktur, tipe, ukuran, dan serialisasi bundle, manifest, dan trust store. Base64 valid. Kunci di trust store valid dan fingerprint-nya cocok. |
| 3 | `UNSUPPORTED_ALGORITHM` | `algorithm` di manifest adalah salah satu dari tiga profil. |
| 4 | `KEY_NOT_TRUSTED` | Trust store memuat `keyid`, profil kunci sama dengan manifest, dan kunci diizinkan untuk paket yang diharapkan. |
| 5 | `INVALID_SIGNATURE` | Signature atas byte manifest sah. Panjang atau encoding signature yang salah juga di sini. |
| 6 | `METADATA_MISMATCH` | Paket dan versi di manifest sama persis dengan masukan. `artifact.name` sama dengan basename berkas. |
| 7 | `ARTIFACT_MISMATCH` | Ukuran dan SHA-256 berkas sama dengan manifest. |
| 8 | `OK` | Semua pemeriksaan lolos. |

`sbom check` menambah satu status: `SBOM_MISMATCH` (kedua bundle sah, tapi SBOM tidak terikat ke rilis).

## Exit code

| Kode | Arti |
|---|---|
| 0 | Berhasil. Untuk `verify`: status `OK` dan `valid` bernilai `true`. |
| 1 | Verifikasi ditolak (semua status selain `OK` dan `INPUT_ERROR`). |
| 2 | Kesalahan pemakaian, I/O, atau lingkungan. Untuk `verify --json` statusnya `INPUT_ERROR`. Semua perintah selain `verify` yang gagal juga memakai kode ini. |

Pipeline sebaiknya menilai penerimaan artefak dari exit code, lalu `valid` dan `status` di JSON sebagai konfirmasi. Jangan mengabaikan exit code non-zero dengan `|| true` atau `continue-on-error`.
