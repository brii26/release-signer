# Format data

Semua berkas JSON memakai UTF-8 tanpa BOM. Parser menolak field tambahan, field duplikat, `null`, dan tipe yang tidak sesuai.

## Release manifest (`minisign-manifest/v1`)

Ukuran maksimum 16 KiB. Serialisasi canonical: tanpa spasi dan newline, urutan field tetap seperti tabel, tanpa escape `\uXXXX`.

| Field | Tipe | Ketentuan |
|---|---|---|
| `schema` | string | Tetap `minisign-manifest/v1`. |
| `package` | string | `[a-z0-9][a-z0-9._-]{0,63}`. |
| `version` | string | `[A-Za-z0-9][A-Za-z0-9._+-]{0,63}`. |
| `algorithm` | string | `rsa-pss-sha256`, `ecdsa-p256-sha256`, atau `ed25519`. |
| `keyid` | string | 64 karakter heksadesimal huruf kecil. |
| `artifact` | object | Tepat tiga field di bawah. |
| `artifact.name` | string | Basename berkas, `[A-Za-z0-9][A-Za-z0-9._-]{0,127}`. |
| `artifact.size` | integer | 0 sampai 9007199254740991. Boolean ditolak. |
| `artifact.sha256` | string | 64 karakter heksadesimal huruf kecil. |

## Bundle (`minisign-bundle/v1`)

Ukuran maksimum 64 KiB. Urutan field dan white space bebas.

| Field | Tipe | Ketentuan |
|---|---|---|
| `schema` | string | Tetap `minisign-bundle/v1`. |
| `manifest_b64` | string | Byte manifest, Base64 RFC 4648 dengan padding, tanpa white space. |
| `signature_b64` | string | Byte signature, Base64 yang sama. Panjang: 384 (RSA-PSS), 64 (ECDSA `r \|\| s`, Ed25519). |

## Trust store (`minisign-trust/v1`)

| Field | Tipe | Ketentuan |
|---|---|---|
| `schema` | string | Tetap `minisign-trust/v1`. |
| `keys` | array | Boleh kosong. Setiap `keyid` unik. Store kosong tidak mempercayai kunci apa pun. |
| `keys[].keyid` | string | `hex_lower(SHA256(DER_SPKI))`, harus cocok dengan `public_key_pem`. |
| `keys[].algorithm` | string | Profil yang sesuai dengan tipe dan parameter kunci. |
| `keys[].public_key_pem` | string | Teks PEM SPKI, bukan path. |
| `keys[].packages` | array of string | Tidak boleh kosong, duplikat, atau wildcard. |

## Berkas kunci

| Komponen | Format |
|---|---|
| Private key | PKCS#8 dalam PEM, label `PRIVATE KEY`. Dibuat dengan mode `0600`. |
| Public key | SubjectPublicKeyInfo dalam PEM, label `PUBLIC KEY`. |
| RSA | Modulus tepat 3072 bit, eksponen publik 65537. |
| ECDSA | P-256 (named curve), titik SEC1 uncompressed. |
| Ed25519 | RFC 8410, field parameter tidak ada. |

## Hasil verifikasi (`verify --json`)

Satu objek JSON di stdout, diikuti satu newline.

| Field | Tipe | Ketentuan |
|---|---|---|
| `valid` | boolean | `true` hanya untuk status `OK`. |
| `status` | string | Lihat [Status dan exit code](status.md). |
| `message` | string | Penjelasan singkat. |
| `algorithm` | string/null | Dari manifest, `null` kalau belum terbaca. |
| `keyid` | string/null | Dari manifest, `null` kalau belum terbaca. |
| `package` | string/null | Dari manifest, `null` kalau belum terbaca. |
| `version` | string/null | Dari manifest, `null` kalau belum terbaca. |

Kalau `valid` bernilai `false`, field metadata hanya untuk menjelaskan hasil dan tidak boleh dianggap sebagai data yang sah.

## SBOM dan hasil `sbom check`

Format SBOM (CycloneDX 1.6) dan keluaran `sbom check --json` dijelaskan di [Signed SBOM](sbom.md).
