# release-signer API

`release-signer` menandatangani dan memverifikasi software release dengan RSA-PSS, ECDSA P-256, dan Ed25519. Dokumentasi ini mencakup dua "API" yang bisa dipakai:

- **Modul Go** di `pkg/...`, dipakai oleh CLI dan bisa diimpor langsung oleh program Go lain.
- **CLI**, yang dipakai pipeline CI/CD lewat image container. Stdout, stderr, dan exit code adalah kontraknya.

## Alur singkat

```text
artefak --hash--> manifest (canonical JSON) --sign--> bundle (manifest + signature, Base64)
bundle + artefak + trust store + (package, version yang diharapkan) --verify--> status + exit code
```

Tanda tangan hanya membuktikan keaslian dan integritas. Ini bukan jaminan software bebas malware atau kerentanan.

## Peta modul

| Package | Tugas | Fungsi utama |
|---|---|---|
| [`pkg/profile`](api/pkg/profile.md) | Nama profil algoritma dan panjang signature | `Parse`, `SignatureLen` |
| [`pkg/keys`](api/pkg/keys.md) | Keygen, PEM PKCS#8 dan SPKI, keyid | `Generate`, `ParsePrivatePEM`, `KeyID` |
| [`pkg/sigalg`](api/pkg/sigalg.md) | Sign dan verify per profil | `Sign`, `Verify` |
| [`pkg/strictjson`](api/pkg/strictjson.md) | Parser JSON yang menolak duplicate key | `Parse`, `ExpectKeys` |
| [`pkg/b64`](api/pkg/b64.md) | Base64 RFC 4648 yang ketat | `Encode`, `DecodeStrict` |
| [`pkg/manifest`](api/pkg/manifest.md) | Release manifest canonical | `New`, `Canonical`, `ParseStrict` |
| [`pkg/bundle`](api/pkg/bundle.md) | Bundle JSON (manifest + signature) | `Build`, `ParseStrict`, `WriteFile` |
| [`pkg/truststore`](api/pkg/truststore.md) | Trust store per paket, simpan atomik | `Load`, `Add`, `Remove`, `Save` |
| [`pkg/release`](api/pkg/release.md) | Alur sign, verify, dan SBOM | `Sign`, `Verify`, `SBOMCheck` |
| [`pkg/sbom`](api/pkg/sbom.md) | SBOM CycloneDX yang terikat ke SHA-256 artefak | `Generate`, `ParseBinding` |

Referensi tiap package dibuat otomatis dari doc comment dengan [gomarkdoc](https://github.com/princjef/gomarkdoc). Cara pakai lengkap ada di [Contoh penggunaan](examples.md), format data di [Format data](formats.md), dan status serta exit code di [Status dan exit code](status.md).

## Konvensi

- Semua string yang ditandatangani atau dibandingkan adalah ASCII. Hash dan keyid ditulis heksadesimal huruf kecil.
- Manifest yang ditandatangani adalah byte persis hasil `Canonical()`. Verifikasi memakai byte manifest yang ada di bundle, bukan hasil serialisasi ulang.
- Setiap fungsi parse bersifat strict: field duplikat, field tambahan, `null`, dan tipe yang salah ditolak.
- Fungsi `Verify` berhenti di kegagalan pertama dan tidak pernah mencoba kunci, profil, atau trust store lain.
