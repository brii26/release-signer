<div align="center">
   <img width="100%" src="https://capsule-render.vercel.app/api?type=waving&height=260&color=0:1F6FEB,100:0B2A5B&text=release-signer&fontColor=FFFFFF&fontSize=62&desc=IF4020%20Kriptografi%20Tugas%203&descAlignY=76&descSize=17&descColor=C9D8F5" />
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

## Nama dan Deskripsi

`release-signer` adalah CLI untuk menandatangani dan memverifikasi software release. Artefak dideskripsikan oleh release manifest dalam canonical JSON, manifest dan signature dibungkus dalam satu bundle Base64, dan verifikasi memakai trust store lokal milik penerima. Tiga profil algoritma didukung: `rsa-pss-sha256`, `ecdsa-p256-sha256`, dan `ed25519`.

Tanda tangan hanya membuktikan keaslian dan integritas artefak. Ini bukan jaminan software bebas malware atau kerentanan.

Fitur utama:

- **Sign dan verify**
  Manifest memuat paket, versi, algoritma, keyid, serta nama, ukuran, dan SHA-256 artefak. Verify berhenti di kegagalan pertama dengan status dan exit code yang tetap.
- **Trust store**
  Kunci publik dipercaya per paket lewat `trust add`. Bundle tidak membawa public key dan `verify` tidak pernah menulis trust store.
- **Container dan pipeline**
  Image berbasis distroless dijalankan di runner CI/CD dengan referensi digest `sha256`, tanpa network dan tanpa TTY.
- **Signed SBOM (bonus)**
  SBOM CycloneDX ditandatangani sebagai artefak terpisah dan diikat ke SHA-256 artefak rilis.
- **API documentation (bonus)**
  Referensi modul Go dan CLI di-host di GitHub Pages: https://brii26.github.io/release-signer/

---

## Tech Stack

| Layer | Technology |
|:---|:---|
| Bahasa | Go 1.27 |
| Kriptografi | `crypto/rsa`, `crypto/ecdsa`, `crypto/ed25519`, `crypto/sha256` (standard library) |
| Encoding | `encoding/base64`, parser JSON strict buatan sendiri (`pkg/strictjson`) |
| Container | Docker, base image `distroless/static-debian12:nonroot` |
| Registry | GitHub Container Registry (GHCR) |
| CI/CD | GitHub Actions |
| SBOM | CycloneDX 1.6 (JSON) |
| API docs | gomarkdoc v1.1.0, MkDocs Material 9.5.50, GitHub Pages |
| Test interop | OpenSSL 3, Python 3 dengan `cryptography==50.0.2`, uv |

## Dependensi

| Komponen | Versi | Dipakai untuk | Dokumentasi |
|:---|:---|:---|:---|
| Go standard library | 1.27 | Seluruh program. `go.mod` tidak punya dependensi pihak ketiga. | https://pkg.go.dev/std |
| golang (base image build) | `alpine` dipin digest | Build stage `Dockerfile` | https://hub.docker.com/_/golang |
| distroless static | `debian12:nonroot` dipin digest | Runtime image | https://github.com/GoogleContainerTools/distroless |
| gomarkdoc | v1.1.0 | Referensi API (hanya dokumentasi) | https://github.com/princjef/gomarkdoc |
| MkDocs Material | 9.5.50 | Situs dokumentasi (hanya dokumentasi) | https://squidfunnel.github.io/mkdocs-material/ |
| OpenSSL | 3.x | Pengujian interoperabilitas saja | https://docs.openssl.org/3.0/ |
| Python `cryptography` | 50.0.2 | Pengujian interoperabilitas saja | https://cryptography.io/en/latest/ |

Program yang dijalankan tidak memerlukan dependensi runtime apa pun selain binary itu sendiri.

---

## Pemetaan Profil ke API Pustaka

| Profil | Hash | Signature | API Go | Bentuk signature |
|:---|:---|:---|:---|:---|
| `rsa-pss-sha256` | SHA-256 atas byte manifest | RSASSA-PSS, MGF1-SHA-256, salt 32 byte | `rsa.SignPSS`, `rsa.VerifyPSS` dengan `rsa.PSSOptions{SaltLength: 32}` | 384 byte (RSA 3072 bit, e = 65537) |
| `ecdsa-p256-sha256` | SHA-256 atas byte manifest | ECDSA P-256 | `ecdsa.Sign`, `ecdsa.Verify` | 64 byte, `r \|\| s` masing-masing 32 byte big-endian |
| `ed25519` | tanpa prehash | Ed25519 murni (RFC 8032), bukan Ed25519ph | `ed25519.Sign`, `ed25519.Verify` | 64 byte |

Format kunci: private key PKCS#8 PEM (`PRIVATE KEY`, mode `0600`), public key SubjectPublicKeyInfo PEM (`PUBLIC KEY`). keyid adalah `hex_lower(SHA256(DER SPKI))`.

## Format Berkas

Ringkasan, detail lengkap ada di [`docs/formats.md`](docs/formats.md).

| Berkas | Schema | Batas | Isi |
|:---|:---|:---|:---|
| Release manifest | `minisign-manifest/v1` | 16 KiB | `package`, `version`, `algorithm`, `keyid`, `artifact{name,size,sha256}`. Canonical: tanpa spasi, urutan field tetap. |
| Bundle | `minisign-bundle/v1` | 64 KiB | `manifest_b64`, `signature_b64` (Base64 RFC 4648 ketat). |
| Trust store | `minisign-trust/v1` | | `keys[]` berisi `keyid`, `algorithm`, `public_key_pem`, `packages`. |
| SBOM | CycloneDX 1.6 | 1 MiB | Hash SHA-256 artefak di `metadata.component.hashes`. Lihat [`docs/sbom.md`](docs/sbom.md). |

Parser menolak field duplikat, field tambahan, `null`, dan tipe yang salah.

---

## Subcommand

Semua perintah non-interaktif. Referensi parameter: [`docs/cli.md`](docs/cli.md). Status dan exit code: [`docs/status.md`](docs/status.md).

```sh
# 1. membuat pasangan kunci
release-signer keygen --algorithm ed25519 --out keys/publisher

# 2. mempercayai public key untuk satu paket
release-signer trust add --key keys/publisher.pub.pem --package demo-app --store trust.json
release-signer trust list --store trust.json
release-signer trust remove --keyid <64 hex> --store trust.json

# 3. menandatangani
release-signer sign --file demo-app.tar.gz --package demo-app --version 1.0.0 \
  --key keys/publisher.key.pem --out release.json

# 4. memverifikasi
release-signer verify --file demo-app.tar.gz --bundle release.json \
  --trust-store trust.json --package demo-app --version 1.0.0 --json
```

Keluaran `verify --json`:

```json
{"valid":true,"status":"OK","message":"...","algorithm":"ed25519","keyid":"<64 hex>","package":"demo-app","version":"1.0.0"}
```

| Exit code | Arti |
|:---:|:---|
| 0 | `OK` |
| 1 | Verifikasi ditolak (`FORMAT_ERROR`, `UNSUPPORTED_ALGORITHM`, `KEY_NOT_TRUSTED`, `INVALID_SIGNATURE`, `METADATA_MISMATCH`, `ARTIFACT_MISMATCH`, `SBOM_MISMATCH`) |
| 2 | Kesalahan pemakaian, I/O, atau lingkungan (`INPUT_ERROR`) |

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

## Menjalankan di Runner CI/CD

### Mengambil image

Image dikunci dengan digest, bukan tag `latest`. Nilai terkini ada di [`ci/image.env`](ci/image.env).

```sh
. ./ci/image.env
docker pull "$IMAGE"
```

| Versi program | Tag repositori | Image | Digest |
|:---|:---|:---|:---|
| 1.0.0 | `v1.0.0` (dibuat saat rilis) | `ghcr.io/brii26/release-signer` | `sha256:0853d9e4bbca739361262b45623d6be1e6cc977bb4001b49f27f2f611e8d2c07` (pin saat ini, diperbarui pada verifikasi akhir) |

Image dibangun dari `Dockerfile` pada commit yang diberi tag, oleh workflow [`publish-image.yml`](.github/workflows/publish-image.yml) setiap tag `v*` di-push.

### Memakai di workflow

Workflow pemakai ada di [`.github/workflows/release-pipeline.yml`](.github/workflows/release-pipeline.yml) dengan job `prepare`, `sign`, `verify`, dan `deploy`. Deploy hanya jalan kalau verify lolos.

```sh
docker run --rm --network none --user "$(id -u):$(id -g)" \
  -v "$PWD/dist:/input:ro" -v "$PWD/out:/output" -v "$KEY_FILE:/key.pem:ro" \
  "$IMAGE" sign --file /input/demo-app.tar.gz --package demo-app --version 1.0.0 \
  --key /key.pem --out /output/release.json </dev/null
```

Aturan yang dipakai pipeline:

- Private key hanya lewat GitHub Secret (`SIGNING_KEY_*`), ditulis ke file sementara di `RUNNER_TEMP` dan dihapus lewat `trap`.
- Job `verify` dan `deploy` tidak punya akses ke secret penandatanganan.
- Trust store diambil dari repositori ([`ci/trust.json`](ci/trust.json)), bukan dari bundle.
- `keygen` dan `trust add` tidak dijalankan otomatis di pipeline rilis.
- Hasil verify dinilai dari exit code, tidak ada `|| true` atau `continue-on-error`.

### Bukti uji integrasi

Skenario C01 sampai C05 dijalankan oleh [`ci-integration.yml`](.github/workflows/ci-integration.yml). Konfigurasi, log tersanitasi, keluaran JSON, bukti marker deploy, dan tautan workflow run ada di [`results/ci/README.md`](results/ci/README.md).

---

## Menjalankan di Luar Runner CI/CD

Prasyarat: Go 1.27.

```sh
git clone https://github.com/brii26/release-signer.git
cd release-signer
make build                      # menghasilkan bin/release-signer
./bin/release-signer --version
```

Atau lewat container:

```sh
make docker VERSION=1.0.0
docker run --rm release-signer:1.0.0 --help
```

Contoh alur lokal lengkap ada di bagian [Subcommand](#subcommand).

---

## Mengulang Pengujian

| Perintah | Isi | Hasil |
|:---|:---|:---|
| `make test` | Unit test seluruh package (`go test -race ./...`) | stdout |
| `make vet` dan `make fmt-check` | Pemeriksaan statis dan format | stdout |
| `make scenarios` | Skenario U01 sampai U14 dan kasus negatif untuk tiga profil | [`results/scenarios/`](results/scenarios/results.md) |
| `make sbom-test` | Skenario S01 sampai S09 untuk signed SBOM | [`results/sbom/`](results/sbom/results.md) |
| `make interop` | Interoperabilitas dengan OpenSSL dan Python (perlu OpenSSL, uv) | [`results/interop/`](results/interop/results.md) |
| `make bench` | Benchmark keygen, hash, sign, verify, dan e2e | [`results/bench/`](results/bench/summary.md) |
| `make docs` | Referensi API dan situs MkDocs (perlu `mkdocs`) | `site/` |

Skenario C01 sampai C05 dijalankan lewat GitHub Actions (`ci-integration`), bukan di mesin lokal.

Pasangan kunci khusus pengujian ada di [`test/keys/`](test/keys/README.md) dan [`ci/keys/`](ci/keys/). Kunci ini hanya untuk uji dan tidak boleh dipakai untuk layanan nyata. Fixture teks, biner, dan berkas kosong ada di [`test/fixtures/`](test/fixtures/).

---

## Struktur Proyek

```
release-signer/
├── cmd/release-signer/   entry point
├── internal/cli/         parsing argumen dan subcommand
├── pkg/
│   ├── profile/          nama profil dan panjang signature
│   ├── keys/             keygen, PEM, keyid
│   ├── sigalg/           sign dan verify per profil
│   ├── strictjson/       parser JSON strict
│   ├── b64/              Base64 ketat
│   ├── manifest/         release manifest canonical
│   ├── bundle/           bundle JSON
│   ├── truststore/       trust store
│   ├── release/          alur sign, verify, SBOM check
│   └── sbom/             SBOM CycloneDX
├── test/                 e2e, interop, sbom, fixtures, keys
├── bench/                benchmark
├── results/              hasil uji (scenarios, interop, bench, ci, sbom)
├── ci/                   image.env, release.env, trust.json, kunci publik uji
├── docs/                 dokumentasi API dan keamanan (sumber MkDocs)
├── doc/                  laporan PDF
├── .github/workflows/    test, publish-image, release-pipeline, ci-integration, docs
└── Dockerfile
```

## Dokumentasi

- API docs: https://brii26.github.io/release-signer/
- Analisis keamanan dan threat model: [`docs/security.md`](docs/security.md)
- Laporan PDF: lihat folder [`doc/`](doc/)

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
