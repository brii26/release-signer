# Signed SBOM

SBOM (Software Bill of Materials) ditandatangani sebagai artefak terpisah memakai bundle yang sama dengan rilis (`minisign-bundle/v1`), lalu diikat ke SHA-256 artefak rilis. Manifest, bundle, dan trust store tidak berubah, dan perilaku fitur wajib tetap sama.

## Format SBOM

CycloneDX 1.6 (JSON). `sbom generate` menghasilkan dokumen berikut (nilai contoh):

```json
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "version": 1,
  "metadata": {
    "component": {
      "type": "application",
      "name": "demo-app",
      "version": "1.0.0",
      "hashes": [{ "alg": "SHA-256", "content": "<sha256 artefak rilis>" }],
      "properties": [{ "name": "release-signer:artifact-name", "value": "demo-app.tar.gz" }]
    }
  },
  "components": []
}
```

Field yang dibaca sebagai binding:

| Field | Tipe | Ketentuan |
|---|---|---|
| `bomFormat` | string | Harus `CycloneDX`. |
| `metadata.component.name` | string | Nama paket. |
| `metadata.component.version` | string | Versi rilis. |
| `metadata.component.hashes[]` | array of object | Tepat satu entri dengan `alg` = `SHA-256`. `content` 64 karakter heksadesimal huruf kecil. |
| `metadata.component.properties[]` | array of object | Tepat satu entri bernama `release-signer:artifact-name`. `value` adalah basename artefak rilis. |

Field lain di luar tabel boleh ada, jadi SBOM dari kakas eksternal (misalnya Syft) bisa dipakai selama memuat binding di atas. Parser tetap menolak field duplikat, BOM, UTF-8 tidak valid, data setelah JSON, dan ukuran lebih dari 1 MiB. Daftar `components` dibiarkan kosong oleh `sbom generate`, karena package manager dan dependency resolution tidak diwajibkan.

## Subcommand

| Perintah | Parameter | Keluaran |
|---|---|---|
| `sbom generate` | `--file <artefak>` `--package <nama>` `--version <versi>` `--out <sbom.cdx.json>` `[--force]` | File SBOM. Exit 2 kalau input atau I/O gagal. |
| `sbom sign` | `--sbom <sbom.cdx.json>` `--package <nama>` `--version <versi>` `--key <private.pem>` `--out <sbom.bundle.json>` `[--force]` | Bundle SBOM. SBOM tanpa binding valid ditolak dengan exit 2 dan bundle tidak ditulis. |
| `sbom verify` | `--sbom` `--bundle <sbom.bundle.json>` `--trust-store` `--package` `--version` `[--json]` | Hasil verify (Tabel 2.9), urutan dan status sama dengan `verify` (Tabel 2.8). |
| `sbom check` | `--file <artefak>` `--bundle <release.json>` `--sbom` `--sbom-bundle` `--trust-store` `--package` `--version` `[--json]` | Hasil gabungan di bawah. |

`sbom sign` memakai alur dan kunci yang sama dengan `sign`. Nama file SBOM menjadi `artifact.name` di manifest bundle SBOM, jadi harus lolos pola `artifact.name`.

## Urutan `sbom check`

Berhenti di kegagalan pertama:

1. Verifikasi bundle rilis (Tabel 2.8). Gagal: status dari verify, `message` diawali `release:`.
2. Verifikasi bundle SBOM dengan trust store, paket, dan versi yang sama. Gagal: status dari verify, `message` diawali `sbom:`.
3. Baca binding SBOM. Tidak valid: `FORMAT_ERROR`.
4. Cocokkan binding dengan manifest rilis dan masukan pengguna: SHA-256, nama artefak, paket, versi. Tidak cocok: `SBOM_MISMATCH`.
5. Semua cocok: `OK`.

## Keluaran `sbom check --json`

Satu objek JSON di stdout diikuti satu newline.

| Field | Tipe | Ketentuan |
|---|---|---|
| `valid` | boolean | `true` hanya untuk status `OK`. |
| `status` | string | Status Tabel 2.8, atau `SBOM_MISMATCH`. |
| `message` | string | Penjelasan singkat. |
| `release` | object/null | Hasil verify rilis (Tabel 2.9). `null` kalau belum dijalankan. |
| `sbom` | object/null | Hasil verify SBOM (Tabel 2.9). `null` kalau belum dijalankan. |

Exit code: `0` untuk `OK`, `2` untuk `INPUT_ERROR`, `1` untuk status lain termasuk `SBOM_MISMATCH`.

## Contoh

```sh
release-signer sbom generate --file demo-app.tar.gz --package demo-app --version 1.0.0 --out sbom.cdx.json
release-signer sbom sign --sbom sbom.cdx.json --package demo-app --version 1.0.0 \
  --key keys/publisher.key.pem --out sbom.bundle.json
release-signer sbom check --file demo-app.tar.gz --bundle release.json \
  --sbom sbom.cdx.json --sbom-bundle sbom.bundle.json \
  --trust-store trust.json --package demo-app --version 1.0.0 --json
```

## Pengujian

`make sbom-test` menjalankan `test/sbom` dan menulis `results/sbom/results.md`.

| ID | Skenario | Hasil yang diharapkan |
|---|---|---|
| S01 | SBOM sah dan artefak sah (3 profil) | `OK`, exit 0 |
| S02 | Isi SBOM diubah setelah sign | `ARTIFACT_MISMATCH`, exit 1 |
| S03 | Artefak rilis diganti dan ditandatangani ulang secara sah, SBOM lama | `SBOM_MISMATCH`, exit 1 |
| S04 | SBOM ditandatangani kunci yang tidak ada di trust store | `KEY_NOT_TRUSTED`, exit 1 |
| S05 | `sbom sign` untuk SBOM tanpa hash SHA-256 | exit 2, bundle tidak ditulis |
| S06 | Artefak rilis diubah setelah sign | `ARTIFACT_MISMATCH`, exit 1 (berhenti di verify rilis) |
| S07 | SBOM sah tapi berisi versi lain | `SBOM_MISMATCH`, exit 1 |
| S08 | `sbom check` tanpa flag wajib | `INPUT_ERROR`, exit 2 |
| S09 | `sbom verify` berdiri sendiri | `OK`, exit 0 |
