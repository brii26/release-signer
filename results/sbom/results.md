# Hasil uji SBOM (S01 sampai S09)

| ID | Profil | Input | Expected | Exit | Actual | Exit | Hasil |
|---|---|---|---|---|---|---|---|
| S01 | ecdsa-p256-sha256 | SBOM dan artefak sah | OK | 0 | OK | 0 | PASS |
| S01 | ed25519 | SBOM dan artefak sah | OK | 0 | OK | 0 | PASS |
| S01 | rsa-pss-sha256 | SBOM dan artefak sah | OK | 0 | OK | 0 | PASS |
| S02 | ed25519 | SBOM ditambah 1 byte setelah sign | ARTIFACT_MISMATCH | 1 | ARTIFACT_MISMATCH | 1 | PASS |
| S03 | ed25519 | artefak diganti dan ditandatangani ulang, SBOM lama | SBOM_MISMATCH | 1 | SBOM_MISMATCH | 1 | PASS |
| S04 | ed25519 | SBOM ditandatangani kunci di luar trust store | KEY_NOT_TRUSTED | 1 | KEY_NOT_TRUSTED | 1 | PASS |
| S05 | ed25519 | sbom sign tanpa hash SHA-256 | (exit 2, tanpa bundle) | 2 |  | 2 | PASS |
| S06 | ed25519 | artefak rilis diubah setelah sign | ARTIFACT_MISMATCH | 1 | ARTIFACT_MISMATCH | 1 | PASS |
| S07 | ed25519 | SBOM berisi versi 2.0.0, diverifikasi sebagai 1.0.0 | SBOM_MISMATCH | 1 | SBOM_MISMATCH | 1 | PASS |
| S08 | - | sbom check tanpa flag wajib | INPUT_ERROR | 2 | INPUT_ERROR | 2 | PASS |
| S09 | ecdsa-p256-sha256 | sbom verify sah | OK | 0 | OK | 0 | PASS |
