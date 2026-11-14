# SBOM test results (S01 to S09)

| ID | Profile | Input | Expected | Exit | Actual | Exit | Result |
|---|---|---|---|---|---|---|---|
| S01 | ecdsa-p256-sha256 | valid SBOM and valid artifact | OK | 0 | OK | 0 | PASS |
| S01 | ed25519 | valid SBOM and valid artifact | OK | 0 | OK | 0 | PASS |
| S01 | rsa-pss-sha256 | valid SBOM and valid artifact | OK | 0 | OK | 0 | PASS |
| S02 | ed25519 | SBOM gets 1 extra byte after sign | ARTIFACT_MISMATCH | 1 | ARTIFACT_MISMATCH | 1 | PASS |
| S03 | ed25519 | artifact replaced and re-signed, old SBOM | SBOM_MISMATCH | 1 | SBOM_MISMATCH | 1 | PASS |
| S04 | ed25519 | SBOM signed by a key outside the trust store | KEY_NOT_TRUSTED | 1 | KEY_NOT_TRUSTED | 1 | PASS |
| S05 | ed25519 | sbom sign without SHA-256 hash | (exit 2, no bundle) | 2 |  | 2 | PASS |
| S06 | ed25519 | release artifact changed after sign | ARTIFACT_MISMATCH | 1 | ARTIFACT_MISMATCH | 1 | PASS |
| S07 | ed25519 | SBOM contains version 2.0.0, verified as 1.0.0 | SBOM_MISMATCH | 1 | SBOM_MISMATCH | 1 | PASS |
| S08 | - | sbom check without required flags | INPUT_ERROR | 2 | INPUT_ERROR | 2 | PASS |
| S09 | ecdsa-p256-sha256 | standalone sbom verify | OK | 0 | OK | 0 | PASS |
