# Status and exit codes

## Order of `verify` checks

Stops at the first failure.

| No | Status on failure | Check |
|---|---|---|
| 1 | `INPUT_ERROR` | Required options are present, `--package` is valid, and every input file is readable. |
| 2 | `FORMAT_ERROR` | Structure, types, size, and serialization of the bundle, manifest, and trust store. Base64 is valid. Trust store keys are valid and their fingerprints match. |
| 3 | `UNSUPPORTED_ALGORITHM` | `algorithm` in the manifest is one of the three profiles. |
| 4 | `KEY_NOT_TRUSTED` | The trust store contains the `keyid`, the key profile equals the manifest profile, and the key is allowed for the expected package. |
| 5 | `INVALID_SIGNATURE` | The signature over the manifest bytes is valid. A wrong signature length or encoding also lands here. |
| 6 | `METADATA_MISMATCH` | Package and version in the manifest equal the inputs exactly. `artifact.name` equals the file basename. |
| 7 | `ARTIFACT_MISMATCH` | File size and SHA-256 equal the manifest. |
| 8 | `OK` | All checks pass. |

`sbom check` adds one status: `SBOM_MISMATCH` (both bundles are valid, but the SBOM is not bound to the release).

## Exit codes

| Code | Meaning |
|---|---|
| 0 | Success. For `verify`: status `OK` and `valid` is `true`. |
| 1 | Verification rejected (every status except `OK` and `INPUT_ERROR`). |
| 2 | Usage, I/O, or environment error. For `verify --json` the status is `INPUT_ERROR`. Every command other than `verify` that fails also uses this code. |

A pipeline should decide whether to accept an artifact from the exit code, then use `valid` and `status` in the JSON as confirmation. Do not ignore a non-zero exit code with `|| true` or `continue-on-error`.
