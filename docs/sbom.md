# Signed SBOM

The SBOM (Software Bill of Materials) is signed as a separate artifact using the same bundle as the release (`minisign-bundle/v1`), then bound to the SHA-256 of the release artifact. The manifest, bundle, and trust store are unchanged, and the mandatory features behave the same.

## SBOM format

CycloneDX 1.6 (JSON). `sbom generate` produces the following document (example values):

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
      "hashes": [{ "alg": "SHA-256", "content": "<release artifact sha256>" }],
      "properties": [{ "name": "release-signer:artifact-name", "value": "demo-app.tar.gz" }]
    }
  },
  "components": []
}
```

Fields read as the binding:

| Field | Type | Rule |
|---|---|---|
| `bomFormat` | string | Must be `CycloneDX`. |
| `metadata.component.name` | string | Package name. |
| `metadata.component.version` | string | Release version. |
| `metadata.component.hashes[]` | array of object | Exactly one entry with `alg` = `SHA-256`. `content` is 64 lowercase hexadecimal characters. |
| `metadata.component.properties[]` | array of object | Exactly one entry named `release-signer:artifact-name`. `value` is the basename of the release artifact. |

Other fields are allowed, so an SBOM from an external tool (for example Syft) can be used as long as it contains the binding above. The parser still rejects duplicate fields, a BOM, invalid UTF-8, data after the JSON, and anything larger than 1 MiB. `sbom generate` leaves the `components` list empty, because a package manager and dependency resolution are not required.

## Subcommands

| Command | Parameters | Output |
|---|---|---|
| `sbom generate` | `--file <artifact>` `--package <name>` `--version <version>` `--out <sbom.cdx.json>` `[--force]` | SBOM file. Exit 2 if input or I/O fails. |
| `sbom sign` | `--sbom <sbom.cdx.json>` `--package <name>` `--version <version>` `--key <private.pem>` `--out <sbom.bundle.json>` `[--force]` | SBOM bundle. An SBOM without a valid binding is rejected with exit 2 and no bundle is written. |
| `sbom verify` | `--sbom` `--bundle <sbom.bundle.json>` `--trust-store` `--package` `--version` `[--json]` | Verify result (Table 2.9), same order and statuses as `verify` (Table 2.8). |
| `sbom check` | `--file <artifact>` `--bundle <release.json>` `--sbom` `--sbom-bundle` `--trust-store` `--package` `--version` `[--json]` | Combined result below. |

`sbom sign` uses the same flow and keys as `sign`. The SBOM file name becomes `artifact.name` in the manifest of the SBOM bundle, so it must match the `artifact.name` pattern.

## Order of `sbom check`

Stops at the first failure:

1. Verify the release bundle (Table 2.8). On failure: the status from verify, with the `message` prefixed by `release:`.
2. Verify the SBOM bundle with the same trust store, package, and version. On failure: the status from verify, with the `message` prefixed by `sbom:`.
3. Read the SBOM binding. If invalid: `FORMAT_ERROR`.
4. Compare the binding with the release manifest and the user inputs: SHA-256, artifact name, package, and version. On mismatch: `SBOM_MISMATCH`.
5. Everything matches: `OK`.

## Output of `sbom check --json`

A single JSON object on stdout followed by one newline.

| Field | Type | Rule |
|---|---|---|
| `valid` | boolean | `true` only for status `OK`. |
| `status` | string | A status from Table 2.8, or `SBOM_MISMATCH`. |
| `message` | string | Short explanation. |
| `release` | object/null | Release verify result (Table 2.9). `null` if it has not run. |
| `sbom` | object/null | SBOM verify result (Table 2.9). `null` if it has not run. |

Exit code: `0` for `OK`, `2` for `INPUT_ERROR`, `1` for any other status including `SBOM_MISMATCH`.

## Example

```sh
release-signer sbom generate --file demo-app.tar.gz --package demo-app --version 1.0.0 --out sbom.cdx.json
release-signer sbom sign --sbom sbom.cdx.json --package demo-app --version 1.0.0 \
  --key keys/publisher.key.pem --out sbom.bundle.json
release-signer sbom check --file demo-app.tar.gz --bundle release.json \
  --sbom sbom.cdx.json --sbom-bundle sbom.bundle.json \
  --trust-store trust.json --package demo-app --version 1.0.0 --json
```

## Testing

`make sbom-test` runs `test/sbom` and writes `results/sbom/results.md`.

| ID | Scenario | Expected result |
|---|---|---|
| S01 | Valid SBOM and valid artifact (3 profiles) | `OK`, exit 0 |
| S02 | SBOM content changed after signing | `ARTIFACT_MISMATCH`, exit 1 |
| S03 | Release artifact replaced and legitimately re-signed, old SBOM | `SBOM_MISMATCH`, exit 1 |
| S04 | SBOM signed by a key that is not in the trust store | `KEY_NOT_TRUSTED`, exit 1 |
| S05 | `sbom sign` for an SBOM without a SHA-256 hash | exit 2, no bundle written |
| S06 | Release artifact changed after signing | `ARTIFACT_MISMATCH`, exit 1 (stops at release verify) |
| S07 | Valid SBOM that contains another version | `SBOM_MISMATCH`, exit 1 |
| S08 | `sbom check` without required flags | `INPUT_ERROR`, exit 2 |
| S09 | Standalone `sbom verify` | `OK`, exit 0 |
