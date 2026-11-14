# CLI reference

All commands are non-interactive: no prompts, no TTY, and no stdin reads. Errors go to stderr. `--help` and `--version` are available at every level.

| Command | Parameters | Output |
|---|---|---|
| `keygen` | `--algorithm <profile>` `--out <prefix>` `[--force]` | `<prefix>.key.pem`, `<prefix>.pub.pem`. The keyid is printed to stdout. |
| `sign` | `--file <path>` `--package <name>` `--version <version>` `--key <private.pem>` `--out <bundle.json>` `[--force]` | Bundle at `--out`. The profile is determined from the private key. |
| `verify` | `--file <path>` `--bundle <bundle.json>` `--trust-store <trust.json>` `--package <name>` `--version <version>` `[--json]` | Verification result. With `--json`, a single JSON object on stdout. |
| `trust add` | `--key <public.pem>` `--package <name>` `--store <trust.json>` | Prints the keyid, algorithm, and allowed package. The store is created if missing. Idempotent. |
| `trust list` | `--store <trust.json>` | List of keyids, profiles, and packages. |
| `trust remove` | `--keyid <fingerprint>` `--store <trust.json>` | Entry removed. Keyid not found: exit 2. |
| `sbom generate` | `--file` `--package` `--version` `--out` `[--force]` | CycloneDX SBOM. See [Signed SBOM](sbom.md). |
| `sbom sign` | `--sbom` `--package` `--version` `--key` `--out` `[--force]` | SBOM bundle. |
| `sbom verify` | `--sbom` `--bundle` `--trust-store` `--package` `--version` `[--json]` | SBOM verification result. |
| `sbom check` | `--file` `--bundle` `--sbom` `--sbom-bundle` `--trust-store` `--package` `--version` `[--json]` | Combined result for the release, the SBOM, and their binding. |

## Parameter types

| Parameter | Type | Rule |
|---|---|---|
| `--algorithm` | string | `rsa-pss-sha256`, `ecdsa-p256-sha256`, or `ed25519`. |
| `--package` | string | `[a-z0-9][a-z0-9._-]{0,63}`. |
| `--version` | string | `[A-Za-z0-9][A-Za-z0-9._+-]{0,63}`. |
| `--file`, `--bundle`, `--key`, `--out`, `--store`, `--trust-store`, `--sbom`, `--sbom-bundle` | path | Local file. |
| `--keyid` | string | 64 lowercase hexadecimal characters. |
| `--force` | boolean | The only way to overwrite an existing private key, bundle, or SBOM. |
| `--json` | boolean | Result as a single JSON object. |

## Output rules

- `verify --json` writes exactly one JSON object followed by one newline to stdout. For `INPUT_ERROR` (missing option, file not found) the JSON object is still written.
- Error messages and extra information go to stderr only.
- A private key is never printed or logged.
- An existing output without `--force` produces a clear error and exit 2, and the old file is not overwritten.
- Exit codes follow [Status and exit codes](status.md).

## Running through the container

```sh
docker run --rm --network none --user "$(id -u):$(id -g)" \
  -v "$PWD/dist:/input:ro" -v "$PWD/out:/output" -v "$KEY_FILE:/run/signing.key.pem:ro" \
  "$IMAGE" sign --file /input/demo-app.tar.gz --package demo-app --version 1.0.0 \
  --key /run/signing.key.pem --out /output/release.json
```

`$IMAGE` is always pinned by digest (`ghcr.io/brii26/release-signer@sha256:...`). The container exit code equals the program exit code.
