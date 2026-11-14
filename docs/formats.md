# Data formats

All JSON files are UTF-8 without a BOM. Parsers reject extra fields, duplicate fields, `null`, and mismatched types.

## Release manifest (`minisign-manifest/v1`)

Maximum size 16 KiB. Canonical serialization: no spaces or newlines, field order fixed as in the table, no `\uXXXX` escapes.

| Field | Type | Rule |
|---|---|---|
| `schema` | string | Always `minisign-manifest/v1`. |
| `package` | string | `[a-z0-9][a-z0-9._-]{0,63}`. |
| `version` | string | `[A-Za-z0-9][A-Za-z0-9._+-]{0,63}`. |
| `algorithm` | string | `rsa-pss-sha256`, `ecdsa-p256-sha256`, or `ed25519`. |
| `keyid` | string | 64 lowercase hexadecimal characters. |
| `artifact` | object | Exactly the three fields below. |
| `artifact.name` | string | File basename, `[A-Za-z0-9][A-Za-z0-9._-]{0,127}`. |
| `artifact.size` | integer | 0 to 9007199254740991. Booleans are rejected. |
| `artifact.sha256` | string | 64 lowercase hexadecimal characters. |

## Bundle (`minisign-bundle/v1`)

Maximum size 64 KiB. Field order and white space are free.

| Field | Type | Rule |
|---|---|---|
| `schema` | string | Always `minisign-bundle/v1`. |
| `manifest_b64` | string | Manifest bytes, RFC 4648 Base64 with padding and no white space. |
| `signature_b64` | string | Signature bytes, same Base64. Length: 384 (RSA-PSS), 64 (ECDSA `r \|\| s`, Ed25519). |

## Trust store (`minisign-trust/v1`)

| Field | Type | Rule |
|---|---|---|
| `schema` | string | Always `minisign-trust/v1`. |
| `keys` | array | May be empty. Every `keyid` is unique. An empty store trusts no key. |
| `keys[].keyid` | string | `hex_lower(SHA256(DER_SPKI))`, must match `public_key_pem`. |
| `keys[].algorithm` | string | Profile matching the key type and parameters. |
| `keys[].public_key_pem` | string | SPKI PEM text, not a path. |
| `keys[].packages` | array of string | Must not be empty, contain duplicates, or use wildcards. |

## Key files

| Component | Format |
|---|---|
| Private key | PKCS#8 in PEM, label `PRIVATE KEY`. Created with mode `0600`. |
| Public key | SubjectPublicKeyInfo in PEM, label `PUBLIC KEY`. |
| RSA | Modulus of exactly 3072 bits, public exponent 65537. |
| ECDSA | P-256 (named curve), SEC1 uncompressed point. |
| Ed25519 | RFC 8410, parameters field absent. |

## Verification result (`verify --json`)

A single JSON object on stdout, followed by one newline.

| Field | Type | Rule |
|---|---|---|
| `valid` | boolean | `true` only for status `OK`. |
| `status` | string | See [Status and exit codes](status.md). |
| `message` | string | Short explanation. |
| `algorithm` | string/null | From the manifest, `null` if not yet read. |
| `keyid` | string/null | From the manifest, `null` if not yet read. |
| `package` | string/null | From the manifest, `null` if not yet read. |
| `version` | string/null | From the manifest, `null` if not yet read. |

When `valid` is `false`, the metadata fields only explain the result and must not be treated as trusted data.

## SBOM and `sbom check` result

The SBOM format (CycloneDX 1.6) and the `sbom check --json` output are described in [Signed SBOM](sbom.md).
