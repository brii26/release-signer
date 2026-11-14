# Test Scenarios U01 to U14 (Table 2.11)

| ID | Profile | Input / Method | Expected Status | Expected Exit | Actual Status | Actual Exit | Result |
|:---|:---|:---|:---|:---:|:---|:---:|:---:|
| U01 | rsa-pss-sha256 | Sign and verify fixture text.txt | `OK` | 0 | `OK` | 0 | **PASS** |
| U01 | rsa-pss-sha256 | Sign and verify fixture binary.bin | `OK` | 0 | `OK` | 0 | **PASS** |
| U01 | rsa-pss-sha256 | Sign and verify fixture empty.bin | `OK` | 0 | `OK` | 0 | **PASS** |
| U01 | ecdsa-p256-sha256 | Sign and verify fixture text.txt | `OK` | 0 | `OK` | 0 | **PASS** |
| U01 | ecdsa-p256-sha256 | Sign and verify fixture binary.bin | `OK` | 0 | `OK` | 0 | **PASS** |
| U01 | ecdsa-p256-sha256 | Sign and verify fixture empty.bin | `OK` | 0 | `OK` | 0 | **PASS** |
| U01 | ed25519 | Sign and verify fixture text.txt | `OK` | 0 | `OK` | 0 | **PASS** |
| U01 | ed25519 | Sign and verify fixture binary.bin | `OK` | 0 | `OK` | 0 | **PASS** |
| U01 | ed25519 | Sign and verify fixture empty.bin | `OK` | 0 | `OK` | 0 | **PASS** |
| U02 | ed25519 | Tamper 1 byte of artifact after signing | `ARTIFACT_MISMATCH` | 1 | `ARTIFACT_MISMATCH` | 1 | **PASS** |
| U03 | ed25519 | Append 1 byte to artifact (size change) | `ARTIFACT_MISMATCH` | 1 | `ARTIFACT_MISMATCH` | 1 | **PASS** |
| U04 | ed25519 | Tamper manifest version preserving canonical form, old signature | `INVALID_SIGNATURE` | 1 | `INVALID_SIGNATURE` | 1 | **PASS** |
| U05 | ed25519 | Flip 1 bit of signature bytes (length 64 preserved) | `INVALID_SIGNATURE` | 1 | `INVALID_SIGNATURE` | 1 | **PASS** |
| U06 | ed25519 | Empty trust store (key lookup failure) | `KEY_NOT_TRUSTED` | 1 | `KEY_NOT_TRUSTED` | 1 | **PASS** |
| U07 | ed25519 | Key authorized only for other-package | `KEY_NOT_TRUSTED` | 1 | `KEY_NOT_TRUSTED` | 1 | **PASS** |
| U08 | ed25519 | CLI --version (2.0.0) differs from manifest (1.0.0) | `METADATA_MISMATCH` | 1 | `METADATA_MISMATCH` | 1 | **PASS** |
| U09 | ed25519 | Rename physical artifact on disk (basename mismatch) | `METADATA_MISMATCH` | 1 | `METADATA_MISMATCH` | 1 | **PASS** |
| U10a | ed25519 | Duplicate schema field in bundle JSON | `FORMAT_ERROR` | 1 | `FORMAT_ERROR` | 1 | **PASS** |
| U10b | ed25519 | artifact.size encoded as string instead of integer | `FORMAT_ERROR` | 1 | `FORMAT_ERROR` | 1 | **PASS** |
| U10c | ed25519 | signature_b64 contains illegal character '!' | `FORMAT_ERROR` | 1 | `FORMAT_ERROR` | 1 | **PASS** |
| U10d | ed25519 | Decoded manifest size > 16 KiB | `FORMAT_ERROR` | 1 | `FORMAT_ERROR` | 1 | **PASS** |
| U11 | ed25519 | Manifest algorithm rsa-pkcs1-sha256 (unsupported) | `UNSUPPORTED_ALGORITHM` | 1 | `UNSUPPORTED_ALGORITHM` | 1 | **PASS** |
| U12 | ed25519 | Signed with other key not present in trust store | `KEY_NOT_TRUSTED` | 1 | `KEY_NOT_TRUSTED` | 1 | **PASS** |
| U13 | ed25519 | Reorder keys in bundle JSON (manifest retains canonical format) | `OK` | 0 | `OK` | 0 | **PASS** |
| U14 | rsa-pss-sha256 | Sign identical manifest twice and verify randomness | `OK` | 0 | `OK` | 0 | **PASS** |
| U14 | ecdsa-p256-sha256 | Sign identical manifest twice and verify randomness | `OK` | 0 | `OK` | 0 | **PASS** |
| U14 | ed25519 | Sign identical manifest twice and verify randomness | `OK` | 0 | `OK` | 0 | **PASS** |
| Neg_ProfileMismatch | ed25519 | Key profile in trust store differs from manifest algorithm | `KEY_NOT_TRUSTED` | 1 | `KEY_NOT_TRUSTED` | 1 | **PASS** |
| Neg_MissingArtifact | ed25519 | Physical artifact file missing from disk | `INPUT_ERROR` | 2 | `INPUT_ERROR` | 2 | **PASS** |
| Neg_BundleTooLarge | ed25519 | Bundle file exceeds 64 KiB limit | `FORMAT_ERROR` | 1 | `FORMAT_ERROR` | 1 | **PASS** |

**Total:** 30 scenarios | **Passed:** 30 | **Failed:** 0 | **Skipped:** 0

## U14 Analysis: Signature Randomness and Determinism

### Profile: `rsa-pss-sha256`
- **Analysis:** RSA-PSS randomized salt (32 bytes) produces distinct signatures
- **Run 1 Signature (Hex):** `46264ca5f60d6ae3febb337688662d44b4c724fdfa0186828ce14d53b9993cd687d6419623ce638a2ad4b3ecc719da3d42785c5c263d037d83e8d850a46ba989e2ebdee3c35a84d99072b475cb257319adf18562d370488a8cd5823b1141a2910df648e3442d463d32c12bc2f356955151ce06fb5b25de2d0e589405f5a1b63e2c9d82d0b73811503ca94f3e85221e3d7290b4e9f913b889387932d25cee799589004f579f0608e7df286f195b7c04bacfeadd72262a7198872190e4c89dc61d11be43616503f0714315aea1d0a018de60486b1a81fa596a607f7b7d6e7ea1a3cc166d8717b258e9df871f95d736f2f4b6fbc19b5f33f25498e2c0ea36078def542683114d200a18b7bef0dcb78ff5b5ea87ee96f0dd176771e4695820d23347312dfa328610efd0856022f933b3ed3db576df576908d0ff00508e69d333140699ae323e3cc313581f8e287aa1f7febe17ce2560a4239b06cec95be76b01e97d1709f821386b2ae58196113616986aea26ce4106121a475034e97672178ed8d3`
- **Run 2 Signature (Hex):** `251d5eea5ab7f9af27b4a12e39154214f56634a31810dcc6dacd1f0542479c4ab7a6f4bf6eb8953f4fbe740bd8134007cb31dacb98b4e32d0ab3d7fac7a43d62ebb0ca0e4f916b81cbadc207fe52e80475b86a01be85bdb3fca0967b72fa564719d7a0fc273641248db1c7d1ca7c45695c79402dab82dc64a20837a7446d301deba0dae5b393b52e0074fd82be6229dfe7e87a1cff5f831d5e23c6d8d563f4f242339962c5cb05de02f27e03472380ef1685f37049e8e41671527ef1c5158eedfcd3fe4476c8b1f31ea42d508e7873368084c573e7132a23b123e766b643ae040b78bf64078b52870ae2c828bea577c53a6d473381c09a681ee306218929066dbcb70068f1388d6356ea219c523959d924825cd5552cba87ed744613832f71554249536b63cb4369752cbcb9ea06ffb3d73575ed8eb48c547c6c84774a0ee6f3d412093f9d4a3d646c620df8c8ed1d7d6c2052259c4f4fc227acd478ac0c2502b4043fafbcd35e5488724e972c26444e2fbec12619506ca8ac229dab6b89db52`

### Profile: `ecdsa-p256-sha256`
- **Analysis:** ECDSA CSPRNG hedged nonce produces distinct signatures
- **Run 1 Signature (Hex):** `5024a00d861ce5045b8dfcd923ae23c2c108f40e9f3b00a15446622254cd9567ddb388bc3ccfba66842879b9cb94be70daf6c0fb315790911963bad20eee9752`
- **Run 2 Signature (Hex):** `15d6c53b476f9183b4b1327010cd51a84fd5777ddcba57215cf0cd3866bf61c90919f20fd133503795e44ddfec98f152943094c5b00f27e05f1bb926c9ca4580`

### Profile: `ed25519`
- **Analysis:** Ed25519 deterministic signature (RFC 8032) produces identical signatures
- **Run 1 Signature (Hex):** `52b5bcd00c9de752c35424e7851d943e40e047fc3e62d2d29e16ae554a5af796b9ff426e4efb726dfc66348b760c06765aaec7147ff2b800cb0c0fb465b80806`
- **Run 2 Signature (Hex):** `52b5bcd00c9de752c35424e7851d943e40e047fc3e62d2d29e16ae554a5af796b9ff426e4efb726dfc66348b760c06765aaec7147ff2b800cb0c0fb465b80806`

