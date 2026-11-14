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
- **Run 1 Signature (Hex):** `1735d0ce0407575e81895c6674fd34899ff7296507e6a975276ffb7d730adeb26f7375a958cff2906a94d4ae3cd73946bff5ddb8decf0dd3e9635959923f43355ec1a5c959cb4bc2da4560a38f11aa2ac20e6ab8d90bb4095d7f6a7e1b2a4df6b34a15b82f78e37b588317dfd21993d76bb1cd82aa639a0a100f771fdf8a55859192c95a6999a33e898c916734c74617dccfcf0856e9d87da29d86204b7a0e007589e3ce22e4788d9d680231f2819f7c9ec0be5f00cb6b3bc5522daa1f5667ce552355315a64ee11dc7aacd1fe0a261f2f671c8337e75f6ee26e247bea4a1243140fd2296e7a3ae043ad6f345345504125c58d038f13c8e4a6913285068e73c5bc5bbf2d32c3808c0857d3a70bb9c59505f9e39c354c6102213cddab2d10ad7429ed065e0b7c80bf668968444b0611b1cbf69675f7dac414d59e02d394a4929aa9f61c0eb63e7e3d6ea5adf95cca221e67efb17625109808bde431455dd04f8767027fb7558adde134a968c19e7dfdb5627ee59184307c502d071fa2d0fb52d6`
- **Run 2 Signature (Hex):** `3f33a22fd7b1a30122b521c45e4ea0331f0c6afb159981d06ed6a74505711400066f2540a508e56710b28a1bf411a15f64aaa5e6ec89968661019466df98e68628087f6dbc62f1367b6edd6a480084a2c05ec8e6e911ab4698d936410dce848cb5c86871f94fa8b049c28f31bc1e81cd4b6f9662f5d2972345e2c34ecf3b49f20e7cf1d271914706cf5b5262364772084c0c73845140e636169071689e33bdb7b4a2c81b163557e3cd863c743f30d1feca2a3eebf34dbb9a3c75c12154f8df45fc0a979e4946c315bfc72b5ac828440777cda3cd8859e60fd9c83eeb59b2de3d6dcdfcf30bc628584f5dedac12962735a5772f3010099202304062883c7aad6dbd975406f65293aecfcfaf69821c44e32c3f097b0e60d6d1de715821421d6b3a758c7f153c54a6d26062de553e1c23e6169ad2df2ca5308d5901644679be75020fb29cbef6faa4d2e51f76c089b7f55bac1d66b70206e6822744ad291823a2d88e2f28996bd332f437446deb701aefa45725f27bae64eb9d8180e380c2af9d56`

### Profile: `ecdsa-p256-sha256`
- **Analysis:** ECDSA CSPRNG hedged nonce produces distinct signatures
- **Run 1 Signature (Hex):** `4b64ddefcdca5476f9aec6b416f6ebe20f93920f44b513667ab6b8b498cb144fadb0ea4529dbed218ecfd9fab3beea81b64aeaf72f254d48bcbd60c9e4dcd75a`
- **Run 2 Signature (Hex):** `79d622c2c12820a9a6ee6d8d717d44c143b500b5f1539e1de6358612cdc26b0b83bb6e1a18d0e010ccf3685dc1f7685d636cb67127c57918c9200811c2419133`

### Profile: `ed25519`
- **Analysis:** Ed25519 deterministic signature (RFC 8032) produces identical signatures
- **Run 1 Signature (Hex):** `52b5bcd00c9de752c35424e7851d943e40e047fc3e62d2d29e16ae554a5af796b9ff426e4efb726dfc66348b760c06765aaec7147ff2b800cb0c0fb465b80806`
- **Run 2 Signature (Hex):** `52b5bcd00c9de752c35424e7851d943e40e047fc3e62d2d29e16ae554a5af796b9ff426e4efb726dfc66348b760c06765aaec7147ff2b800cb0c0fb465b80806`

