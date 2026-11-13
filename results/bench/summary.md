# Local benchmark results

UTC: 2026-11-13T06:27:54Z. Source: `b5030bc0c86bd00cd4effddca964c0bc93a07c3c` (tracked source dirty: false).

- Machine-local measurements before the final release tag; not publication-quality controlled-hardware evidence.

- Serial rounds with five warmups and 30 samples, except keygen has 30 samples and no warmups; no CPU pinning, frequency locking, or cache eviction.

- Artifacts and demo keys/trust store are prepared outside timing. Demo keys are generated once per profile and held fixed across artifacts and measured rounds, then deleted.

- E2E includes subprocess startup, actual filesystem I/O, parsing, hashing, signing/verification, and bundle write/fsync; OS caches may be warm.

- Sign/verify microbenchmarks use canonical manifest M, not artifact bytes or a prehash; profile-internal hashing is included.

Run from the repository root with `make bench` (or `go run ./bench`). See [bench/README.md](../../bench/README.md) for methodology. Binary build and artifact generation are excluded from timing. Library keygen uses `keys.Generate` directly. The e2e sign command also includes the signer's built-in signature self-check. Per-round output checks happen after the timer stops; e2e sign additionally invokes an untimed CLI verify, warming filesystem caches.

Raw CSVs have **no header**: exactly 30 lines, one integer nanosecond duration per line in collection order. Warmups are omitted. Median averages the middle pair; p95 uses nearest rank ceil(0.95 × 30) = 29. Keygen uses artifact `none`; every other metric covers every profile/artifact combination. Durations below are milliseconds; JSON retains nanoseconds.

| Metric | Profile | Artifact | Samples | Median (ms) | p95 (ms) | Raw CSV |
|---|---|---|---:|---:|---:|---|
| keygen | rsa-pss-sha256 | none | 30 | 442.853481 | 1037.330727 | [keygen_rsa-pss-sha256_none.csv](raw/keygen_rsa-pss-sha256_none.csv) |
| keygen | ecdsa-p256-sha256 | none | 30 | 0.024821 | 0.041097 | [keygen_ecdsa-p256-sha256_none.csv](raw/keygen_ecdsa-p256-sha256_none.csv) |
| keygen | ed25519 | none | 30 | 0.033773 | 0.034445 | [keygen_ed25519_none.csv](raw/keygen_ed25519_none.csv) |
| hash | rsa-pss-sha256 | small.bin | 30 | 0.001232 | 0.001292 | [hash_rsa-pss-sha256_small.bin.csv](raw/hash_rsa-pss-sha256_small.bin.csv) |
| sign | rsa-pss-sha256 | small.bin | 30 | 5.179163 | 5.218929 | [sign_rsa-pss-sha256_small.bin.csv](raw/sign_rsa-pss-sha256_small.bin.csv) |
| verify | rsa-pss-sha256 | small.bin | 30 | 0.221165 | 0.287318 | [verify_rsa-pss-sha256_small.bin.csv](raw/verify_rsa-pss-sha256_small.bin.csv) |
| e2e_sign | rsa-pss-sha256 | small.bin | 30 | 11.754859 | 12.682272 | [e2e_sign_rsa-pss-sha256_small.bin.csv](raw/e2e_sign_rsa-pss-sha256_small.bin.csv) |
| e2e_verify | rsa-pss-sha256 | small.bin | 30 | 5.991020 | 6.805371 | [e2e_verify_rsa-pss-sha256_small.bin.csv](raw/e2e_verify_rsa-pss-sha256_small.bin.csv) |
| hash | ecdsa-p256-sha256 | small.bin | 30 | 0.001252 | 0.001523 | [hash_ecdsa-p256-sha256_small.bin.csv](raw/hash_ecdsa-p256-sha256_small.bin.csv) |
| sign | ecdsa-p256-sha256 | small.bin | 30 | 0.057298 | 0.077445 | [sign_ecdsa-p256-sha256_small.bin.csv](raw/sign_ecdsa-p256-sha256_small.bin.csv) |
| verify | ecdsa-p256-sha256 | small.bin | 30 | 0.131241 | 0.163827 | [verify_ecdsa-p256-sha256_small.bin.csv](raw/verify_ecdsa-p256-sha256_small.bin.csv) |
| e2e_sign | ecdsa-p256-sha256 | small.bin | 30 | 6.045732 | 6.857589 | [e2e_sign_ecdsa-p256-sha256_small.bin.csv](raw/e2e_sign_ecdsa-p256-sha256_small.bin.csv) |
| e2e_verify | ecdsa-p256-sha256 | small.bin | 30 | 5.698206 | 6.583686 | [e2e_verify_ecdsa-p256-sha256_small.bin.csv](raw/e2e_verify_ecdsa-p256-sha256_small.bin.csv) |
| hash | ed25519 | small.bin | 30 | 0.001232 | 0.001242 | [hash_ed25519_small.bin.csv](raw/hash_ed25519_small.bin.csv) |
| sign | ed25519 | small.bin | 30 | 0.042079 | 0.061385 | [sign_ed25519_small.bin.csv](raw/sign_ed25519_small.bin.csv) |
| verify | ed25519 | small.bin | 30 | 0.097783 | 0.129162 | [verify_ed25519_small.bin.csv](raw/verify_ed25519_small.bin.csv) |
| e2e_sign | ed25519 | small.bin | 30 | 7.880120 | 9.298352 | [e2e_sign_ed25519_small.bin.csv](raw/e2e_sign_ed25519_small.bin.csv) |
| e2e_verify | ed25519 | small.bin | 30 | 6.080528 | 6.941356 | [e2e_verify_ed25519_small.bin.csv](raw/e2e_verify_ed25519_small.bin.csv) |
| hash | rsa-pss-sha256 | medium.bin | 30 | 1.071503 | 1.232149 | [hash_rsa-pss-sha256_medium.bin.csv](raw/hash_rsa-pss-sha256_medium.bin.csv) |
| sign | rsa-pss-sha256 | medium.bin | 30 | 5.198866 | 5.465941 | [sign_rsa-pss-sha256_medium.bin.csv](raw/sign_rsa-pss-sha256_medium.bin.csv) |
| verify | rsa-pss-sha256 | medium.bin | 30 | 0.221194 | 0.247784 | [verify_rsa-pss-sha256_medium.bin.csv](raw/verify_rsa-pss-sha256_medium.bin.csv) |
| e2e_sign | rsa-pss-sha256 | medium.bin | 30 | 13.844836 | 15.370860 | [e2e_sign_rsa-pss-sha256_medium.bin.csv](raw/e2e_sign_rsa-pss-sha256_medium.bin.csv) |
| e2e_verify | rsa-pss-sha256 | medium.bin | 30 | 7.481257 | 8.454863 | [e2e_verify_rsa-pss-sha256_medium.bin.csv](raw/e2e_verify_rsa-pss-sha256_medium.bin.csv) |
| hash | ecdsa-p256-sha256 | medium.bin | 30 | 1.065992 | 1.098879 | [hash_ecdsa-p256-sha256_medium.bin.csv](raw/hash_ecdsa-p256-sha256_medium.bin.csv) |
| sign | ecdsa-p256-sha256 | medium.bin | 30 | 0.058540 | 0.081553 | [sign_ecdsa-p256-sha256_medium.bin.csv](raw/sign_ecdsa-p256-sha256_medium.bin.csv) |
| verify | ecdsa-p256-sha256 | medium.bin | 30 | 0.130965 | 0.144762 | [verify_ecdsa-p256-sha256_medium.bin.csv](raw/verify_ecdsa-p256-sha256_medium.bin.csv) |
| e2e_sign | ecdsa-p256-sha256 | medium.bin | 30 | 7.573569 | 8.287858 | [e2e_sign_ecdsa-p256-sha256_medium.bin.csv](raw/e2e_sign_ecdsa-p256-sha256_medium.bin.csv) |
| e2e_verify | ecdsa-p256-sha256 | medium.bin | 30 | 7.194401 | 8.476533 | [e2e_verify_ecdsa-p256-sha256_medium.bin.csv](raw/e2e_verify_ecdsa-p256-sha256_medium.bin.csv) |
| hash | ed25519 | medium.bin | 30 | 1.065060 | 1.152610 | [hash_ed25519_medium.bin.csv](raw/hash_ed25519_medium.bin.csv) |
| sign | ed25519 | medium.bin | 30 | 0.042034 | 0.042600 | [sign_ed25519_medium.bin.csv](raw/sign_ed25519_medium.bin.csv) |
| verify | ed25519 | medium.bin | 30 | 0.097513 | 0.116047 | [verify_ed25519_medium.bin.csv](raw/verify_ed25519_medium.bin.csv) |
| e2e_sign | ed25519 | medium.bin | 30 | 9.977886 | 10.915933 | [e2e_sign_ed25519_medium.bin.csv](raw/e2e_sign_ed25519_medium.bin.csv) |
| e2e_verify | ed25519 | medium.bin | 30 | 7.587858 | 8.520846 | [e2e_verify_ed25519_medium.bin.csv](raw/e2e_verify_ed25519_medium.bin.csv) |
| hash | rsa-pss-sha256 | large.bin | 30 | 106.697445 | 106.948021 | [hash_rsa-pss-sha256_large.bin.csv](raw/hash_rsa-pss-sha256_large.bin.csv) |
| sign | rsa-pss-sha256 | large.bin | 30 | 5.190616 | 5.240629 | [sign_rsa-pss-sha256_large.bin.csv](raw/sign_rsa-pss-sha256_large.bin.csv) |
| verify | rsa-pss-sha256 | large.bin | 30 | 0.229104 | 0.287970 | [verify_rsa-pss-sha256_large.bin.csv](raw/verify_rsa-pss-sha256_large.bin.csv) |
| e2e_sign | rsa-pss-sha256 | large.bin | 30 | 146.311298 | 149.439730 | [e2e_sign_rsa-pss-sha256_large.bin.csv](raw/e2e_sign_rsa-pss-sha256_large.bin.csv) |
| e2e_verify | rsa-pss-sha256 | large.bin | 30 | 80.617391 | 85.581113 | [e2e_verify_rsa-pss-sha256_large.bin.csv](raw/e2e_verify_rsa-pss-sha256_large.bin.csv) |
| hash | ecdsa-p256-sha256 | large.bin | 30 | 72.010013 | 106.940538 | [hash_ecdsa-p256-sha256_large.bin.csv](raw/hash_ecdsa-p256-sha256_large.bin.csv) |
| sign | ecdsa-p256-sha256 | large.bin | 30 | 0.056601 | 0.067967 | [sign_ecdsa-p256-sha256_large.bin.csv](raw/sign_ecdsa-p256-sha256_large.bin.csv) |
| verify | ecdsa-p256-sha256 | large.bin | 30 | 0.131116 | 0.140403 | [verify_ecdsa-p256-sha256_large.bin.csv](raw/verify_ecdsa-p256-sha256_large.bin.csv) |
| e2e_sign | ecdsa-p256-sha256 | large.bin | 30 | 141.084210 | 145.192709 | [e2e_sign_ecdsa-p256-sha256_large.bin.csv](raw/e2e_sign_ecdsa-p256-sha256_large.bin.csv) |
| e2e_verify | ecdsa-p256-sha256 | large.bin | 30 | 81.091713 | 92.835926 | [e2e_verify_ecdsa-p256-sha256_large.bin.csv](raw/e2e_verify_ecdsa-p256-sha256_large.bin.csv) |
| hash | ed25519 | large.bin | 30 | 48.760168 | 49.408248 | [hash_ed25519_large.bin.csv](raw/hash_ed25519_large.bin.csv) |
| sign | ed25519 | large.bin | 30 | 0.018975 | 0.019367 | [sign_ed25519_large.bin.csv](raw/sign_ed25519_large.bin.csv) |
| verify | ed25519 | large.bin | 30 | 0.044839 | 0.045004 | [verify_ed25519_large.bin.csv](raw/verify_ed25519_large.bin.csv) |
| e2e_sign | ed25519 | large.bin | 30 | 142.247800 | 145.693822 | [e2e_sign_ed25519_large.bin.csv](raw/e2e_sign_ed25519_large.bin.csv) |
| e2e_verify | ed25519 | large.bin | 30 | 83.891974 | 137.570977 | [e2e_verify_ed25519_large.bin.csv](raw/e2e_verify_ed25519_large.bin.csv) |

## Serialized sizes

Private and public key sizes are DER PKCS#8 and DER SPKI, respectively; no private key bytes are retained. Bundle sizes are measured from the actual CLI output file, including JSON/base64 overhead and its final newline.

| Profile | Artifact | Public DER (bytes) | Private DER (bytes) | Signature (bytes) | Bundle file (bytes) |
|---|---|---:|---:|---:|---:|
| rsa-pss-sha256 | small.bin | 422 | 1793 | 384 | 994 |
| ecdsa-p256-sha256 | small.bin | 91 | 138 | 64 | 574 |
| ed25519 | small.bin | 44 | 48 | 64 | 558 |
| rsa-pss-sha256 | medium.bin | 422 | 1793 | 384 | 998 |
| ecdsa-p256-sha256 | medium.bin | 91 | 138 | 64 | 578 |
| ed25519 | medium.bin | 44 | 48 | 64 | 566 |
| rsa-pss-sha256 | large.bin | 422 | 1793 | 384 | 998 |
| ecdsa-p256-sha256 | large.bin | 91 | 138 | 64 | 578 |
| ed25519 | large.bin | 44 | 48 | 64 | 566 |

## Shared artifacts

Every profile uses these exact byte sequences; digest and size checks precede timing. See [files.txt](files.txt).

| Artifact | Bytes | SHA-256 |
|---|---:|---|
| small.bin | 1024 | `785b0751fc2c53dc14a4ce3d800e69ef9ce1009eb327ccf458afe09c242c26c9` |
| medium.bin | 1048576 | `fbbab289f7f94b25736c58be46a994c441fd02552cc6022352e3d86d2fab7c83` |
| large.bin | 104857600 | `4cbf988462cc3ba2e10e3aae9f5268546aa79016359fb45be7dd199c073125c0` |
