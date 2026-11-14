# Local benchmark results

UTC: 2026-11-14T19:35:11Z. Source: `16c1e251307a88049d406a27dcf4d265baf24218` (tracked source dirty: false).

- Machine-local measurements before the final release tag; not publication-quality controlled-hardware evidence.

- Serial rounds with five warmups and 30 samples, except keygen has 30 samples and no warmups; no CPU pinning, frequency locking, or cache eviction.

- Artifacts and demo keys/trust store are prepared outside timing. Demo keys are generated once per profile and held fixed across artifacts and measured rounds, then deleted.

- E2E includes subprocess startup, actual filesystem I/O, parsing, hashing, signing/verification, and bundle write/fsync; OS caches may be warm.

- Sign/verify microbenchmarks use canonical manifest M, not artifact bytes or a prehash; profile-internal hashing is included.

Run from the repository root with `make bench` (or `go run ./bench`). See [bench/README.md](../../bench/README.md) for methodology. Binary build and artifact generation are excluded from timing. Library keygen uses `keys.Generate` directly. The e2e sign command also includes the signer's built-in signature self-check. Per-round output checks happen after the timer stops; e2e sign additionally invokes an untimed CLI verify, warming filesystem caches.

Raw CSVs have **no header**: exactly 30 lines, one integer nanosecond duration per line in collection order. Warmups are omitted. Median averages the middle pair; p95 uses nearest rank ceil(0.95 × 30) = 29. Keygen uses artifact `none`; every other metric covers every profile/artifact combination. Durations below are milliseconds; JSON retains nanoseconds.

| Metric | Profile | Artifact | Samples | Median (ms) | p95 (ms) | Raw CSV |
|---|---|---|---:|---:|---:|---|
| keygen | rsa-pss-sha256 | none | 30 | 148.730799 | 463.339410 | [keygen_rsa-pss-sha256_none.csv](raw/keygen_rsa-pss-sha256_none.csv) |
| keygen | ecdsa-p256-sha256 | none | 30 | 0.011702 | 0.018585 | [keygen_ecdsa-p256-sha256_none.csv](raw/keygen_ecdsa-p256-sha256_none.csv) |
| keygen | ed25519 | none | 30 | 0.015905 | 0.016602 | [keygen_ed25519_none.csv](raw/keygen_ed25519_none.csv) |
| hash | rsa-pss-sha256 | small.bin | 30 | 0.000581 | 0.000611 | [hash_rsa-pss-sha256_small.bin.csv](raw/hash_rsa-pss-sha256_small.bin.csv) |
| sign | rsa-pss-sha256 | small.bin | 30 | 2.443739 | 2.589775 | [sign_rsa-pss-sha256_small.bin.csv](raw/sign_rsa-pss-sha256_small.bin.csv) |
| verify | rsa-pss-sha256 | small.bin | 30 | 0.101287 | 0.104037 | [verify_rsa-pss-sha256_small.bin.csv](raw/verify_rsa-pss-sha256_small.bin.csv) |
| e2e_sign | rsa-pss-sha256 | small.bin | 30 | 5.346556 | 5.662925 | [e2e_sign_rsa-pss-sha256_small.bin.csv](raw/e2e_sign_rsa-pss-sha256_small.bin.csv) |
| e2e_verify | rsa-pss-sha256 | small.bin | 30 | 2.481511 | 3.514092 | [e2e_verify_rsa-pss-sha256_small.bin.csv](raw/e2e_verify_rsa-pss-sha256_small.bin.csv) |
| hash | ecdsa-p256-sha256 | small.bin | 30 | 0.000711 | 0.000712 | [hash_ecdsa-p256-sha256_small.bin.csv](raw/hash_ecdsa-p256-sha256_small.bin.csv) |
| sign | ecdsa-p256-sha256 | small.bin | 30 | 0.026981 | 0.040246 | [sign_ecdsa-p256-sha256_small.bin.csv](raw/sign_ecdsa-p256-sha256_small.bin.csv) |
| verify | ecdsa-p256-sha256 | small.bin | 30 | 0.060619 | 0.075272 | [verify_ecdsa-p256-sha256_small.bin.csv](raw/verify_ecdsa-p256-sha256_small.bin.csv) |
| e2e_sign | ecdsa-p256-sha256 | small.bin | 30 | 2.638393 | 3.262307 | [e2e_sign_ecdsa-p256-sha256_small.bin.csv](raw/e2e_sign_ecdsa-p256-sha256_small.bin.csv) |
| e2e_verify | ecdsa-p256-sha256 | small.bin | 30 | 2.411348 | 2.905873 | [e2e_verify_ecdsa-p256-sha256_small.bin.csv](raw/e2e_verify_ecdsa-p256-sha256_small.bin.csv) |
| hash | ed25519 | small.bin | 30 | 0.000711 | 0.000712 | [hash_ed25519_small.bin.csv](raw/hash_ed25519_small.bin.csv) |
| sign | ed25519 | small.bin | 30 | 0.019352 | 0.019467 | [sign_ed25519_small.bin.csv](raw/sign_ed25519_small.bin.csv) |
| verify | ed25519 | small.bin | 30 | 0.044735 | 0.044814 | [verify_ed25519_small.bin.csv](raw/verify_ed25519_small.bin.csv) |
| e2e_sign | ed25519 | small.bin | 30 | 3.513281 | 4.168239 | [e2e_sign_ed25519_small.bin.csv](raw/e2e_sign_ed25519_small.bin.csv) |
| e2e_verify | ed25519 | small.bin | 30 | 2.630097 | 3.194328 | [e2e_verify_ed25519_small.bin.csv](raw/e2e_verify_ed25519_small.bin.csv) |
| hash | rsa-pss-sha256 | medium.bin | 30 | 0.490692 | 0.506447 | [hash_rsa-pss-sha256_medium.bin.csv](raw/hash_rsa-pss-sha256_medium.bin.csv) |
| sign | rsa-pss-sha256 | medium.bin | 30 | 2.390359 | 2.908518 | [sign_rsa-pss-sha256_medium.bin.csv](raw/sign_rsa-pss-sha256_medium.bin.csv) |
| verify | rsa-pss-sha256 | medium.bin | 30 | 0.181443 | 0.279137 | [verify_rsa-pss-sha256_medium.bin.csv](raw/verify_rsa-pss-sha256_medium.bin.csv) |
| e2e_sign | rsa-pss-sha256 | medium.bin | 30 | 6.041690 | 7.980655 | [e2e_sign_rsa-pss-sha256_medium.bin.csv](raw/e2e_sign_rsa-pss-sha256_medium.bin.csv) |
| e2e_verify | rsa-pss-sha256 | medium.bin | 30 | 3.180687 | 3.553878 | [e2e_verify_rsa-pss-sha256_medium.bin.csv](raw/e2e_verify_rsa-pss-sha256_medium.bin.csv) |
| hash | ecdsa-p256-sha256 | medium.bin | 30 | 0.482272 | 0.489375 | [hash_ecdsa-p256-sha256_medium.bin.csv](raw/hash_ecdsa-p256-sha256_medium.bin.csv) |
| sign | ecdsa-p256-sha256 | medium.bin | 30 | 0.026425 | 0.031760 | [sign_ecdsa-p256-sha256_medium.bin.csv](raw/sign_ecdsa-p256-sha256_medium.bin.csv) |
| verify | ecdsa-p256-sha256 | medium.bin | 30 | 0.060043 | 0.065003 | [verify_ecdsa-p256-sha256_medium.bin.csv](raw/verify_ecdsa-p256-sha256_medium.bin.csv) |
| e2e_sign | ecdsa-p256-sha256 | medium.bin | 30 | 3.228308 | 4.366514 | [e2e_sign_ecdsa-p256-sha256_medium.bin.csv](raw/e2e_sign_ecdsa-p256-sha256_medium.bin.csv) |
| e2e_verify | ecdsa-p256-sha256 | medium.bin | 30 | 3.155876 | 3.556463 | [e2e_verify_ecdsa-p256-sha256_medium.bin.csv](raw/e2e_verify_ecdsa-p256-sha256_medium.bin.csv) |
| hash | ed25519 | medium.bin | 30 | 0.487787 | 0.617868 | [hash_ed25519_medium.bin.csv](raw/hash_ed25519_medium.bin.csv) |
| sign | ed25519 | medium.bin | 30 | 0.019237 | 0.025679 | [sign_ed25519_medium.bin.csv](raw/sign_ed25519_medium.bin.csv) |
| verify | ed25519 | medium.bin | 30 | 0.044995 | 0.056286 | [verify_ed25519_medium.bin.csv](raw/verify_ed25519_medium.bin.csv) |
| e2e_sign | ed25519 | medium.bin | 30 | 4.098432 | 5.018906 | [e2e_sign_ed25519_medium.bin.csv](raw/e2e_sign_ed25519_medium.bin.csv) |
| e2e_verify | ed25519 | medium.bin | 30 | 3.539471 | 4.295299 | [e2e_verify_ed25519_medium.bin.csv](raw/e2e_verify_ed25519_medium.bin.csv) |
| hash | rsa-pss-sha256 | large.bin | 30 | 48.164961 | 106.539759 | [hash_rsa-pss-sha256_large.bin.csv](raw/hash_rsa-pss-sha256_large.bin.csv) |
| sign | rsa-pss-sha256 | large.bin | 30 | 5.188122 | 5.255744 | [sign_rsa-pss-sha256_large.bin.csv](raw/sign_rsa-pss-sha256_large.bin.csv) |
| verify | rsa-pss-sha256 | large.bin | 30 | 0.266804 | 0.291080 | [verify_rsa-pss-sha256_large.bin.csv](raw/verify_rsa-pss-sha256_large.bin.csv) |
| e2e_sign | rsa-pss-sha256 | large.bin | 30 | 142.574966 | 145.125211 | [e2e_sign_rsa-pss-sha256_large.bin.csv](raw/e2e_sign_rsa-pss-sha256_large.bin.csv) |
| e2e_verify | rsa-pss-sha256 | large.bin | 30 | 144.072660 | 148.010694 | [e2e_verify_rsa-pss-sha256_large.bin.csv](raw/e2e_verify_rsa-pss-sha256_large.bin.csv) |
| hash | ecdsa-p256-sha256 | large.bin | 30 | 47.905242 | 106.618552 | [hash_ecdsa-p256-sha256_large.bin.csv](raw/hash_ecdsa-p256-sha256_large.bin.csv) |
| sign | ecdsa-p256-sha256 | large.bin | 30 | 0.026174 | 0.035878 | [sign_ecdsa-p256-sha256_large.bin.csv](raw/sign_ecdsa-p256-sha256_large.bin.csv) |
| verify | ecdsa-p256-sha256 | large.bin | 30 | 0.058495 | 0.059864 | [verify_ecdsa-p256-sha256_large.bin.csv](raw/verify_ecdsa-p256-sha256_large.bin.csv) |
| e2e_sign | ecdsa-p256-sha256 | large.bin | 30 | 68.170968 | 69.831146 | [e2e_sign_ecdsa-p256-sha256_large.bin.csv](raw/e2e_sign_ecdsa-p256-sha256_large.bin.csv) |
| e2e_verify | ecdsa-p256-sha256 | large.bin | 30 | 77.075089 | 87.095933 | [e2e_verify_ecdsa-p256-sha256_large.bin.csv](raw/e2e_verify_ecdsa-p256-sha256_large.bin.csv) |
| hash | ed25519 | large.bin | 30 | 49.317437 | 51.225249 | [hash_ed25519_large.bin.csv](raw/hash_ed25519_large.bin.csv) |
| sign | ed25519 | large.bin | 30 | 0.018675 | 0.019226 | [sign_ed25519_large.bin.csv](raw/sign_ed25519_large.bin.csv) |
| verify | ed25519 | large.bin | 30 | 0.044074 | 0.044264 | [verify_ed25519_large.bin.csv](raw/verify_ed25519_large.bin.csv) |
| e2e_sign | ed25519 | large.bin | 30 | 104.291005 | 139.692007 | [e2e_sign_ed25519_large.bin.csv](raw/e2e_sign_ed25519_large.bin.csv) |
| e2e_verify | ed25519 | large.bin | 30 | 76.942582 | 79.041175 | [e2e_verify_ed25519_large.bin.csv](raw/e2e_verify_ed25519_large.bin.csv) |

## Serialized sizes

Private and public key sizes are DER PKCS#8 and DER SPKI, respectively; no private key bytes are retained. Bundle sizes are measured from the actual CLI output file, including JSON/base64 overhead and its final newline.

| Profile | Artifact | Public DER (bytes) | Private DER (bytes) | Signature (bytes) | Bundle file (bytes) |
|---|---|---:|---:|---:|---:|
| rsa-pss-sha256 | small.bin | 422 | 1794 | 384 | 994 |
| ecdsa-p256-sha256 | small.bin | 91 | 138 | 64 | 574 |
| ed25519 | small.bin | 44 | 48 | 64 | 558 |
| rsa-pss-sha256 | medium.bin | 422 | 1794 | 384 | 998 |
| ecdsa-p256-sha256 | medium.bin | 91 | 138 | 64 | 578 |
| ed25519 | medium.bin | 44 | 48 | 64 | 566 |
| rsa-pss-sha256 | large.bin | 422 | 1794 | 384 | 998 |
| ecdsa-p256-sha256 | large.bin | 91 | 138 | 64 | 578 |
| ed25519 | large.bin | 44 | 48 | 64 | 566 |

## Shared artifacts

Every profile uses these exact byte sequences; digest and size checks precede timing. See [files.txt](files.txt).

| Artifact | Bytes | SHA-256 |
|---|---:|---|
| small.bin | 1024 | `785b0751fc2c53dc14a4ce3d800e69ef9ce1009eb327ccf458afe09c242c26c9` |
| medium.bin | 1048576 | `fbbab289f7f94b25736c58be46a994c441fd02552cc6022352e3d86d2fab7c83` |
| large.bin | 104857600 | `4cbf988462cc3ba2e10e3aae9f5268546aa79016359fb45be7dd199c073125c0` |
