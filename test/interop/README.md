# Independent interoperability checks

Run `make interop` from the repository root. Requires Go, OpenSSL 3 with
`pkeyutl -rawin` support, Python 3, uv, Git and `sha256sum`. The runner pins the
test-only Python dependency using `uv run --with cryptography==50.0.2 python`.
It does not add dependencies to the CLI or `go.mod`.

The runner builds the CLI in `/tmp`, then exercises all three profiles:

- CLI-generated key and CLI signature verified by OpenSSL, including rejection
  of a one-bit signature corruption with actual exit code 1.
- OpenSSL-generated PKCS#8 private key and SPKI public key, independent Python
  manifest and signature, and CLI trust/verification with `valid=true`,
  `status=OK` and exit 0. Corrupted Python signatures must return
  `valid=false`, `INVALID_SIGNATURE` and exit 1.
- CLI signing with those OpenSSL private keys, verified by CLI and OpenSSL.
- Both key sources checked against SHA-256 of OpenSSL-exported DER SPKI.

The Python signer constructs the canonical manifest itself, hashes the artifact
itself and signs its exact bytes. The extraction helper preserves decoded
manifest/signature bytes. ECDSA uses fixed-width raw `r || s` in bundles and
unsigned DER INTEGERs for OpenSSL. RSA-PSS fixes SHA-256, MGF1-SHA-256 and a
32-byte salt; Ed25519 signs the message directly without a digest option.

`results/interop/results.md` is regenerated with commands, observed exits,
versions, fingerprints, script hashes and source/platform metadata. It stops
on the first failed check and retains a failure report with bounded, sanitized
diagnostics. `INTEROP_RESULTS_DIR` can redirect reports for fault tests. Private
keys, artifacts, logs and the CLI binary remain under a mode-restricted temporary
directory that is removed on success, failure or handled signals. Cache defaults
are `/tmp/release-signer-go-cache` and `/tmp/release-signer-uv-cache`.

Run focused boundary and failure tests with:

```sh
GOCACHE=/tmp/release-signer-go-cache UV_CACHE_DIR=/tmp/release-signer-uv-cache \
  uv run --with cryptography==50.0.2 python -B -m unittest discover \
  -s test/interop -p 'test_*.py' -v
```

These also inject an OpenSSL verifier that incorrectly accepts corruption or
returns an infrastructure error, ensuring neither becomes a successful
rejection. Their reports go to separate `/tmp` directories.
