# Reproducing the local benchmark

From the repository root, run `make bench`. Go (the version required by `go.mod`),
Git, a POSIX shell, and `uname` are required. No additional Go modules or runtime
packages are used. `sh bench/gen.sh` generates the three input files by itself.
`go run ./bench` also works directly: it generates missing data, builds a fresh
CLI in a temporary directory, runs the benchmark and writes `results/bench/`.
Existing data is checked against the deterministic stream before measurements;
regenerate corrupt files with `sh bench/gen.sh`.

The deterministic stream is byte `i mod 256` at offset `i`. The same 1 KiB,
1 MiB and 100 MiB files are used by all profiles. Artifacts live in ignored
`bench/data/`; `files.txt` records their exact byte counts and SHA-256 hashes.
Demo keys are generated afresh each run, held fixed across that run's artifacts
and sign/verify rounds, and deleted with their temporary trust store and CLI.
No private key bytes are written into results.

Each metric has 30 samples. Key generation calls `keys.Generate` 30 times per
profile with no warmups; all other metrics run five warmups before 30 samples.
Rounds are serial. Every timer uses `time.Now` and `time.Since`, which use Go's
monotonic clock. Preparation, subprocess construction, validation and report
writing are outside timing. Each completed operation is checked for success.

- `keygen`: `keys.Generate`, with public key/profile validation afterward.
- `hash`: `sha256.Sum256` of artifact bytes already loaded into memory.
- `sign` and `verify`: `sigalg.Sign` and `sigalg.Verify` over the **original
  canonical manifest bytes M**. Manifest construction and artifact hashing are
  outside timing. Profile-internal hashing of M is included; there is no I/O
  in these timed regions. Each signature is checked afterward.
- `e2e_sign` and `e2e_verify`: actual `release-signer` subprocesses, including
  process startup, key/trust/bundle parsing, artifact I/O and hashing, and
  bundle writing/fsync for sign. The signer's built-in signature self-check is
  included. Demo key/trust setup and binary build are outside timing. Sign uses
  `--force` to replace the same output path; every new bundle is checked with
  an additional untimed CLI verify. Verify JSON must report `valid: true`,
  `status: "OK"` and the expected identity, package, version and algorithm.

The raw CSVs contain exactly 30 **headerless** lines: one integer nanosecond
value per line in measurement order, without warmups. Keygen uses artifact
`none`; every other metric covers all nine profile/artifact combinations.
`summary.json` records nanoseconds. `summary.md` shows milliseconds, key sizes
(DER SPKI / DER PKCS#8), raw signature sizes and actual bundle file sizes.
Median averages the middle pair for even sample counts; p95 uses nearest rank
`ceil(0.95*n)` (rank 29 for 30 samples). `env.txt` records CPU model, available
logical core count, RAM, OS/kernel, Go/binary version, UTC and source commit.

Results are machine-local measurements before the final release tag, not
publication-quality controlled-hardware evidence. There is no CPU pinning,
frequency locking, cache eviction, or assertion of an otherwise idle machine.
Filesystem caches may be warm; the untimed per-sign verification also reads the
artifact. Random key generation, OS scheduling and system load cause variation.
Regenerating artifacts and reproducing the protocol is deterministic; timing
values and random demo keys are not expected to be byte-for-byte reproducible.

`go test ./bench` checks statistics, deterministic bytes/digest and corrupt input
rejection, and runs a small Ed25519/1 KiB subprocess smoke test using temporary
files, one warmup and two samples. It never runs the full benchmark or changes
`results/bench/`.
