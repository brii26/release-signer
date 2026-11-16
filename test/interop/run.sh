#!/bin/sh
# dependency test (python dll) di luar CLI dan go.mod
set -eu
umask 077

root=$(CDPATH= cd -P "$(dirname "$0")/../.." && pwd)
cd "$root"
results=${INTEROP_RESULTS_DIR:-"$root/results/interop"}
mkdir -p "$results"
report="$results/results.md"
work=$(mktemp -d /tmp/release-signer-interop.XXXXXX)
finished=false
cleanup() {
    rc=$?
    trap - 0 HUP INT TERM
    if [ "$finished" = true ] && [ "$rc" -eq 0 ]; then
        printf '\n**Overall: PASS.** All three profiles passed both directions, external-key signing, six fingerprint checks, and corrupted-signature rejections.\n' >> "$report"
    else
        printf '\n**Overall: FAIL** (runner exit %s). Execution stopped; later checks were not run.\n' "$rc" >> "$report"
    fi
    rm -rf "$work"
    exit "$rc"
}
trap cleanup 0
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

# report minimal tetap dibuat walau Python tidak ada
printf '# Interoperability results\n\nRun started; prerequisites pending.\n' > "$report"
for dependency in python3 go openssl uv sha256sum git; do
    if ! command -v "$dependency" >/dev/null 2>&1; then
        printf '\n**FAIL:** missing executable `%s`.\n' "$dependency" >> "$report"
        exit 1
    fi
done
export GOCACHE=${GOCACHE:-/tmp/release-signer-go-cache}
export UV_CACHE_DIR=${UV_CACHE_DIR:-/tmp/release-signer-uv-cache}
export PYTHONDONTWRITEBYTECODE=1
python3 test/interop/check.py init "$report" "$work"
profile=all
direction=environment

# tangkap exit code asli (termasuk reject yang diharapkan), tanpa pipeline atau `! cmd` yang menutupi
expect() {
    expected=$1
    shift
    if "$@" > "$work/command.out" 2> "$work/command.err"; then
        actual=0
    else
        actual=$?
    fi
    cat "$work/command.out" "$work/command.err" > "$work/command.log"
    python3 test/interop/check.py record "$report" "$work" "$profile" "$direction" \
        "$expected" "$actual" "$work/command.log" "$@"
    if [ "$actual" -ne "$expected" ]; then
        printf 'FAIL: %s / %s: expected exit %s, got %s; see %s\n' \
            "$profile" "$direction" "$expected" "$actual" "$report" >&2
        exit 1
    fi
}

openssl_verify() {
    expected_rc=$1
    signature_path=$2
    set -- openssl pkeyutl -verify -pubin -inkey "$d/key.pub.pem" -rawin \
        -in "$d/manifest.bin" -sigfile "$signature_path"
    case "$profile" in
        rsa-pss-sha256)
            set -- "$@" -digest sha256 -pkeyopt rsa_padding_mode:pss \
                -pkeyopt rsa_pss_saltlen:32 -pkeyopt rsa_mgf1_md:sha256 ;;
        ecdsa-p256-sha256) set -- "$@" -digest sha256 ;;
        ed25519) ;;
    esac
    expect "$expected_rc" "$@"
}

cli_verify() {
    expected_rc=$1
    expected_status=$2
    bundle_path=$3
    expect "$expected_rc" "$work/release-signer" verify --file "$work/artifact.bin" \
        --bundle "$bundle_path" --trust-store "$d/trust.json" \
        --package interop --version 1.0.0 --json
    cp "$work/command.out" "$d/verify.json"
    expect 0 python3 test/interop/check.py verify-json "$d/verify.json" \
        "$expected_status" "$profile" "$d/public.sha256"
}

fingerprint() {
    # dua command dicek terpisah supaya exit code proses pertama tidak hilang seperti di pipeline
    expect 0 openssl pkey -pubin -in "$d/key.pub.pem" -outform DER -out "$d/public.der"
    expect 0 sha256sum "$d/public.der"
    cp "$work/command.out" "$d/public.sha256"
    expect 0 python3 test/interop/check.py fingerprint "$d/public.sha256" "$d/bundle.json" "$d/identity.txt"
}

expect 0 go version
expect 0 openssl version -a
expect 0 uv --version
expect 0 python3 --version
expect 0 uv run --with cryptography==50.0.2 python test/interop/py_sign.py --crypto-version
expect 0 go build -trimpath -o "$work/release-signer" ./cmd/release-signer
printf 'Independent interoperability fixture\n\000\377\001\002\r\n' > "$work/artifact.bin"

for profile in rsa-pss-sha256 ecdsa-p256-sha256 ed25519; do
    printf 'Checking %s interoperability...\n' "$profile"
    direction='A: CLI -> OpenSSL'
    d="$work/$profile-cli"
    mkdir "$d"
    expect 0 "$work/release-signer" keygen --algorithm "$profile" --out "$d/key"
    cp "$work/command.out" "$d/identity.txt"
    expect 0 "$work/release-signer" sign --file "$work/artifact.bin" --package interop \
        --version 1.0.0 --key "$d/key.key.pem" --out "$d/bundle.json"
    expect 0 python3 test/interop/check.py extract "$d/bundle.json" "$d"
    fingerprint
    openssl_verify 0 "$d/signature.bin"
    direction='A: corrupted signature -> OpenSSL (must exit 1)'
    openssl_verify 1 "$d/corrupt.bin"

    direction='B: OpenSSL / Python -> CLI'
    d="$work/$profile-openssl"
    mkdir "$d"
    case "$profile" in
        rsa-pss-sha256)
            expect 0 openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:3072 \
                -pkeyopt rsa_keygen_pubexp:65537 -out "$d/key.key.pem" ;;
        ecdsa-p256-sha256)
            expect 0 openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 \
                -pkeyopt ec_param_enc:named_curve -out "$d/key.key.pem" ;;
        ed25519) expect 0 openssl genpkey -algorithm ED25519 -out "$d/key.key.pem" ;;
    esac
    expect 0 openssl pkey -in "$d/key.key.pem" -pubout -out "$d/key.pub.pem"
    expect 0 uv run --with cryptography==50.0.2 python test/interop/py_sign.py \
        --algorithm "$profile" --key "$d/key.key.pem" --file "$work/artifact.bin" \
        --package interop --version 1.0.0 --out "$d/bundle.json"
    cp "$work/command.out" "$d/identity.txt"
    expect 0 python3 test/interop/check.py extract "$d/bundle.json" "$d"
    fingerprint
    expect 0 "$work/release-signer" trust add --key "$d/key.pub.pem" --package interop --store "$d/trust.json"
    cp "$work/command.out" "$d/trust.txt"
    expect 0 python3 test/interop/check.py trust-fingerprint "$d/trust.txt" "$d/public.sha256" "$profile"
    cli_verify 0 OK "$d/bundle.json"
    direction='B: corrupted Python signature -> CLI (must exit 1)'
    cli_verify 1 INVALID_SIGNATURE "$d/corrupt.bundle.json"

    direction='C: CLI signs OpenSSL key -> CLI / OpenSSL'
    expect 0 "$work/release-signer" sign --file "$work/artifact.bin" --package interop \
        --version 1.0.0 --key "$d/key.key.pem" --out "$d/cli.bundle.json"
    cli_verify 0 OK "$d/cli.bundle.json"
    expect 0 python3 test/interop/check.py extract "$d/cli.bundle.json" "$d"
    expect 0 python3 test/interop/check.py fingerprint "$d/public.sha256" "$d/cli.bundle.json" "$d/identity.txt"
    openssl_verify 0 "$d/signature.bin"
done
finished=true
printf 'PASS: all interoperability checks; report: %s\n' "$report"
