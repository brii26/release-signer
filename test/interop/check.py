#!/usr/bin/env python3
"""Standard-library byte extraction, assertions, and sanitized report writer."""

import base64
from datetime import datetime, timezone
import hashlib
import html
import json
from pathlib import Path
import platform
import re
import shlex
import subprocess
import sys


def raw_to_der(raw):
    if len(raw) != 64:
        raise ValueError("ECDSA signature must contain exactly 64 bytes")

    def integer(part):
        part = part.lstrip(b"\0") or b"\0"
        if part[0] & 128:
            part = b"\0" + part
        return b"\x02" + bytes([len(part)]) + part

    sequence = integer(raw[:32]) + integer(raw[32:])
    return b"\x30" + bytes([len(sequence)]) + sequence


def extract(bundle_path, directory):
    bundle = json.loads(Path(bundle_path).read_text())
    manifest = base64.b64decode(bundle["manifest_b64"], validate=True)
    signature = base64.b64decode(bundle["signature_b64"], validate=True)
    algorithm = json.loads(manifest)["algorithm"]
    expected_length = {"rsa-pss-sha256": 384, "ecdsa-p256-sha256": 64, "ed25519": 64}[algorithm]
    assert len(signature) == expected_length, "unexpected signature length"
    directory = Path(directory)
    # Preserve the decoded bytes exactly, without parsing/reserializing the manifest.
    (directory / "manifest.bin").write_bytes(manifest)
    (directory / "signature.raw").write_bytes(signature)
    corrupted = bytearray(signature)
    corrupted[-1] ^= 1
    for name, value in (("signature.bin", signature), ("corrupt.bin", bytes(corrupted))):
        (directory / name).write_bytes(raw_to_der(value) if algorithm == "ecdsa-p256-sha256" else value)
    bundle["signature_b64"] = base64.b64encode(corrupted).decode("ascii")
    (directory / "corrupt.bundle.json").write_text(json.dumps(bundle) + "\n", encoding="ascii")
    print(f"original manifest preserved ({len(manifest)} bytes); signature {len(signature)} bytes; flipped final signature bit")


def fingerprint(hash_path, bundle_path, identity_path):
    expected = Path(hash_path).read_text().split()[0]
    assert re.fullmatch("[0-9a-f]{64}", expected), "invalid sha256sum output"
    manifest = json.loads(base64.b64decode(json.loads(Path(bundle_path).read_text())["manifest_b64"], validate=True))
    assert manifest["keyid"] == expected, "bundle keyid differs from OpenSSL DER fingerprint"
    assert Path(identity_path).read_text().strip() == expected, "producer keyid differs from OpenSSL DER fingerprint"
    print(f"keygen/signer keyid = bundle keyid = sha256(OpenSSL DER SPKI) = {expected}")


def verify_json(path, status, algorithm, hash_path):
    result = json.loads(Path(path).read_text())
    assert result["valid"] is (status == "OK"), "unexpected valid value"
    assert result["status"] == status, "unexpected status"
    assert result["algorithm"] == algorithm, "unexpected algorithm"
    assert result["keyid"] == Path(hash_path).read_text().split()[0], "unexpected verifier keyid"
    print(f"valid={str(result['valid']).lower()}, status={result['status']}, algorithm={algorithm}")


def trust_fingerprint(path, hash_path, algorithm):
    expected = Path(hash_path).read_text().split()[0]
    expected_entry = f"keyid={expected} algorithm={algorithm} packages=interop"
    assert Path(path).read_text().strip() == expected_entry, "trust add identity differs from OpenSSL fingerprint/profile/package"
    print(f"trust add keyid = sha256(OpenSSL DER SPKI) = {expected}; algorithm={algorithm}; packages=interop")


def sanitized(text, work):
    text = re.sub(r"-----BEGIN [^-]*PRIVATE KEY-----.*?(?:-----END [^-]*PRIVATE KEY-----|\Z)", "[private key redacted]", text, flags=re.S)
    text = text.replace(work, "$TMP")
    # Strip terminal/control characters and bound failure output.
    return "".join(c for c in text if c in "\n\t" or c.isprintable())[:4000]


def report_init(path, work):
    revision = subprocess.check_output(["git", "rev-parse", "HEAD"], text=True).strip()
    dirty = subprocess.check_output([
        "git", "status", "--porcelain", "--untracked-files=normal", "--", ".", ":(exclude)results/interop"
    ], text=True).strip()
    scripts = sorted(Path("test/interop").glob("*.py")) + [Path("test/interop/run.sh")]
    lines = [
        "# OpenSSL / Python interoperability results", "",
        f"- UTC: {datetime.now(timezone.utc).isoformat(timespec='seconds')}",
        f"- Source revision: `{revision}`; source tree {'dirty' if dirty else 'clean'} at start (generated results excluded).",
        f"- Platform: `{platform.platform()}`; machine: `{platform.machine()}`.",
        "- Invocation: `make interop`; private keys, binary and artifact exist only in a cleaned `/tmp` directory.",
        "- Test dependencies only: OpenSSL, Python, uv and cryptography==50.0.2. The CLI build has no such runtime dependency.",
        "- `$TMP` below replaces this run's temporary directory; shell arguments are quoted for replay.",
        "- Fingerprint oracle: `openssl pkey -pubin -in pub.pem -outform DER | sha256sum`, run in two checked commands to avoid hidden pipeline failures.",
        "- A: CLI-generated keys / CLI signatures -> OpenSSL. B: OpenSSL keys / independent Python signatures -> CLI. C: OpenSSL keys / CLI signatures -> CLI and OpenSSL.",
        "- ECDSA extraction preserves raw r||s and converts each integer to unsigned DER for OpenSSL; manifests retain their original decoded bytes.", "",
        "Script SHA-256 (identifies the exact runner even before a results commit):", "",
    ]
    lines += [f"- `{p}`: `{hashlib.sha256(p.read_bytes()).hexdigest()}`" for p in scripts]
    lines += ["", "| Profile | Direction / check | Command | Expected exit | Actual exit | Result / observed output |", "| --- | --- | --- | --- | --- | --- |"]
    Path(path).write_text("\n".join(lines) + "\n", encoding="utf-8")


def record(args):
    path, work, profile, direction, expected, actual, output, *command = args
    passed = expected == actual
    # Commands only write private keys to files, never stdout. Still redact PEM on failures.
    observed = sanitized(Path(output).read_text(errors="replace"), work).strip()
    if passed and command[:2] == ["openssl", "genpkey"]:
        observed = "key-generation progress omitted"
    cmd = sanitized(shlex.join(command), work)
    def cell(value):
        return html.escape(value).replace("|", "&#124;").replace("`", "&#96;").replace("\n", "<br>")
    with Path(path).open("a", encoding="utf-8") as report:
        report.write(f"| {cell(profile)} | {cell(direction)} | <code>{cell(cmd)}</code> | {expected} | {actual} | **{'PASS' if passed else 'FAIL'}** {cell(observed)} |\n")


def main():
    action, *args = sys.argv[1:]
    if action == "extract":
        extract(*args)
    elif action == "fingerprint":
        fingerprint(*args)
    elif action == "verify-json":
        verify_json(*args)
    elif action == "trust-fingerprint":
        trust_fingerprint(*args)
    elif action == "init":
        report_init(*args)
    elif action == "record":
        record(args)
    else:
        raise ValueError("unknown check")


if __name__ == "__main__":
    main()
