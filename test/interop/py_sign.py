#!/usr/bin/env python3
"""Independent test-only bundle producer; run with cryptography==50.0.2."""

import argparse
import base64
import hashlib
import json
from pathlib import Path
import re

import cryptography
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, padding, rsa, utils

PROFILES = ("rsa-pss-sha256", "ecdsa-p256-sha256", "ed25519")


def sign_bundle(algorithm, key_path, artifact_path, package, version):
    artifact_path = Path(artifact_path)
    for value, pattern in (
        (package, r"[a-z0-9][a-z0-9._-]{0,63}"),
        (version, r"[A-Za-z0-9][A-Za-z0-9._+-]{0,63}"),
        (artifact_path.name, r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}"),
    ):
        if re.fullmatch(pattern, value, flags=re.ASCII) is None:
            raise ValueError("metadata does not satisfy manifest syntax")
    key = serialization.load_pem_private_key(Path(key_path).read_bytes(), password=None)
    if algorithm == "rsa-pss-sha256":
        if not isinstance(key, rsa.RSAPrivateKey) or key.key_size != 3072:
            raise ValueError("RSA profile requires a 3072-bit RSA key")
        if key.public_key().public_numbers().e != 65537:
            raise ValueError("RSA profile requires exponent 65537")
    elif algorithm == "ecdsa-p256-sha256":
        if not isinstance(key, ec.EllipticCurvePrivateKey) or not isinstance(key.curve, ec.SECP256R1):
            raise ValueError("ECDSA profile requires P-256")
    elif algorithm == "ed25519":
        if not isinstance(key, ed25519.Ed25519PrivateKey):
            raise ValueError("Ed25519 profile requires an Ed25519 key")
    else:
        raise ValueError("unsupported profile")

    spki = key.public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    keyid = hashlib.sha256(spki).hexdigest()
    digest = hashlib.sha256()
    size = 0
    with artifact_path.open("rb") as artifact:
        for chunk in iter(lambda: artifact.read(1024 * 1024), b""):
            size += len(chunk)
            digest.update(chunk)
    if size > 2**53 - 1:
        raise ValueError("artifact size exceeds JSON safe integer limit")
    # Dict insertion order fixes every field, including the nested artifact.
    # No CLI or project package is used to construct these signed bytes.
    manifest = json.dumps({
        "schema": "minisign-manifest/v1",
        "package": package,
        "version": version,
        "algorithm": algorithm,
        "keyid": keyid,
        "artifact": {"name": artifact_path.name, "size": size, "sha256": digest.hexdigest()},
    }, ensure_ascii=True, separators=(",", ":")).encode("ascii")
    if algorithm == "rsa-pss-sha256":
        signature = key.sign(manifest, padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=32), hashes.SHA256())
    elif algorithm == "ecdsa-p256-sha256":
        r, s = utils.decode_dss_signature(key.sign(manifest, ec.ECDSA(hashes.SHA256())))
        signature = r.to_bytes(32, "big") + s.to_bytes(32, "big")
    else:
        signature = key.sign(manifest)
    return {
        "schema": "minisign-bundle/v1",
        "manifest_b64": base64.b64encode(manifest).decode("ascii"),
        "signature_b64": base64.b64encode(signature).decode("ascii"),
    }, keyid


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--crypto-version", action="version", version=cryptography.__version__)
    parser.add_argument("--algorithm", choices=PROFILES, required=True)
    parser.add_argument("--key", type=Path, required=True)
    parser.add_argument("--file", type=Path, required=True)
    parser.add_argument("--package", required=True)
    parser.add_argument("--version", required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    try:
        bundle, keyid = sign_bundle(args.algorithm, args.key, args.file, args.package, args.version)
        with args.out.open("x", encoding="ascii") as output:
            output.write(json.dumps(bundle, indent=2) + "\n")
    except (ValueError, OSError) as error:
        # Key parsing exceptions can contain input details; never log the PEM.
        parser.exit(2, f"independent signer failed ({type(error).__name__})\n")
    print(keyid)


if __name__ == "__main__":
    main()
