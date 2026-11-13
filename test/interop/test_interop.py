"""Boundary and fault-injection tests for the test-only interoperability tools."""

import json
import os
from pathlib import Path
import shlex
import shutil
import subprocess
import sys
import tempfile
import unittest

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa, utils

import check
import py_sign

ROOT = Path(__file__).resolve().parents[2]


class ByteAndAssertionTests(unittest.TestCase):
    def test_unsigned_der_integers_at_padding_boundaries(self):
        for r, s in ((0, 0), (1, 127), (128, 255), (2**255, 2**256 - 1)):
            with self.subTest(r=r, s=s):
                raw = r.to_bytes(32, "big") + s.to_bytes(32, "big")
                # Decode with an independent ASN.1 implementation.
                self.assertEqual(utils.decode_dss_signature(check.raw_to_der(raw)), (r, s))

    def test_wrong_raw_lengths_rejected(self):
        for size in (0, 63, 65, 72):
            with self.assertRaises(ValueError):
                check.raw_to_der(b"\x01" * size)

    def test_verify_assertion_rejects_string_boolean_and_wrong_identity(self):
        with tempfile.TemporaryDirectory(prefix="interop-assert-", dir="/tmp") as tmp:
            root = Path(tmp)
            fingerprint = root / "hash"
            fingerprint.write_text("a" * 64 + "  public.der\n")
            result_path = root / "verify.json"
            for change in ({"valid": "true"}, {"keyid": "b" * 64}, {"status": "INVALID_SIGNATURE"}, {"algorithm": "rsa-pss-sha256"}):
                result = {"valid": True, "status": "OK", "algorithm": "ed25519", "keyid": "a" * 64}
                result.update(change)
                result_path.write_text(json.dumps(result))
                with self.subTest(change=change), self.assertRaises(AssertionError):
                    check.verify_json(result_path, "OK", "ed25519", fingerprint)

    def test_trust_assertion_rejects_wrong_identity_or_scope(self):
        with tempfile.TemporaryDirectory(prefix="interop-trust-", dir="/tmp") as tmp:
            root = Path(tmp)
            fingerprint = root / "hash"
            fingerprint.write_text("a" * 64 + "  public.der\n")
            entry = root / "entry"
            for keyid, package in (("b" * 64, "interop"), ("a" * 64, "other")):
                entry.write_text(f"keyid={keyid} algorithm=ed25519 packages={package}\n")
                with self.assertRaises(AssertionError):
                    check.trust_fingerprint(entry, fingerprint, "ed25519")


class SignerNegativeTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="interop-signer-", dir="/tmp")
        self.addCleanup(self.tmp.cleanup)
        self.directory = Path(self.tmp.name)
        self.artifact = self.directory / "artifact.bin"
        self.artifact.write_bytes(b"\0\xffartifact\n")
        self.key_path = self.directory / "private.pem"
        self.write_key(ed25519.Ed25519PrivateKey.generate())

    def write_key(self, key):
        self.key_path.write_bytes(key.private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        ))
        self.key_path.chmod(0o600)

    def test_mismatched_key_profiles_rejected(self):
        for profile in ("rsa-pss-sha256", "ecdsa-p256-sha256", "unsupported"):
            with self.subTest(profile=profile), self.assertRaises(ValueError):
                py_sign.sign_bundle(profile, self.key_path, self.artifact, "interop", "1.0.0")

    def test_disallowed_key_parameters_rejected(self):
        for profile, key in (
            ("rsa-pss-sha256", rsa.generate_private_key(public_exponent=65537, key_size=2048)),
            ("ecdsa-p256-sha256", ec.generate_private_key(ec.SECP384R1())),
        ):
            self.write_key(key)
            with self.subTest(profile=profile), self.assertRaises(ValueError):
                py_sign.sign_bundle(profile, self.key_path, self.artifact, "interop", "1.0.0")

    def test_metadata_rejects_escape_and_unicode_inputs(self):
        for package, version in (("bad\"name", "1"), ("interop", "1\n"), ("\u0131nterop", "1"), ("interop", "1\\x")):
            with self.subTest(package=package, version=version), self.assertRaises(ValueError):
                py_sign.sign_bundle("ed25519", self.key_path, self.artifact, package, version)

    def test_existing_bundle_preserved_and_private_key_parse_failure_sanitized(self):
        output = self.directory / "bundle.json"
        output.write_text("preserve existing output")
        command = [sys.executable, str(ROOT / "test/interop/py_sign.py"), "--algorithm", "ed25519", "--key", str(self.key_path), "--file", str(self.artifact), "--package", "interop", "--version", "1", "--out", str(output)]
        result = subprocess.run(command, text=True, capture_output=True, check=False)
        self.assertEqual(result.returncode, 2)
        self.assertEqual(output.read_text(), "preserve existing output")
        self.key_path.write_text("-----BEGIN PRIVATE KEY-----\nPRIVATE-SENTINEL\n-----END PRIVATE KEY-----")
        result = subprocess.run(command, text=True, capture_output=True, check=False)
        self.assertEqual(result.returncode, 2)
        self.assertNotIn("PRIVATE-SENTINEL", result.stdout + result.stderr)
        self.assertNotIn("BEGIN PRIVATE", result.stdout + result.stderr)


class RunnerFaultTests(unittest.TestCase):
    def test_unexpected_acceptance_and_infrastructure_error_fail_runner(self):
        real_openssl = shutil.which("openssl")
        self.assertIsNotNone(real_openssl)
        for injected_rc in (0, 2):
            with self.subTest(injected_rc=injected_rc), tempfile.TemporaryDirectory(prefix="interop-fault-", dir="/tmp") as tmp:
                directory = Path(tmp)
                wrapper = directory / "openssl"
                wrapper.write_text(
                    "#!/bin/sh\n"
                    "for argument do\n"
                    "  case $argument in\n"
                    "    */corrupt.bin)\n"
                    f"      printf '%s\\n' \"${{argument%/*}}\" > {shlex.quote(str(directory / 'trace'))}\n"
                    "      printf '%s\\n' '-----BEGIN PRIVATE KEY-----' 'PRIVATE-SENTINEL' '-----END PRIVATE KEY-----' >&2\n"
                    f"      exit {injected_rc} ;;\n"
                    "  esac\n"
                    "done\n"
                    f"exec {shlex.quote(real_openssl)} \"$@\"\n"
                )
                wrapper.chmod(0o700)
                env = dict(os.environ, PATH=str(directory) + os.pathsep + os.environ["PATH"], INTEROP_RESULTS_DIR=str(directory / "results"))
                result = subprocess.run(["sh", "test/interop/run.sh"], cwd=ROOT, env=env, text=True, capture_output=True, check=False, timeout=180)
                self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
                report = (directory / "results/results.md").read_text()
                self.assertIn("**FAIL**", report)
                self.assertIn("**Overall: FAIL**", report)
                self.assertIn(f"| 1 | {injected_rc} | **FAIL**", report)
                self.assertIn("[private key redacted]", report)
                self.assertNotIn("PRIVATE-SENTINEL", report)
                self.assertNotIn("BEGIN PRIVATE", report)
                work = Path((directory / "trace").read_text().strip()).parent
                self.assertEqual(work.parent, Path("/tmp"))
                self.assertTrue(work.name.startswith("release-signer-interop."))
                self.assertFalse(work.exists(), "runner left its private-key directory behind")


if __name__ == "__main__":
    unittest.main()
