"""Compile the generated C profile hashes through the production memcpy shape."""

import hashlib
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[2]
EMBEDDED = ROOT / "tests" / "embedded" / "espnow_dmp"
PROFILE_DIR = ROOT / "profiles" / "deployments"
PROFILE_NAMES = (
    "test-direct-sample-retry-2-nnpsk0.json",
    "test-direct-multi-peer-nnpsk0.json",
)


def _compiler() -> str:
    configured = os.environ.get("CC")
    if configured:
        return configured
    found = shutil.which("gcc") or shutil.which("cc")
    if found:
        return found
    windows_gcc = Path("C:/develop/mingw/w64devkit/bin/gcc.exe")
    if windows_gcc.is_file():
        return str(windows_gcc)
    raise AssertionError("a host C compiler (CC, gcc, or cc) is required")


class EmbeddedProfileHashTests(unittest.TestCase):
    def test_generated_arrays_compile_and_match_exact_manifest_digests(self):
        expected = "".join(
            hashlib.sha256((PROFILE_DIR / name).read_bytes()).hexdigest()
            for name in PROFILE_NAMES
        )
        (ROOT / "build").mkdir(exist_ok=True)
        with tempfile.TemporaryDirectory(prefix="dmp-profile-hash-", dir=ROOT / "build") as temp:
            exe = Path(temp) / ("profile_hashes.exe" if os.name == "nt" else "profile_hashes")
            subprocess.run(
                [
                    _compiler(), "-std=c11", "-Wall", "-Wextra", "-Wpedantic", "-Werror",
                    "-I", str(EMBEDDED), str(EMBEDDED / "profile_hashes_compile.c"),
                    "-o", str(exe),
                ],
                check=True,
                cwd=ROOT,
                capture_output=True,
                text=True,
            )
            actual = subprocess.run(
                [str(exe)], check=True, capture_output=True, text=True, cwd=ROOT
            ).stdout.strip()
        self.assertEqual(actual, expected)
