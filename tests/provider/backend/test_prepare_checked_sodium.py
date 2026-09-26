"""Focused safety and determinism tests for checked sodium preparation."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import tempfile
import unittest

from prepare_checked_sodium import PreparationError, TARGETS, _prepare


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


class PrepareCheckedSodiumTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory(prefix="prepare-checked-sodium-test-")
        self.root = Path(self.temp.name)
        self.source = self.root / "source"
        self.output = self.root / "generated"
        self.patch = self.root / "checked-init.patch"
        self.inputs = self.root / "inputs.json"
        self.originals = {
            TARGETS[0]: b"int sodium_init(void) { return 0; }\r\n",
            TARGETS[1]: b"void randombytes_stir(void) {}\r\n",
        }
        for name, contents in self.originals.items():
            path = self.source / Path(name)
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(contents)
        self._write_inputs()
        self._write_patch(
            {
                TARGETS[0]: b"int sodium_init(void) { return checked_startup(); }\n",
                TARGETS[1]: b"int randombytes_stir_checked(void) { return checked_stir(); }\n",
            }
        )

    def tearDown(self) -> None:
        self.temp.cleanup()

    def _write_inputs(self) -> None:
        self.inputs.write_text(
            json.dumps({
                "files": {
                    name: digest(contents.replace(b"\r\n", b"\n"))
                    for name, contents in self.originals.items()
                },
                "hash_normalization": "crlf-to-lf",
            }),
            encoding="utf-8",
        )

    def _write_patch(self, replacements: dict[str, bytes]) -> None:
        chunks: list[str] = []
        for name in TARGETS:
            old = self.originals[name].replace(b"\r\n", b"\n").decode("utf-8").rstrip("\n")
            new = replacements[name].decode("utf-8").rstrip("\n")
            chunks.extend((
                f"--- a/{name}",
                f"+++ b/{name}",
                "@@ -1 +1 @@",
                f"-{old}",
                f"+{new}",
            ))
        self.patch.write_bytes(("\n".join(chunks) + "\n").encode("utf-8"))

    def prepare(self) -> dict[str, object]:
        return _prepare(self.source, self.output, self.patch, self.inputs)

    def test_tampered_source_is_rejected_without_materialization(self) -> None:
        path = self.source / Path(TARGETS[0])
        path.write_bytes(b"tampered\n")

        with self.assertRaisesRegex(PreparationError, "hash mismatch"):
            self.prepare()

        self.assertFalse(self.output.exists())
        self.assertEqual(path.read_bytes(), b"tampered\n")

    def test_invalid_patch_leaves_source_and_output_untouched(self) -> None:
        self.patch.write_text("not a unified diff\n", encoding="utf-8")

        with self.assertRaises(PreparationError):
            self.prepare()

        self.assertFalse(self.output.exists())
        for name, contents in self.originals.items():
            self.assertEqual((self.source / Path(name)).read_bytes(), contents)

    def test_success_is_idempotent_and_records_hashes(self) -> None:
        report = self.prepare()
        first_bytes = {
            name: (self.output / Path(name)).read_bytes()
            for name in TARGETS
        }
        report_bytes = (self.output / "preparation.json").read_bytes()

        second_report = self.prepare()

        self.assertEqual(report, second_report)
        self.assertEqual(report["source_hashes"], {name: digest(data) for name, data in self.originals.items()})
        self.assertEqual(report["normalized_source_hashes"], {
            name: digest(data.replace(b"\r\n", b"\n"))
            for name, data in self.originals.items()
        })
        self.assertEqual(report["source_hash_normalization"], "crlf-to-lf")
        self.assertEqual(report["patch_sha256"], digest(self.patch.read_bytes()))
        self.assertEqual(report["output_hashes"], {name: digest(data) for name, data in first_bytes.items()})
        self.assertEqual(report["temporary_source_line_endings"], "CRLF normalized to LF")
        self.assertEqual(json.loads(report_bytes.decode("utf-8")), report)
        self.assertEqual({name: (self.output / Path(name)).read_bytes() for name in TARGETS}, first_bytes)
        for name, contents in self.originals.items():
            self.assertEqual((self.source / Path(name)).read_bytes(), contents)

    def test_lf_and_crlf_variants_match_same_normalized_pin(self) -> None:
        for name, contents in self.originals.items():
            (self.source / Path(name)).write_bytes(contents.replace(b"\r\n", b"\n"))

        report = self.prepare()

        self.assertEqual(report["source_hash_normalization"], "crlf-to-lf")
        self.assertEqual(report["normalized_source_hashes"], {
            name: digest(contents.replace(b"\r\n", b"\n"))
            for name, contents in self.originals.items()
        })
        self.assertEqual(report["source_hashes"], {
            name: digest(contents.replace(b"\r\n", b"\n"))
            for name, contents in self.originals.items()
        })
        for name, contents in self.originals.items():
            self.assertEqual((self.source / Path(name)).read_bytes(), contents.replace(b"\r\n", b"\n"))

    def test_output_may_not_overlap_source(self) -> None:
        with self.assertRaisesRegex(PreparationError, "separate from the source"):
            _prepare(self.source, self.source / "generated", self.patch, self.inputs)

    def test_hard_linked_output_and_report_preserve_source(self) -> None:
        generated_core = self.output / Path(TARGETS[0])
        generated_core.parent.mkdir(parents=True)
        report_path = self.output / "preparation.json"
        source_core = self.source / Path(TARGETS[0])
        source_utils = self.source / Path(TARGETS[1])
        try:
            os.link(source_core, generated_core)
            os.link(source_utils, report_path)
        except (OSError, NotImplementedError) as exc:
            self.skipTest(f"hard links unavailable: {exc}")

        report = self.prepare()

        self.assertFalse(os.path.samefile(source_core, generated_core))
        self.assertFalse(os.path.samefile(source_utils, report_path))
        self.assertEqual(json.loads(report_path.read_text(encoding="utf-8")), report)
        for name, contents in self.originals.items():
            self.assertEqual((self.source / Path(name)).read_bytes(), contents)
        self.assertEqual(digest(generated_core.read_bytes()), report["output_hashes"][TARGETS[0]])

    def test_output_symlink_cannot_redirect_materialization(self) -> None:
        output_sodium = self.output / "libsodium" / "src" / "libsodium" / "sodium"
        output_sodium.parent.mkdir(parents=True)
        try:
            output_sodium.symlink_to((self.source / Path(TARGETS[0])).parent, target_is_directory=True)
        except (OSError, NotImplementedError) as exc:
            self.skipTest(f"directory symlinks unavailable: {exc}")

        with self.assertRaisesRegex(PreparationError, "symlink"):
            self.prepare()

        self.assertEqual((self.source / Path(TARGETS[0])).read_bytes(), self.originals[TARGETS[0]])
        self.assertEqual((self.source / Path(TARGETS[1])).read_bytes(), self.originals[TARGETS[1]])
        self.assertFalse((self.source / "preparation.json").exists())


if __name__ == "__main__":
    unittest.main()
