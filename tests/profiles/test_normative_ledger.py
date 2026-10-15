"""Keep normative traceability links bound to declared host tests."""

import json
from pathlib import Path
import re
import unittest


ROOT = Path(__file__).resolve().parents[2]
LEDGER = ROOT / "dev" / "DMP_Normative_Cases.json"


class NormativeLedgerCrosswalkTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.cases = json.loads(LEDGER.read_text(encoding="utf-8"))["cases"]

    def assert_declared_test_reference(self, case_id, field, reference):
        self.assertIsInstance(reference, str, f"{case_id}.{field} must be a string")
        self.assertIn("::", reference, f"{case_id}.{field} must name file::symbol")
        relative_path, symbol = reference.split("::", 1)
        path = (ROOT / relative_path).resolve()
        try:
            path.relative_to(ROOT.resolve())
        except ValueError:
            self.fail(f"{case_id}.{field} escapes the repository: {reference}")
        self.assertTrue(path.is_file(), f"{case_id}.{field} file is missing: {reference}")

        parts = symbol.split(".")
        name = parts[-1]
        source = path.read_text(encoding="utf-8", errors="replace")
        if path.suffix == ".py":
            declaration = rf"(?m)^\s*(?:async\s+)?def\s+{re.escape(name)}\s*\("
            self.assertRegex(source, declaration, f"{case_id}.{field}: {reference}")
            if len(parts) > 1:
                class_declaration = rf"(?m)^\s*class\s+{re.escape(parts[0])}\b"
                self.assertRegex(source, class_declaration,
                                 f"{case_id}.{field}: {reference}")
        elif path.suffix == ".c":
            declaration = (
                rf"(?m)^\s*(?:(?:static|inline|extern)\s+)*"
                rf"(?:[A-Za-z_]\w*\s+|\*\s*)+\*?\s*{re.escape(name)}\s*\("
            )
            self.assertRegex(source, declaration, f"{case_id}.{field}: {reference}")
        else:
            self.fail(f"{case_id}.{field} uses an unsupported source file: {reference}")

    def test_all_normative_rows_resolve_primary_peer_and_interop_tests(self):
        case_ids = [case["id"] for case in self.cases]
        self.assertEqual(137, len(case_ids), "update this gate with the normative ledger")
        self.assertEqual(len(case_ids), len(set(case_ids)), "normative case IDs must be unique")

        for case in self.cases:
            with self.subTest(case=case["id"]):
                for field in ("primary_test_id", "peer_test_id"):
                    self.assert_declared_test_reference(case["id"], field, case[field])
                for field in ("primary_checks", "peer_checks", "interop_checks"):
                    for reference in case.get(field) or []:
                        self.assert_declared_test_reference(case["id"], field, reference)
                if case.get("interop_result") == "passed":
                    self.assertTrue(case.get("interop_checks"),
                                    "passed interop evidence must name executable checks")
                if case.get("interop_result") == "not-applicable":
                    self.assertTrue(case.get("interop_evidence"),
                                    "not-applicable interop evidence must state its scope")


if __name__ == "__main__":
    unittest.main()
