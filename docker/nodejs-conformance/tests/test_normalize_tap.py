#!/usr/bin/env python3
import importlib.util
from pathlib import Path
import unittest


NORMALIZER = Path(__file__).resolve().parents[1] / "normalize-tap.py"
SPEC = importlib.util.spec_from_file_location("normalize_tap", NORMALIZER)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)
normalize = MODULE.normalize


class NormalizeTapTests(unittest.TestCase):
    def test_preserves_existing_tap_without_temp_path(self):
        got = normalize(
            "node-core", 0, "TAP version 13\n1..1\nok 1 - test-a\n"
        )
        self.assertEqual(got, "TAP version 13\n1..1\nok 1 - test-a\n")
        self.assertNotIn("/tmp/", got)

    def test_plain_smoke_is_one_tap_assertion(self):
        self.assertEqual(
            normalize("v8-smoke", 0, "v8-smoke ok\n"),
            "TAP version 13\n1..1\nok 1 - v8-smoke\n",
        )

    def test_plain_failure_is_one_failed_tap_assertion(self):
        self.assertEqual(
            normalize("app-smoke", 1, "boom\n"),
            "TAP version 13\n1..1\nnot ok 1 - app-smoke\n# boom\n",
        )


if __name__ == "__main__":
    unittest.main()
