#!/usr/bin/env python3

import pathlib
import sys
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import native_go_build


class NativeGoBuildTest(unittest.TestCase):
    def test_command_is_native_and_cold_cache(self):
        cmd = native_go_build.build_carrick_command(
            pathlib.Path("/repo"), "perf-test-1"
        )

        rendered = "\0".join(cmd)
        self.assertIn("--exec-backend\0native", rendered)
        self.assertIn('GOCACHE="/tmp/gc-$CARRICK_RUN_ID"', rendered)
        self.assertNotIn("docker", rendered.lower())

    def test_five_sample_median_is_middle_value(self):
        self.assertEqual(native_go_build.median_ms([21, 18, 30, 19, 20]), 20)


if __name__ == "__main__":
    unittest.main()
