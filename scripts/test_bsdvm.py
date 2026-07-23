#!/usr/bin/env python3

import importlib.util
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

SCRIPT = Path(__file__).with_name("bsdvm.py")
SPEC = importlib.util.spec_from_file_location("bsdvm", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
BSDVM = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = BSDVM
SPEC.loader.exec_module(BSDVM)


class ConfigTests(unittest.TestCase):
    def test_inventory_matches_spec(self) -> None:
        self.assertEqual(sorted(BSDVM.VMS), ["freebsd-arm64", "netbsd-arm64"])
        fb = BSDVM.VMS["freebsd-arm64"]
        nb = BSDVM.VMS["netbsd-arm64"]
        self.assertEqual(fb.ssh_port, 2201)
        self.assertEqual(nb.ssh_port, 2202)
        self.assertEqual(fb.remote, "fbsd-arm")
        self.assertEqual(nb.remote, "nbsd-arm")
        # NetBSD non-login ssh PATH gotcha must be baked into config.
        self.assertIn("/usr/pkg/bin", nb.remote_path_prefix)
        self.assertEqual(fb.remote_path_prefix, "")

    def test_state_dir_env_override(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            with mock.patch.dict(os.environ, {"CARRICK_BSDVM_STATE": td}):
                d = BSDVM.state_dir("freebsd-arm64")
                self.assertEqual(d, Path(td) / "freebsd-arm64")

    def test_state_dir_default_is_under_home(self) -> None:
        env = {k: v for k, v in os.environ.items() if k != "CARRICK_BSDVM_STATE"}
        with mock.patch.dict(os.environ, env, clear=True):
            self.assertEqual(
                BSDVM.state_root(), Path.home() / ".carrick" / "bsdvm"
            )

    def test_unknown_vm_is_an_error(self) -> None:
        rc = BSDVM.main(["ps", "no-such-vm"])
        self.assertEqual(rc, 2)


if __name__ == "__main__":
    unittest.main()
