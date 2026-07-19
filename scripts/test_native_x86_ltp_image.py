#!/usr/bin/env python3

import importlib.util
from pathlib import Path
import stat
import sys
import tempfile
import unittest

SCRIPT = Path(__file__).with_name("native-x86-ltp-image.py")
SPEC = importlib.util.spec_from_file_location("native_x86_ltp_image", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
IMAGE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = IMAGE
SPEC.loader.exec_module(IMAGE)


class NativeX86LtpImageTests(unittest.TestCase):
    def test_prepares_flat_scratch_context_and_hash_manifest(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            ltp = root / "ltp"
            rootfs = root / "prepared"
            context = root / "context"
            (ltp / "getpid").mkdir(parents=True)
            (ltp / "uname").mkdir(parents=True)
            (rootfs / "bin").mkdir(parents=True)
            context.mkdir()
            for path, content in (
                (ltp / "getpid/getpid01", b"getpid"),
                (ltp / "uname/uname01", b"uname"),
                (rootfs / "bin/sh", b"shell"),
                (rootfs / "bin/zcat", b"zcat"),
            ):
                path.write_bytes(content)
                path.chmod(path.stat().st_mode | stat.S_IXUSR)

            manifest = IMAGE.prepare_context(context, ltp, rootfs)

            self.assertEqual(sorted(manifest["binaries_sha256"]), ["getpid01", "uname01"])
            self.assertTrue((context / "rootfs/opt/ltp/testcases/bin/getpid01").is_file())
            self.assertTrue((context / "rootfs/bin/zcat").is_file())
            self.assertIn('CMD ["/opt/ltp/testcases/bin/getpid01"]', (context / "Dockerfile").read_text())

    def test_rejects_duplicate_flattened_names(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for area in ("one", "two"):
                path = root / area / "same"
                path.parent.mkdir()
                path.write_bytes(b"x")
                path.chmod(path.stat().st_mode | stat.S_IXUSR)
            with self.assertRaisesRegex(ValueError, "duplicate"):
                IMAGE.executable_files(root)


if __name__ == "__main__":
    unittest.main()
