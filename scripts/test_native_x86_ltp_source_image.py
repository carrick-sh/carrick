#!/usr/bin/env python3

import contextlib
import importlib.util
import io
from pathlib import Path
import subprocess
import sys
import tarfile
import tempfile
import unittest

SCRIPT = Path(__file__).with_name("native-x86-ltp-source-image.py")
SPEC = importlib.util.spec_from_file_location("native_x86_ltp_source_image", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
IMAGE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = IMAGE
SPEC.loader.exec_module(IMAGE)


class NativeX86LtpSourceImageTests(unittest.TestCase):
    def test_builder_keeps_artifacts_out_of_carrick_tar_mount(self) -> None:
        dockerfile = SCRIPT.parent.parent / "docker/ltp-native-musl/Dockerfile"
        contents = dockerfile.read_text(encoding="utf-8")
        self.assertIn("COPY ltp.tar /tmp/ltp.tar", contents)
        self.assertIn("mkdir -p /artifact/", contents)
        self.assertIn("COPY --from=builder /artifact /", contents)
        self.assertIn("linux-libc-dev", contents)
        self.assertIn("/usr/include/x86_64-linux-musl/linux", contents)
        self.assertIn("/usr/include/x86_64-linux-musl/asm-generic", contents)
        self.assertIn("ARG LTP_BUILD_JOBS=8", contents)
        self.assertIn('make -C /src/lib -j"${LTP_BUILD_JOBS}"', contents)
        self.assertIn("for lib in ipc newipc numa sigwait swap vdso", contents)
        self.assertIn("/tmp/ltp-build-leaves", contents)
        self.assertIn('if ! make -C "$dir" -j1', contents)
        self.assertNotIn("make -C testcases/kernel/syscalls -k", contents)
        self.assertNotIn("mkdir -p /out/", contents)

    def test_build_jobs_are_bounded_positive_values(self) -> None:
        default = IMAGE.parse_args(["--ltp-source", "/tmp/source"])
        self.assertEqual(default.jobs, 8)
        explicit = IMAGE.parse_args(["--ltp-source", "/tmp/source", "--jobs", "4"])
        self.assertEqual(explicit.jobs, 4)
        with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
            IMAGE.parse_args(["--ltp-source", "/tmp/source", "--jobs", "0"])

    def test_archive_output_is_explicit_and_optional(self) -> None:
        default = IMAGE.parse_args(["--ltp-source", "/tmp/source"])
        self.assertIsNone(default.archive)
        explicit = IMAGE.parse_args(
            ["--ltp-source", "/tmp/source", "--archive", "/tmp/image.tar"]
        )
        self.assertEqual(explicit.archive, Path("/tmp/image.tar"))

    def test_archive_output_is_forwarded_to_carrick_build(self) -> None:
        command = IMAGE.carrick_build_command(
            Path("/opt/carrick"),
            tag="ltp:test",
            dns="1.1.1.1",
            jobs=4,
            context=Path("/tmp/context"),
            archive=Path("/tmp/image.tar"),
        )
        self.assertIn("--output", command)
        self.assertEqual(command[command.index("--output") + 1], "/tmp/image.tar")
        self.assertEqual(command[-1], "/tmp/context")

    def test_archives_the_requested_pinned_ref(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "source"
            output = root / "ltp.tar"
            source.mkdir()
            subprocess.run(["git", "init", "-q", str(source)], check=True)
            subprocess.run(
                ["git", "-C", str(source), "config", "user.email", "test@example.invalid"],
                check=True,
            )
            subprocess.run(
                ["git", "-C", str(source), "config", "user.name", "Carrick Test"],
                check=True,
            )
            (source / "version").write_text("pinned\n", encoding="utf-8")
            subprocess.run(["git", "-C", str(source), "add", "version"], check=True)
            subprocess.run(["git", "-C", str(source), "commit", "-qm", "fixture"], check=True)
            subprocess.run(["git", "-C", str(source), "tag", "pinned"], check=True)
            (source / "version").write_text("working tree\n", encoding="utf-8")

            IMAGE.archive_source(source, "pinned", output)

            with tarfile.open(output) as archive:
                archived = archive.extractfile("version")
                assert archived is not None
                self.assertEqual(archived.read(), b"pinned\n")


if __name__ == "__main__":
    unittest.main()
