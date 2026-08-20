#!/usr/bin/env python3

import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts" / "lint-domains.sh"


class LintDomainsTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.capture = self.root / "capture.json"
        self.cert = self.root / "cert.pem"
        self.cert.write_text("fixture certificate bundle\n", encoding="utf-8")
        self.fake = self.root / "semgrep"
        self.fake.write_text(
            "#!/usr/bin/env python3\n"
            "import json, os, pathlib, sys\n"
            "pathlib.Path(os.environ['CAPTURE']).write_text(json.dumps({\n"
            "  'argv': sys.argv[1:],\n"
            "  'ssl': os.environ.get('SSL_CERT_FILE'),\n"
            "  'log': os.environ.get('SEMGREP_LOG_FILE'),\n"
            "  'log_contents': pathlib.Path(os.environ['SEMGREP_LOG_FILE']).read_text(),\n"
            "  'metrics': os.environ.get('SEMGREP_SEND_METRICS'),\n"
            "  'version_check': os.environ.get('SEMGREP_ENABLE_VERSION_CHECK'),\n"
            "  'otel': os.environ.get('OTEL_SDK_DISABLED'),\n"
            "}))\n"
            "raise SystemExit(int(os.environ.get('FAKE_STATUS', '0')))\n",
            encoding="utf-8",
        )
        self.fake.chmod(0o755)

    def tearDown(self):
        self.temp.cleanup()

    def run_launcher(self, status="0", log_file=None):
        if not SCRIPT.is_file():
            self.fail("required launcher is missing: scripts/lint-domains.sh")
        env = os.environ.copy()
        env.update(
            {
                "SEMGREP_BIN": str(self.fake),
                "SSL_CERT_FILE": str(self.cert),
                "CAPTURE": str(self.capture),
                "FAKE_STATUS": status,
            }
        )
        if log_file is not None:
            env["SEMGREP_LOG_FILE"] = str(log_file)
        else:
            env.pop("SEMGREP_LOG_FILE", None)
        return subprocess.run(
            [str(SCRIPT)], cwd=ROOT, env=env, text=True, capture_output=True
        )

    def test_launcher_is_offline_and_uses_explicit_writable_paths(self):
        log_file = self.root / "semgrep.log"
        result = self.run_launcher(log_file=log_file)
        self.assertEqual(result.returncode, 0)
        capture = json.loads(self.capture.read_text(encoding="utf-8"))
        self.assertEqual(capture["ssl"], str(self.cert))
        self.assertEqual(capture["log"], str(log_file))
        self.assertEqual(capture["metrics"], "off")
        self.assertEqual(capture["version_check"], "0")
        self.assertEqual(capture["otel"], "true")
        self.assertEqual(
            capture["argv"],
            ["--config", ".semgrep/", "crates/", "--severity", "ERROR", "--error", "--quiet"],
        )

    def test_launcher_preserves_semgrep_failure(self):
        self.assertEqual(
            self.run_launcher("7", self.root / "semgrep.log").returncode, 7
        )

    def test_launcher_does_not_truncate_explicit_log_before_semgrep_runs(self):
        log_file = self.root / "semgrep.log"
        log_file.write_text("sentinel log content\n", encoding="utf-8")
        result = self.run_launcher(log_file=log_file)
        self.assertEqual(result.returncode, 0)
        capture = json.loads(self.capture.read_text(encoding="utf-8"))
        self.assertEqual(capture["log_contents"], "sentinel log content\n")

    def test_launcher_rejects_unwritable_log_path_before_running_semgrep(self):
        log_file = self.root / "missing-parent" / "semgrep.log"
        result = self.run_launcher(log_file=log_file)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("error: cannot write semgrep log file:", result.stderr)
        self.assertFalse(self.capture.exists())

    def test_launcher_removes_default_temporary_log_directory(self):
        inherited_log_file = self.root / "inherited.log"
        previous_log_file = os.environ.get("SEMGREP_LOG_FILE")
        os.environ["SEMGREP_LOG_FILE"] = str(inherited_log_file)
        try:
            result = self.run_launcher()
        finally:
            if previous_log_file is None:
                os.environ.pop("SEMGREP_LOG_FILE", None)
            else:
                os.environ["SEMGREP_LOG_FILE"] = previous_log_file
        self.assertEqual(result.returncode, 0)
        capture = json.loads(self.capture.read_text(encoding="utf-8"))
        self.assertNotEqual(capture["log"], str(inherited_log_file))
        self.assertFalse(Path(capture["log"]).parent.exists())


if __name__ == "__main__":
    unittest.main()
