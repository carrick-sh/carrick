#!/usr/bin/env python3

import os
import re
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
LAUNCHER = ROOT / "scripts" / "lint-domains.sh"
TYPED_CONFIG = ROOT / ".semgrep" / "typed-domains.yml"
ESCAPE_CONFIG = ROOT / ".semgrep" / "host-authority-escape-hatches.yml"


class HostAuthorityEscapeHatchTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        subprocess.run(
            ["git", "init", "-q"], cwd=self.root, check=True, capture_output=True
        )
        (self.root / ".semgrep").mkdir()
        shutil.copy2(TYPED_CONFIG, self.root / ".semgrep" / TYPED_CONFIG.name)
        if not ESCAPE_CONFIG.is_file():
            self.fail(
                "required escape-hatch rules are missing: "
                ".semgrep/host-authority-escape-hatches.yml"
            )
        shutil.copy2(ESCAPE_CONFIG, self.root / ".semgrep" / ESCAPE_CONFIG.name)

        self.cert = Path("/etc/ssl/cert.pem")
        self.assertTrue(self.cert.is_file(), "real Semgrep tests require /etc/ssl/cert.pem")
        self.log = self.root / "semgrep.log"

    def run_lint(self, files: dict[str, str]) -> subprocess.CompletedProcess[str]:
        for relative, body in files.items():
            path = self.root / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(body, encoding="utf-8")

        env = os.environ.copy()
        env.update(
            {
                "SSL_CERT_FILE": str(self.cert),
                "SEMGREP_LOG_FILE": str(self.log),
            }
        )
        return subprocess.run(
            [str(LAUNCHER)],
            cwd=self.root,
            env=env,
            text=True,
            capture_output=True,
        )

    def assert_rejected(self, body: str) -> None:
        result = self.run_lint({"crates/fixture/src/lib.rs": body})
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertRegex(
            result.stdout + result.stderr,
            re.compile(r"compiler\s+host-\s*authority\s+catalog"),
        )

    def test_rejects_raw_libc_syscall(self):
        self.assert_rejected(
            "pub unsafe fn call() { let _ = libc::syscall(libc::SYS_getpid); }\n"
        )

    def test_rejects_dynamic_symbol_lookup(self):
        for operation in ("dlopen", "dlsym"):
            with self.subTest(operation=operation):
                self.assert_rejected(
                    f"pub unsafe fn call(p: *const i8) {{ let _ = libc::{operation}(p); }}\n"
                )

    def test_rejects_inline_assembly(self):
        for macro_call in (
            'core::arch::asm!("nop")',
            'core::arch::global_asm!(".text")',
        ):
            with self.subTest(macro_call=macro_call):
                self.assert_rejected(f"pub unsafe fn call() {{ {macro_call}; }}\n")

    def test_rejects_local_host_api_declarations(self):
        declarations = {
            "waitpid": "fn waitpid(pid: i32, status: *mut i32, options: i32) -> i32;",
            "kill": "fn kill(pid: i32, signal: i32) -> i32;",
            "open": "fn open(path: *const i8, flags: i32, ...) -> i32;",
            "fork": "fn fork() -> i32;",
        }
        for operation, declaration in declarations.items():
            with self.subTest(operation=operation):
                self.assert_rejected(f'unsafe extern "C" {{ {declaration} }}\n')

    def test_ignores_comments_strings_and_catalog_covered_safe_rust(self):
        result = self.run_lint(
            {
                "crates/fixture/src/lib.rs": r'''
// libc::syscall and core::arch::asm!("nop") are documentation only.
// unsafe extern "C" { fn waitpid(pid: i32) -> i32; }
pub fn safe() -> u32 {
    let _description = "extern \"C\" { fn waitpid(); } libc::dlsym";
    std::process::id()
}
'''
            }
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_checked_boundary_modules_are_path_specific_exemptions(self):
        result = self.run_lint(
            {
                "crates/carrick-portable/src/lib.rs": (
                    "pub unsafe fn call() { let _ = libc::syscall(1); }\n"
                ),
                "crates/carrick-dsr-aarch64/src/emit.rs": (
                    'pub unsafe fn emit() { core::arch::asm!("nop"); }\n'
                ),
                "crates/carrick-host/src/host_proc.rs": (
                    'unsafe extern "C" { fn mach_vm_region(task: i32) -> i32; }\n'
                ),
            }
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_launcher_requires_each_checked_semgrep_config(self):
        for config_name in (TYPED_CONFIG.name, ESCAPE_CONFIG.name):
            with self.subTest(config=config_name):
                config = self.root / ".semgrep" / config_name
                config.unlink()
                result = self.run_lint(
                    {"crates/fixture/src/lib.rs": "pub fn safe() {}\n"}
                )
                self.assertNotEqual(result.returncode, 0)
                self.assertIn(
                    f"error: required Semgrep config is missing: .semgrep/{config_name}",
                    result.stderr,
                )
                shutil.copy2(ROOT / ".semgrep" / config_name, config)


if __name__ == "__main__":
    unittest.main()
