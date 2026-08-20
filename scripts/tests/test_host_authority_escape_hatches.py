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
CHECKED_FIXTURES = ROOT / "scripts" / "tests" / "fixtures" / "host-authority-escape-syntax"
REJECT_FIXTURES = ("imports.rs", "macros.rs", "externs.rs")
SAFE_FIXTURE = "safe.rs"


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

    def run_lint(
        self,
        files: dict[str, str],
        semgrep_bin: Path | None = None,
        extra_env: dict[str, str] | None = None,
    ) -> subprocess.CompletedProcess[str]:
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
        if semgrep_bin is not None:
            env["SEMGREP_BIN"] = str(semgrep_bin)
        if extra_env is not None:
            env.update(extra_env)
        return subprocess.run(
            [str(LAUNCHER)],
            cwd=self.root,
            env=env,
            text=True,
            capture_output=True,
        )

    def run_escape_semgrep_only(
        self, files: dict[str, str]
    ) -> subprocess.CompletedProcess[str]:
        shutil.rmtree(self.root / "crates", ignore_errors=True)
        for relative, body in files.items():
            path = self.root / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(body, encoding="utf-8")
        env = os.environ.copy()
        env.update(
            {
                "SSL_CERT_FILE": str(self.cert),
                "SEMGREP_LOG_FILE": str(self.log),
                "SEMGREP_SEND_METRICS": "off",
                "SEMGREP_ENABLE_VERSION_CHECK": "0",
                "OTEL_SDK_DISABLED": "true",
            }
        )
        return subprocess.run(
            [
                "semgrep",
                "--config",
                ".semgrep/host-authority-escape-hatches.yml",
                "crates/",
                "--severity",
                "ERROR",
                "--error",
                "--quiet",
            ],
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

    def test_checked_fixtures_are_valid_rust_and_rustfmt_clean(self):
        fixtures = (*REJECT_FIXTURES, SAFE_FIXTURE)
        with tempfile.TemporaryDirectory() as output_dir:
            for index, name in enumerate(fixtures):
                with self.subTest(name=name):
                    source = CHECKED_FIXTURES / name
                    self.assertTrue(source.is_file(), f"missing checked fixture: {source}")
                    rustfmt = subprocess.run(
                        ["rustfmt", "--check", "--edition", "2024", str(source)],
                        text=True,
                        capture_output=True,
                    )
                    self.assertEqual(
                        rustfmt.returncode, 0, rustfmt.stdout + rustfmt.stderr
                    )
                    rustc = subprocess.run(
                        [
                            "rustc",
                            "--crate-name",
                            f"host_authority_escape_fixture_{index}",
                            "--crate-type",
                            "lib",
                            "--edition",
                            "2024",
                            "--emit",
                            "metadata",
                            "--out-dir",
                            output_dir,
                            str(source),
                        ],
                        text=True,
                        capture_output=True,
                    )
                    self.assertEqual(rustc.returncode, 0, rustc.stdout + rustc.stderr)

    def test_checked_reject_fixtures_are_denied_and_safe_fixture_is_clean(self):
        for name in REJECT_FIXTURES:
            with self.subTest(name=name):
                shutil.rmtree(self.root / "crates", ignore_errors=True)
                body = (CHECKED_FIXTURES / name).read_text(encoding="utf-8")
                self.assert_rejected(body)
        shutil.rmtree(self.root / "crates", ignore_errors=True)
        safe = (CHECKED_FIXTURES / SAFE_FIXTURE).read_text(encoding="utf-8")
        result = self.run_lint({"crates/fixture/src/lib.rs": safe})
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

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

    def test_rejects_assembly_import_aliases(self):
        fixtures = (
            'use core::arch::asm; pub unsafe fn call() { asm!("nop"); }\n',
            'use core::arch::{asm, global_asm}; global_asm!(".text");\n',
            (
                'use core::arch::asm as carrier_asm; '
                'pub unsafe fn call() { carrier_asm!("nop"); }\n'
            ),
            (
                'use core::arch::{global_asm as carrier_global_asm}; '
                'carrier_global_asm!(".text");\n'
            ),
        )
        for body in fixtures:
            with self.subTest(body=body):
                self.assert_rejected(body)

    def test_rejects_escape_hatches_inside_macro_rules(self):
        fixtures = (
            'macro_rules! call { () => { core::arch::asm!("nop") }; }\n',
            'macro_rules! call { () => { asm!("nop") }; }\n',
            'macro_rules! call { () => { core::arch::global_asm!(".text") }; }\n',
            (
                'macro_rules! call { () => { unsafe { '
                'libc::syscall(libc::SYS_getpid) } }; }\n'
            ),
            'macro_rules! call { () => { unsafe { libc::dlopen(0 as _) } }; }\n',
            'macro_rules! call { () => { unsafe { libc::dlsym(0 as _, 0 as _) } }; }\n',
        )
        for body in fixtures:
            with self.subTest(body=body):
                self.assert_rejected(body)

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

    def test_rejects_local_host_api_declaration_variants(self):
        fixtures = (
            'unsafe extern { fn waitpid(pid: i32) -> i32; }\n',
            'unsafe extern "C-unwind" { fn kill(pid: i32, signal: i32) -> i32; }\n',
            (
                'unsafe extern "C" { #[link_name = "waitpid"] '
                'fn carrier_wait(pid: i32) -> i32; }\n'
            ),
            (
                'macro_rules! declare_wait { () => { unsafe extern "C" { '
                'fn waitpid(pid: i32) -> i32; } }; }\n'
            ),
        )
        for body in fixtures:
            with self.subTest(body=body):
                self.assert_rejected(body)

    def test_ignores_comments_strings_and_catalog_covered_safe_rust(self):
        result = self.run_lint(
            {
                "crates/fixture/src/lib.rs": r'''
// libc::syscall and core::arch::asm!("nop") are documentation only.
// unsafe extern "C" { fn waitpid(pid: i32) -> i32; }
pub fn safe() -> u32 {
    let _description = "extern \"C\" { fn waitpid(); } libc::dlsym";
    let _raw = r###"libc::syscall(1); core::arch::global_asm!(\"x\")"###;
    std::process::id()
}

pub trait SafeTrait {
    fn waitpid(&self, pid: i32) -> i32;
}

macro_rules! documentation_only {
    () => {{
        // unsafe extern "C-unwind" { fn kill(pid: i32); }
        "#[link_name = \"waitpid\"] fn renamed(); asm!(\"nop\")"
    }};
}

macro_rules! compiler_catalog_owned {
    () => {{ std::process::id() }};
}
'''
            }
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_launcher_propagates_supplemental_checker_failure(self):
        fake_semgrep = self.root / "semgrep-success"
        fake_semgrep.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
        fake_semgrep.chmod(0o755)
        result = self.run_lint(
            {
                "crates/fixture/src/lib.rs": (
                    'macro_rules! hidden { () => { unsafe { '
                    'libc::syscall(1) } }; }\n'
                )
            },
            semgrep_bin=fake_semgrep,
        )
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn("libc::syscall bypasses resolved review", result.stderr)

    def test_launcher_propagates_helper_tokenization_failure(self):
        fake_semgrep = self.root / "semgrep-success"
        fake_semgrep.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
        fake_semgrep.chmod(0o755)
        result = self.run_lint(
            {"crates/fixture/src/lib.rs": "fn broken( {\n"},
            semgrep_bin=fake_semgrep,
        )
        self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
        self.assertIn("Rust tokenization failed", result.stderr)

    def test_launcher_propagates_helper_build_failure(self):
        fake_semgrep = self.root / "semgrep-success"
        fake_semgrep.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
        fake_semgrep.chmod(0o755)
        result = self.run_lint(
            {"crates/fixture/src/lib.rs": "pub fn safe() {}\n"},
            semgrep_bin=fake_semgrep,
            extra_env={"RUSTC": str(self.root / "missing-rustc")},
        )
        self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
        self.assertIn("checked Rust token helper exited", result.stderr)

    def test_nested_suffix_lookalikes_do_not_inherit_boundary_exclusions(self):
        fixtures = {
            "crates/nested/crates/carrick-portable/src/lib.rs": (
                "pub unsafe fn call() { let _ = libc::syscall(1); }\n"
            ),
            "crates/nested/crates/carrick-dsr-aarch64/src/emit.rs": (
                'pub unsafe fn emit() { core::arch::asm!("nop"); }\n'
            ),
        }
        for relative, body in fixtures.items():
            with self.subTest(relative=relative):
                result = self.run_lint({relative: body})
                self.assertNotEqual(
                    result.returncode,
                    0,
                    f"nested suffix path inherited an exact boundary: {relative}",
                )
                self.assertRegex(
                    result.stdout + result.stderr,
                    re.compile(r"compiler\s+host-\s*authority\s+catalog"),
                )

    def test_semgrep_boundary_exclusions_are_root_anchored(self):
        cases = (
            (
                "crates/carrick-portable/src/lib.rs",
                "pub unsafe fn call() { let _ = libc::syscall(1); }\n",
                0,
            ),
            (
                "crates/nested/crates/carrick-portable/src/lib.rs",
                "pub unsafe fn call() { let _ = libc::syscall(1); }\n",
                1,
            ),
            (
                "crates/carrick-dsr-aarch64/src/emit.rs",
                'pub unsafe fn emit() { core::arch::asm!("nop"); }\n',
                0,
            ),
            (
                "crates/nested/crates/carrick-dsr-aarch64/src/emit.rs",
                'pub unsafe fn emit() { core::arch::asm!("nop"); }\n',
                1,
            ),
        )
        for relative, body, expected_status in cases:
            with self.subTest(relative=relative):
                result = self.run_escape_semgrep_only({relative: body})
                self.assertEqual(
                    result.returncode,
                    expected_status,
                    result.stdout + result.stderr,
                )

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
