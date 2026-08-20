#!/usr/bin/env python3

"""Run the checked Rust token helper and enforce exact escape-boundary paths.

The standalone proc_macro2 helper owns all Rust tokenization. This wrapper only
runs the locked/offline helper, validates its deterministic JSON interface,
applies exact PurePosixPath allowlists, and renders fail-closed diagnostics.
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from pathlib import Path, PurePosixPath


REPO_ROOT = Path(__file__).resolve().parents[2]
HELPER_MANIFEST = (
    REPO_ROOT / "scripts" / "tools" / "host-authority-escape-syntax" / "Cargo.toml"
)
HELPER_TARGET_DIR = REPO_ROOT / "target" / "host-authority-escape-syntax"
REPLACEMENT = (
    "add a named operation to the compiler host-authority catalog or route it "
    "through the typed host-capability facade"
)

RAW_SYSCALL_BOUNDARIES = frozenset(
    {
        PurePosixPath("crates/carrick-portable/src/lib.rs"),
        PurePosixPath("crates/carrick-vmm-kvm/src/kvm_aarch64_engine.rs"),
        PurePosixPath("crates/carrick-aarch64/src/engine.rs"),
        PurePosixPath("crates/carrick-host/src/netbsd_futex.rs"),
        PurePosixPath("crates/carrick-host-linux/src/epoll_mux.rs"),
        PurePosixPath("crates/carrick-host/src/shared_word.rs"),
        PurePosixPath("crates/carrick-vmm-nvmm/src/nvmm.rs"),
        PurePosixPath("crates/carrick-vmm-bhyve/fixtures/bhyve-asyncsig/src/main.rs"),
        PurePosixPath("crates/carrick-vmm-bhyve/fixtures/bhyve-fork-raw/src/main.rs"),
        PurePosixPath("crates/carrick-vmm-bhyve/fixtures/bhyve-vfork-exec/src/main.rs"),
        PurePosixPath("crates/carrick-vmm-bhyve/fixtures/bhyve-vfork-exit/src/main.rs"),
    }
)

ASSEMBLY_BOUNDARIES = frozenset(
    {
        PurePosixPath("crates/carrick-dsr-aarch64/src/counter.rs"),
        PurePosixPath("crates/carrick-dsr-aarch64/src/emit.rs"),
        PurePosixPath("crates/carrick-dsr-x86/src/gateway.rs"),
        PurePosixPath("crates/carrick-dsr-x86/tests/fixtures/computeloop.rs"),
        PurePosixPath("crates/carrick-dsr-x86/tests/fixtures/tinyguest.rs"),
        PurePosixPath("crates/carrick-native-darwin/src/direct.rs"),
        PurePosixPath("crates/carrick-runtime/tools/vdso_getrandom_blob.rs"),
        PurePosixPath("crates/carrick-vmm-bhyve/fixtures/bhyve-fpsignal/src/main.rs"),
        PurePosixPath("crates/carrick-vmm-bhyve/fixtures/bhyve-sigfpe/src/main.rs"),
        PurePosixPath("crates/carrick-vmm-bhyve/fixtures/bhyve-sigill/src/main.rs"),
        PurePosixPath("crates/carrick-vmm-bhyve/fixtures/bhyve-sigsegv-default/src/main.rs"),
        PurePosixPath("crates/carrick-vmm-bhyve/fixtures/bhyve-sigsegv-gp/src/main.rs"),
        PurePosixPath("crates/carrick-vmm-bhyve/fixtures/bhyve-sigsegv/src/main.rs"),
        PurePosixPath("crates/carrick-vmm-hvf/src/trap/sysreg.rs"),
        PurePosixPath("crates/carrick-vmm-kvm/src/guest_setup.rs"),
        PurePosixPath("crates/carrick-vmm-kvm/src/kvm.rs"),
    }
)

EXPECTED_FIELDS = {"path", "line", "column", "kind", "detail"}
KIND_ORDER = {
    "libc_syscall": 0,
    "libc_dlopen": 1,
    "libc_dlsym": 2,
    "assembly": 3,
    "extern": 4,
}


class ScanError(RuntimeError):
    pass


def _helper_command(root: Path) -> list[str]:
    return [
        "cargo",
        "run",
        "--quiet",
        "--locked",
        "--offline",
        "--manifest-path",
        str(HELPER_MANIFEST),
        "--",
        "--format",
        "json",
        "--root",
        str(root),
    ]


def _run_helper(root: Path) -> list[dict[str, object]]:
    environment = os.environ.copy()
    environment["CARGO_NET_OFFLINE"] = "true"
    environment["CARGO_TARGET_DIR"] = str(HELPER_TARGET_DIR)
    try:
        completed = subprocess.run(
            _helper_command(root),
            cwd=REPO_ROOT,
            env=environment,
            text=True,
            capture_output=True,
        )
    except OSError as error:
        raise ScanError(f"cannot launch checked Rust token helper: {error}") from error
    if completed.returncode != 0:
        detail = completed.stderr.strip() or completed.stdout.strip() or "no diagnostic"
        raise ScanError(
            f"checked Rust token helper exited {completed.returncode}: {detail}"
        )

    rows: list[dict[str, object]] = []
    identities: set[tuple[object, ...]] = set()
    for line_number, line in enumerate(completed.stdout.splitlines(), 1):
        if not line:
            raise ScanError(f"helper emitted blank JSON line {line_number}")
        try:
            row = json.loads(line)
        except json.JSONDecodeError as error:
            raise ScanError(f"helper emitted malformed JSON line {line_number}: {error}") from error
        if not isinstance(row, dict) or set(row) != EXPECTED_FIELDS:
            raise ScanError(f"helper JSON line {line_number} has wrong schema")
        path = row["path"]
        source_line = row["line"]
        column = row["column"]
        kind = row["kind"]
        detail = row["detail"]
        if not isinstance(path, str):
            raise ScanError(f"helper JSON line {line_number} has non-string path")
        relative = PurePosixPath(path)
        if (
            relative.is_absolute()
            or ".." in relative.parts
            or not relative.parts
            or relative.parts[0] != "crates"
            or relative.as_posix() != path
        ):
            raise ScanError(f"helper JSON line {line_number} has unsafe path: {path!r}")
        if (
            not isinstance(source_line, int)
            or isinstance(source_line, bool)
            or source_line < 1
            or not isinstance(column, int)
            or isinstance(column, bool)
            or column < 1
        ):
            raise ScanError(f"helper JSON line {line_number} has invalid location")
        if not isinstance(kind, str) or kind not in KIND_ORDER:
            raise ScanError(f"helper JSON line {line_number} has unknown kind: {kind!r}")
        if not isinstance(detail, str) or not detail:
            raise ScanError(f"helper JSON line {line_number} has invalid detail")
        identity = (path, KIND_ORDER[kind], source_line, column, detail)
        if identity in identities:
            raise ScanError(f"helper emitted duplicate finding on JSON line {line_number}")
        identities.add(identity)
        rows.append(row)

    ordering = [
        (
            row["path"],
            KIND_ORDER[str(row["kind"])],
            row["line"],
            row["column"],
            row["detail"],
        )
        for row in rows
    ]
    if ordering != sorted(ordering):
        raise ScanError("helper findings are not deterministically ordered")
    return rows


def _is_reviewed_boundary(path: PurePosixPath, kind: str) -> bool:
    if kind == "libc_syscall":
        return path in RAW_SYSCALL_BOUNDARIES
    if kind == "assembly":
        return path in ASSEMBLY_BOUNDARIES
    return False


def scan_tree(root: Path) -> list[str]:
    findings: list[str] = []
    for row in _run_helper(root):
        path = PurePosixPath(str(row["path"]))
        kind = str(row["kind"])
        if _is_reviewed_boundary(path, kind):
            continue
        findings.append(
            f"{path}:{row['line']}:{row['column']}: error: {row['detail']} "
            f"bypasses resolved review; {REPLACEMENT}"
        )
    return findings


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path.cwd())
    args = parser.parse_args(argv)
    root = args.root.resolve()
    try:
        findings = scan_tree(root)
    except ScanError as error:
        print(f"error: host-authority escape scan failed closed: {error}", file=sys.stderr)
        return 2
    if findings:
        for finding in findings:
            print(finding, file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
