#!/usr/bin/env python3

"""Fail closed when product execution can escape the one-carrier process model.

The checked Rust helper supplies syntax-aware, alias-aware findings and omits
`cfg(test)` items. This wrapper owns repository topology: product execution,
the four exact carrier-birth operations, and explicit operator/probe surfaces
are intentionally separate classifications.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
import tomllib
from dataclasses import dataclass
from pathlib import Path, PurePosixPath


REPO_ROOT = Path(__file__).resolve().parents[2]
HELPER_MANIFEST = (
    REPO_ROOT / "scripts" / "tools" / "host-authority-escape-syntax" / "Cargo.toml"
)
HELPER_TARGET_DIR = REPO_ROOT / "target" / "host-authority-escape-syntax"

CREATION_KINDS = frozenset(
    {
        "fork",
        "vfork",
        "posix_spawn",
        "process_command",
        "clone",
        "forkpty",
        "system",
        "popen",
        "daemon",
        "exec",
    }
)
CONTROL_KINDS = frozenset(
    {
        "kill",
        "kill_probe",
        "killpg",
        "pthread_kill",
        "sigqueue",
        "wait",
        "waitpid",
        "wait4",
        "waitid",
        "ptrace",
        "setpgid",
        "setsid",
    }
)
KNOWN_KINDS = CREATION_KINDS | CONTROL_KINDS
KIND_ORDER = {
    kind: index
    for index, kind in enumerate(
        (
            "fork",
            "vfork",
            "posix_spawn",
            "process_command",
            "clone",
            "forkpty",
            "system",
            "popen",
            "daemon",
            "exec",
            "kill",
            "kill_probe",
            "killpg",
            "pthread_kill",
            "sigqueue",
            "wait",
            "waitpid",
            "wait4",
            "waitid",
            "ptrace",
            "setpgid",
            "setsid",
        )
    )
}
EXPECTED_FIELDS = {"path", "line", "column", "kind", "detail", "enclosing_item"}

NON_PRODUCT_CRATES = frozenset({"carrick-conformance", "carrick-test-support"})


def _is_product_source(path: PurePosixPath) -> bool:
    return (
        len(path.parts) >= 4
        and path.parts[0] == "crates"
        and path.parts[2] == "src"
        and path.parts[1] not in NON_PRODUCT_CRATES
    )

REVIEWED_OPERATOR_LIMITS = {
    (PurePosixPath("crates/carrick-cli/src/apfs_operator.rs"), "run_diskutil", "process_command"): 1,
    (PurePosixPath("crates/carrick-cli/src/commands.rs"), "wait_fixture_child", "waitpid"): 1,
    (
        PurePosixPath("crates/carrick-cli/src/commands.rs"),
        "run_native_profile_birth_fixture",
        "fork",
    ): 1,
    (PurePosixPath("crates/carrick-cli/src/debug.rs"), "run_lldb_deadline", "process_command"): 1,
    (PurePosixPath("crates/carrick-cli/src/debug.rs"), "run_lldb_attach", "process_command"): 1,
    (PurePosixPath("crates/carrick-cli/src/debug.rs"), "collect_scoped_processes", "process_command"): 1,
    (PurePosixPath("crates/carrick-cli/src/debug.rs"), "terminate_scoped_run", "process_command"): 1,
    (PurePosixPath("crates/carrick-cli/src/debug.rs"), "dump_lldb", "kill"): 1,
    (PurePosixPath("crates/carrick-cli/src/debug.rs"), "stop_scoped_processes", "kill"): 1,
    (PurePosixPath("crates/carrick-cli/src/debug.rs"), "terminate_scoped_run", "kill"): 3,
    (
        PurePosixPath("crates/carrick-cli/src/native_profile_qualification.rs"),
        "command_output",
        "process_command",
    ): 1,
    (
        PurePosixPath("crates/carrick-cli/src/native_shape_profile.rs"),
        "command_stdout",
        "process_command",
    ): 1,
    (PurePosixPath("crates/carrick-cli/src/quiet_host.rs"), "count_named_processes", "process_command"): 1,
    (
        PurePosixPath("crates/carrick-cli/src/quiet_host.rs"),
        "count_proctitle_processes",
        "process_command",
    ): 1,
    (PurePosixPath("crates/carrick-cli/src/trace_cli.rs"), "exec_trace_under_sudo", "process_command"): 1,
    (PurePosixPath("crates/carrick-cli/src/trace_profile.rs"), "git_dirty", "process_command"): 1,
    (PurePosixPath("crates/carrick-cli/src/trace_profile.rs"), "command_output", "process_command"): 1,
}
REVIEWED_PROBE_LIMITS = {
    (PurePosixPath("crates/carrick-vmm-hvf/src/bin/hvf_fork_probe.rs"), "live_fork", "fork"): 1,
    (PurePosixPath("crates/carrick-vmm-hvf/src/bin/hvf_fork_probe.rs"), "run_fork_churn", "fork"): 1,
    (PurePosixPath("crates/carrick-vmm-hvf/src/bin/hvf_fork_probe.rs"), "fork_churn", "fork"): 1,
    (PurePosixPath("crates/carrick-vmm-hvf/src/bin/hvf_fork_probe.rs"), "parallel_recreate", "fork"): 1,
    (PurePosixPath("crates/carrick-vmm-hvf/src/bin/hvf_fork_probe.rs"), "parent_keeps_vm", "fork"): 1,
    (PurePosixPath("crates/carrick-vmm-hvf/src/bin/hvf_fork_probe.rs"), "concurrent_ceiling", "fork"): 1,
    (PurePosixPath("crates/carrick-vmm-hvf/src/bin/hvf_fork_probe.rs"), "signal_flood", "kill"): 1,
    (PurePosixPath("crates/carrick-vmm-hvf/src/bin/hvf_fork_probe.rs"), "concurrent_ceiling", "kill"): 1,
    (PurePosixPath("crates/carrick-vmm-hvf/src/bin/hvf_fork_probe.rs"), "live_fork", "waitpid"): 1,
    (PurePosixPath("crates/carrick-vmm-hvf/src/bin/hvf_fork_probe.rs"), "run_fork_churn", "waitpid"): 1,
    (PurePosixPath("crates/carrick-vmm-hvf/src/bin/hvf_fork_probe.rs"), "fork_churn", "waitpid"): 1,
    (PurePosixPath("crates/carrick-vmm-hvf/src/bin/hvf_fork_probe.rs"), "parallel_recreate", "waitpid"): 1,
    (PurePosixPath("crates/carrick-vmm-hvf/src/bin/hvf_fork_probe.rs"), "parent_keeps_vm", "waitpid"): 1,
    (PurePosixPath("crates/carrick-vmm-hvf/src/bin/hvf_fork_probe.rs"), "concurrent_ceiling", "waitpid"): 3,
    (
        PurePosixPath("crates/carrick-vmm-hvf/src/bin/hvf_kernel_memory_probe.rs"),
        "command_output",
        "process_command",
    ): 1,
    (PurePosixPath("crates/carrick-vmm-hvf/src/bin/hvf_svc_tax_probe.rs"), "run_ipc_probe", "fork"): 1,
    (PurePosixPath("crates/carrick-vmm-hvf/src/bin/hvf_svc_tax_probe.rs"), "run_ipc_probe", "waitpid"): 1,
}
TEST_SOURCE_PATHS = frozenset(
    {
        PurePosixPath("crates/carrick-runtime/src/dispatch/fs/tests.rs"),
        PurePosixPath("crates/carrick-runtime/src/dispatch/mem/tests.rs"),
        PurePosixPath("crates/carrick-runtime/src/dispatch/tests.rs"),
        PurePosixPath("crates/carrick-runtime/src/file_authority/tests.rs"),
        PurePosixPath("crates/carrick-runtime/src/kernel/tests.rs"),
    }
)
TEST_SOURCE_PARENTS = {
    PurePosixPath("crates/carrick-runtime/src/dispatch/fs/tests.rs"): PurePosixPath(
        "crates/carrick-runtime/src/dispatch/fs.rs"
    ),
    PurePosixPath("crates/carrick-runtime/src/dispatch/mem/tests.rs"): PurePosixPath(
        "crates/carrick-runtime/src/dispatch/mem.rs"
    ),
    PurePosixPath("crates/carrick-runtime/src/dispatch/tests.rs"): PurePosixPath(
        "crates/carrick-runtime/src/dispatch/mod.rs"
    ),
    PurePosixPath("crates/carrick-runtime/src/file_authority/tests.rs"): PurePosixPath(
        "crates/carrick-runtime/src/file_authority/mod.rs"
    ),
    PurePosixPath("crates/carrick-runtime/src/kernel/tests.rs"): PurePosixPath(
        "crates/carrick-runtime/src/kernel/mod.rs"
    ),
}

# Carrier birth is the only product process-creation boundary. Each entry binds
# file + enclosing function + operation, so adding another call in lifecycle.rs
# cannot silently expand the authority surface.
CARRIER_BIRTH_LIMITS = {
    (
        PurePosixPath("crates/carrick-cli/src/lifecycle.rs"),
        "launch",
        "posix_spawn",
    ): 1,
    (
        PurePosixPath("crates/carrick-cli/src/lifecycle.rs"),
        "run_detached_carrier",
        "setsid",
    ): 1,
    (
        PurePosixPath("crates/carrick-cli/src/lifecycle.rs"),
        "await_detached_ready",
        "waitpid",
    ): 1,
    (
        PurePosixPath("crates/carrick-cli/src/lifecycle.rs"),
        "rollback_spawned_carrier",
        "waitpid",
    ): 1,
    (
        PurePosixPath("crates/carrick-cli/src/lifecycle.rs"),
        "rollback_spawned_carrier",
        "kill",
    ): 1,
}

# Signal 0 may authenticate or census the host carrier itself. These are host
# containment/lifecycle substrates; none accept a guest PID. All other direct
# process-control calls in product code are rejected.
CARRIER_SUBSTRATE_LIMITS = {
    (
        PurePosixPath("crates/carrick-native-darwin/src/aot_cache.rs"),
        "claim_recording",
        "kill_probe",
    ): 1,
    (
        PurePosixPath("crates/carrick-portable/src/lib.rs"),
        "ptrace",
        "ptrace",
    ): 3,
    (
        PurePosixPath("crates/carrick-runtime/src/container.rs"),
        "pid_alive",
        "kill_probe",
    ): 1,
    (
        PurePosixPath("crates/carrick-runtime/src/kernel/control/endpoint.rs"),
        "process_is_alive",
        "kill_probe",
    ): 1,
    (
        PurePosixPath("crates/carrick-runtime/src/kernel/debug/endpoint.rs"),
        "process_is_alive",
        "kill_probe",
    ): 1,
    (
        PurePosixPath("crates/carrick-vmm-bhyve/src/vmm.rs"),
        "sweep_dead_vm_nodes",
        "kill_probe",
    ): 1,
    (
        PurePosixPath("crates/carrick-vmm-bhyve/src/bhyve_kicker.rs"),
        "kick",
        "pthread_kill",
    ): 1,
    (
        PurePosixPath("crates/carrick-vmm-kvm/src/kvm_kicker.rs"),
        "kick",
        "pthread_kill",
    ): 1,
    (
        PurePosixPath("crates/carrick-vmm-nvmm/src/nvmm_kicker.rs"),
        "kick",
        "pthread_kill",
    ): 1,
}


class GateError(RuntimeError):
    pass


@dataclass(frozen=True)
class Finding:
    path: PurePosixPath
    line: int
    column: int
    kind: str
    detail: str
    enclosing_item: str


def _under(path: PurePosixPath, prefix: PurePosixPath) -> bool:
    try:
        path.relative_to(prefix)
        return True
    except ValueError:
        return False


def _is_test_or_probe_path(path: PurePosixPath) -> bool:
    parts = path.parts
    return (
        (len(parts) >= 3 and parts[0] == "crates" and parts[2] in {"tests", "fixtures"})
        or path in TEST_SOURCE_PATHS
    )


def classify(finding: Finding) -> str:
    if _is_test_or_probe_path(finding.path):
        return "test_or_probe"
    if (finding.path, finding.enclosing_item, finding.kind) in REVIEWED_PROBE_LIMITS:
        return "probe_tool"
    if (finding.path, finding.enclosing_item, finding.kind) in REVIEWED_OPERATOR_LIMITS:
        return "operator_tool"
    if not _is_product_source(finding.path):
        return "out_of_product_scope"
    identity = (finding.path, finding.enclosing_item, finding.kind)
    if identity in CARRIER_BIRTH_LIMITS:
        return "carrier_birth"
    if identity in CARRIER_SUBSTRATE_LIMITS:
        return "carrier_substrate"
    if finding.kind in CREATION_KINDS:
        return "forbidden_product_process_creation"
    return "forbidden_guest_to_host_process_control"


def cfg_test_includes(parent_source: str, child_name: str) -> bool:
    escaped = re.escape(child_name)
    patterns = (
        rf"#\s*\[\s*cfg\s*\(\s*test\s*\)\s*\]\s*include!\s*\(\s*\"{escaped}\"\s*\)",
        rf"#\s*\[\s*cfg\s*\(\s*test\s*\)\s*\]\s*(?:#\s*\[\s*path\s*=\s*\"{escaped}\"\s*\]\s*)?mod\s+tests\s*;",
    )
    return any(re.search(pattern, parent_source, re.MULTILINE) for pattern in patterns)


def dependency_package_names(
    dependencies: dict[str, object], workspace_dependencies: dict[str, object]
) -> set[str]:
    packages: set[str] = set()
    for alias, declaration in dependencies.items():
        effective = declaration
        if (
            isinstance(declaration, dict)
            and declaration.get("workspace") is True
            and alias in workspace_dependencies
        ):
            effective = workspace_dependencies[alias]
        package = (
            effective.get("package", alias)
            if isinstance(effective, dict)
            else alias
        )
        if isinstance(package, str):
            packages.add(package)
    return packages


def reachability_failures(root: Path) -> list[str]:
    result: list[str] = []
    workspace = tomllib.loads((root / "Cargo.toml").read_text(encoding="utf-8"))
    workspace_dependencies = workspace.get("workspace", {}).get("dependencies", {})
    if set(TEST_SOURCE_PARENTS) != set(TEST_SOURCE_PATHS):
        result.append("error: test_source_proof_catalog_drift")
        return result
    for child, parent in TEST_SOURCE_PARENTS.items():
        child_path = root / child
        parent_path = root / parent
        if not child_path.is_file() or not parent_path.is_file():
            result.append(f"{child}: error: missing_test_source_reachability_input")
            continue
        source = parent_path.read_text(encoding="utf-8")
        child_name = child.relative_to(parent.parent).as_posix()
        if not cfg_test_includes(source, child_name):
            result.append(
                f"{child}: error: test_source_not_proven_cfg_test_only via {parent}"
            )

    probe_paths = {identity[0] for identity in REVIEWED_PROBE_LIMITS}
    for probe in probe_paths:
        if len(probe.parts) < 5 or probe.parts[2:4] != ("src", "bin"):
            result.append(f"{probe}: error: reviewed_probe_is_not_a_bin_target")

    for manifest in sorted((root / "crates").glob("*/Cargo.toml")):
        crate_name = manifest.parent.name
        if crate_name in NON_PRODUCT_CRATES:
            continue
        data = tomllib.loads(manifest.read_text(encoding="utf-8"))
        production_dependencies = dict(data.get("dependencies", {}))
        for target in data.get("target", {}).values():
            if isinstance(target, dict):
                production_dependencies.update(target.get("dependencies", {}))
        leaked = sorted(
            NON_PRODUCT_CRATES
            & dependency_package_names(
                production_dependencies, workspace_dependencies
            )
        )
        for dependency in leaked:
            result.append(
                f"{manifest.relative_to(root)}: error: non_product_crate_reachable_from_product: {dependency}"
            )
    return result


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
        "--mode",
        "carrier-processes",
        "--root",
        str(root),
    ]


def scan(root: Path) -> list[Finding]:
    environment = os.environ.copy()
    environment["CARGO_NET_OFFLINE"] = "true"
    environment["CARGO_TARGET_DIR"] = str(HELPER_TARGET_DIR)
    completed = subprocess.run(
        _helper_command(root),
        cwd=REPO_ROOT,
        env=environment,
        text=True,
        capture_output=True,
    )
    if completed.returncode != 0:
        detail = completed.stderr.strip() or completed.stdout.strip() or "no diagnostic"
        raise GateError(
            f"checked Rust process scanner exited {completed.returncode}: {detail}"
        )

    findings: list[Finding] = []
    identities: set[tuple[object, ...]] = set()
    for output_line, line in enumerate(completed.stdout.splitlines(), 1):
        try:
            row = json.loads(line)
        except json.JSONDecodeError as error:
            raise GateError(
                f"scanner emitted malformed JSON line {output_line}: {error}"
            ) from error
        if not isinstance(row, dict) or set(row) != EXPECTED_FIELDS:
            raise GateError(f"scanner JSON line {output_line} has wrong schema")
        if not isinstance(row["path"], str):
            raise GateError(f"scanner JSON line {output_line} has non-string path")
        path = PurePosixPath(row["path"])
        if (
            path.is_absolute()
            or ".." in path.parts
            or not path.parts
            or path.parts[0] != "crates"
            or path.as_posix() != row["path"]
        ):
            raise GateError(f"scanner JSON line {output_line} has unsafe path")
        if not isinstance(row["kind"], str) or row["kind"] not in KNOWN_KINDS:
            raise GateError(f"scanner JSON line {output_line} has unknown operation")
        if (
            not isinstance(row["line"], int)
            or isinstance(row["line"], bool)
            or row["line"] < 1
        ):
            raise GateError(f"scanner JSON line {output_line} has invalid line")
        if (
            not isinstance(row["column"], int)
            or isinstance(row["column"], bool)
            or row["column"] < 1
        ):
            raise GateError(f"scanner JSON line {output_line} has invalid column")
        if not isinstance(row["detail"], str) or not row["detail"]:
            raise GateError(f"scanner JSON line {output_line} has invalid detail")
        if not isinstance(row["enclosing_item"], str) or not row["enclosing_item"]:
            raise GateError(f"scanner JSON line {output_line} has invalid enclosing item")
        finding = Finding(
            path,
            row["line"],
            row["column"],
            row["kind"],
            row["detail"],
            row["enclosing_item"],
        )
        identity = (
            str(finding.path),
            KIND_ORDER[finding.kind],
            finding.line,
            finding.column,
            finding.detail,
            finding.enclosing_item,
        )
        if identity in identities:
            raise GateError(f"scanner emitted duplicate finding on JSON line {output_line}")
        identities.add(identity)
        findings.append(finding)
    ordering = [
        (
            str(finding.path),
            KIND_ORDER[finding.kind],
            finding.line,
            finding.column,
            finding.detail,
            finding.enclosing_item,
        )
        for finding in findings
    ]
    if ordering != sorted(ordering):
        mismatch = next(
            (
                (ordering[index - 1], ordering[index])
                for index in range(1, len(ordering))
                if ordering[index - 1] > ordering[index]
            ),
            None,
        )
        raise GateError(f"scanner findings are not deterministically ordered: {mismatch}")
    return findings


def failures(root: Path) -> list[str]:
    result = reachability_failures(root)
    allowed_counts: dict[tuple[PurePosixPath, str, str], int] = {}
    for finding in scan(root):
        classification = classify(finding)
        identity = (finding.path, finding.enclosing_item, finding.kind)
        if classification in {
            "carrier_birth",
            "carrier_substrate",
            "operator_tool",
            "probe_tool",
        }:
            count = allowed_counts.get(identity, 0) + 1
            allowed_counts[identity] = count
            limits = {
                "carrier_birth": CARRIER_BIRTH_LIMITS,
                "carrier_substrate": CARRIER_SUBSTRATE_LIMITS,
                "operator_tool": REVIEWED_OPERATOR_LIMITS,
                "probe_tool": REVIEWED_PROBE_LIMITS,
            }[classification]
            if count > limits[identity]:
                result.append(
                    f"{finding.path}:{finding.line}:{finding.column}: error: "
                    f"forbidden_exception_expansion: occurrence {count} of "
                    f"{finding.kind} in {finding.enclosing_item} exceeds the reviewed "
                    f"carrier-only limit {limits[identity]}"
                )
            continue
        if not classification.startswith("forbidden_"):
            continue
        result.append(
            f"{finding.path}:{finding.line}:{finding.column}: error: "
            f"{classification}: {finding.kind} in {finding.enclosing_item} "
            "violates the carrier-only host-process invariant"
        )
    reviewed_limits = (
        CARRIER_BIRTH_LIMITS
        | CARRIER_SUBSTRATE_LIMITS
        | REVIEWED_OPERATOR_LIMITS
        | REVIEWED_PROBE_LIMITS
    )
    for identity, limit in reviewed_limits.items():
        count = allowed_counts.get(identity, 0)
        if count >= limit:
            continue
        path, enclosing_item, kind = identity
        result.append(
            f"{path}: error: stale_exception: reviewed {kind} identity in "
            f"{enclosing_item} occurs {count} time(s), expected exactly {limit}; "
            "remove or update the stale exception in the same reviewed change"
        )
    return result


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path.cwd())
    args = parser.parse_args(argv)
    try:
        found = failures(args.root.resolve())
    except (GateError, OSError) as error:
        print(f"error: carrier-only process scan failed closed: {error}", file=sys.stderr)
        return 2
    if found:
        print(
            "error: carrier-only process invariant has forbidden production residuals:",
            file=sys.stderr,
        )
        for line in found:
            print(line, file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
