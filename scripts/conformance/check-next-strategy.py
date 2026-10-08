#!/usr/bin/env python3
"""Fail closed when probe wiring regresses to the legacy subprocess strategy."""

from pathlib import Path
import shlex
import sys


ROOT = Path(__file__).resolve().parents[2]
NEXT = ROOT / "crates" / "carrick-conformance-next"


def fail(message: str) -> None:
    print(f"conformance-next strategy violation: {message}", file=sys.stderr)
    raise SystemExit(1)


def check_next_has_no_subprocesses() -> None:
    forbidden = ("Command::new(", "use std::process::Command", "use tokio::process::Command")
    for path in sorted(NEXT.rglob("*.rs")):
        for lineno, raw in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            line = raw.lstrip()
            if line.startswith("//"):
                continue
            if any(token in raw for token in forbidden):
                fail(f"{path.relative_to(ROOT)}:{lineno} introduces subprocess execution")


def check_ci_uses_public_gate() -> None:
    workflows = sorted((ROOT / ".github/workflows").glob("*.yml"))
    legacy = "cargo test -p carrick-cli --test conformance"
    for workflow in workflows:
        if legacy in workflow.read_text(encoding="utf-8"):
            fail(
                f"{workflow.relative_to(ROOT)} invokes the legacy carrick-cli "
                "conformance target directly"
            )
    if not any(_uses_public_gate(workflow) for workflow in workflows):
        fail("no workflow invokes the public just conformance-probes gate")


def _uses_public_gate(workflow: Path) -> bool:
    lines = workflow.read_text(encoding="utf-8").splitlines()
    for index, raw in enumerate(lines):
        command = _run_command(raw)
        if command is None:
            continue
        if _command_uses_public_gate(command):
            return True
        if command.startswith(("|", ">")) and _block_uses_public_gate(lines, index):
            return True
    return False


def _run_command(raw: str) -> str | None:
    stripped = raw.lstrip()
    for prefix in ("run:", "- run:"):
        if stripped.startswith(prefix):
            return stripped.removeprefix(prefix).strip()
    return None


def _block_uses_public_gate(lines: list[str], header_index: int) -> bool:
    header = lines[header_index]
    header_indent = len(header) - len(header.lstrip())
    for raw in lines[header_index + 1 :]:
        if raw.strip() and len(raw) - len(raw.lstrip()) <= header_indent:
            return False
        if _command_uses_public_gate(raw.strip()):
            return True
    return False


def _command_uses_public_gate(command: str) -> bool:
    try:
        tokens = shlex.split(command, comments=False)
    except ValueError:
        return False
    while tokens and _is_environment_assignment(tokens[0]):
        tokens.pop(0)
    return tokens[:2] == ["just", "conformance-probes"]


def _is_environment_assignment(token: str) -> bool:
    name, separator, _value = token.partition("=")
    return separator == "=" and name.isidentifier()


def check_public_gate_is_filtered() -> None:
    justfile = (ROOT / "justfile").read_text(encoding="utf-8")
    required = (
        "./scripts/test-signed.sh carrick-conformance-next generic_probe_shard_ --nocapture",
        'CARRICK_PROBE_FILTER="$retained_filter"',
        "scripts/conformance/retained-generic-probes.txt",
    )
    for marker in required:
        if marker not in justfile:
            fail(f"public probe gate lost required wiring: {marker}")


def check_native_oracle_layout() -> None:
    """Native provenance is a sidecar, never a generic subprocess probe."""
    root = ROOT / "crates/carrick-cli/tests/probe-oracle"
    allowed = {"arm64-musl", "arm64-gnu", "amd64-musl", "amd64-gnu",
               "amd64native-musl", "amd64native-gnu"}
    for directory in sorted(root.iterdir()):
        if not directory.is_dir():
            continue
        if directory.name not in allowed:
            fail(f"unknown oracle directory: {directory.relative_to(ROOT)}")
        if directory.name.startswith("amd64native-"):
            import json
            provenance = directory / "PROVENANCE.json"
            if not provenance.is_file():
                fail(f"native oracle directory lacks {provenance.relative_to(ROOT)}")
            data = json.loads(provenance.read_text(encoding="utf-8"))
            if data.get("oracle_backend") != "native-unshare-v1":
                fail(f"invalid native oracle provenance: {provenance.relative_to(ROOT)}")
            for entry in directory.iterdir():
                if entry.name == "PROVENANCE.json":
                    continue
                if not (ROOT / "conformance-probes/src/bin" / f"{entry.name}.rs").is_file():
                    fail(f"native oracle without probe source: {entry.relative_to(ROOT)}")


def main() -> None:
    check_native_oracle_layout()
    check_next_has_no_subprocesses()
    check_ci_uses_public_gate()
    check_public_gate_is_filtered()
    print("conformance-next strategy: enforced")


if __name__ == "__main__":
    main()
