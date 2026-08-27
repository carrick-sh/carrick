#!/usr/bin/env python3
"""Fail closed when probe wiring regresses to the legacy subprocess strategy."""

from pathlib import Path
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
    workflow = (ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")
    legacy = "cargo test -p carrick-cli --test conformance"
    if legacy in workflow:
        fail("CI invokes the legacy carrick-cli conformance target directly")
    if "run: just conformance-probes" not in workflow:
        fail("CI does not invoke the public just conformance-probes gate")


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


def main() -> None:
    check_next_has_no_subprocesses()
    check_ci_uses_public_gate()
    check_public_gate_is_filtered()
    print("conformance-next strategy: enforced")


if __name__ == "__main__":
    main()
