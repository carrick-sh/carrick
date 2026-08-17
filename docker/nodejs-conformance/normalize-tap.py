#!/usr/bin/env python3
"""Emit stable TAP for Node conformance logs without exposing temp paths."""

from pathlib import Path
import re
import sys


PLAN = re.compile(r"^1\.\.\d+\s*$")
ASSERTION = re.compile(r"^(?:ok|not ok)\s+\d+(?:\s|$)")


def _looks_like_tap(output: str) -> bool:
    return any(
        line.startswith("TAP version ")
        or PLAN.match(line) is not None
        or ASSERTION.match(line) is not None
        or line.startswith("Bail out!")
        for line in output.splitlines()
    )


def normalize(name: str, returncode: int, output: str) -> str:
    if _looks_like_tap(output):
        return output

    status = "ok" if returncode == 0 else "not ok"
    normalized = f"TAP version 13\n1..1\n{status} 1 - {name}\n"
    if returncode != 0:
        for line in output.splitlines():
            normalized += f"# {line}\n"
    return normalized


def main(argv: list[str]) -> int:
    if len(argv) != 4:
        print("usage: normalize-tap.py NAME RETURNCODE LOG", file=sys.stderr)
        return 2
    name, returncode_text, log_path = argv[1:]
    try:
        returncode = int(returncode_text)
        output = Path(log_path).read_text(encoding="utf-8", errors="replace")
    except (OSError, ValueError) as error:
        print(f"normalize-tap.py: {error}", file=sys.stderr)
        return 2
    sys.stdout.write(normalize(name, returncode, output))
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
