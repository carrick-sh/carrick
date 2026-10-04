#!/usr/bin/env python3
"""Prove lint-domains rejects a new Linux compiler-resolved authority site.

Run explicitly on Linux with --ref <reviewed commit>. The product mutation is
confined to a disposable local clone; the reviewed worktree stays untouched.
The cheap added/removed/changed projection tests run in lint-domains itself.
"""

from __future__ import annotations

import argparse
import platform
import subprocess
import sys
import tempfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[3]
SITE = "crates/carrick-host-linux/src/lib.rs"
CHECKER = "scripts/migrate/check-host-authority-transitions.py"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--ref", required=True, help="clean reviewed commit to test")
    args = parser.parse_args()
    if platform.system() != "Linux":
        parser.error("the live Linux breaker requires a Linux host")
    commit = subprocess.check_output(
        ["git", "rev-parse", "--verify", f"{args.ref}^{{commit}}"], cwd=ROOT, text=True
    ).strip()
    with tempfile.TemporaryDirectory(prefix="carrick-ha-linux-breaker-") as directory:
        clone = Path(directory) / "repo"
        subprocess.run(
            ["git", "clone", "--quiet", "--shared", "--no-checkout", str(ROOT), str(clone)],
            check=True,
        )
        subprocess.run(["git", "checkout", "--quiet", "--detach", commit], cwd=clone, check=True)
        path = clone / SITE
        with path.open("a", encoding="utf-8") as stream:
            stream.write(
                "\n// Disposable Linux host-authority gate breaker.\n"
                "pub fn carrick_host_authority_linux_breaker() -> u32 {\n"
                "    std::process::id()\n"
                "}\n"
            )
        subprocess.run(["git", "add", SITE], cwd=clone, check=True)
        subprocess.run(
            ["git", "commit", "--quiet", "-m", "test(linux): add disposable authority breaker",
             "-m", "Verify that a new Linux-only call fails the live compiler census."],
            cwd=clone,
            check=True,
        )
        # The reviewed macOS projection still agrees. A static-only check
        # cannot establish Linux coverage; lint must run the fresh census.
        subprocess.run([sys.executable, CHECKER, "--static"], cwd=clone, check=True)
        result = subprocess.run(
            ["just", "lint-domains"], cwd=clone, capture_output=True, text=True
        )
        output = result.stdout + result.stderr
        if (
            result.returncode == 0
            or "inventory drift: new=" not in output
            or SITE not in output
            or "std::process::id" not in output
        ):
            print(output, file=sys.stderr)
            raise RuntimeError("Linux breaker did not fail at fresh compiler inventory drift")
        for line in output.splitlines():
            if "inventory drift:" in line:
                print(line)
        print(f"PASS: {commit}: fake Linux std::process::id site failed lint-domains "
              f"(exit {result.returncode}); disposable clone removed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
