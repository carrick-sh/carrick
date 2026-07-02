#!/usr/bin/env python3
"""Stage-14 (LinuxErrno) compiler-span-driven codemod.

After killing `impl From<i32> for DispatchOutcome`/`DispatchError` and retyping
the `LINUX_E*` constants to `LinuxErrno`, every `X.into()` whose target was
`DispatchOutcome` fails with E0277 `DispatchOutcome: From<carrick_abi::
LinuxErrno>`. Regex CANNOT classify these sites (the target type is invisible
in the text), but the compiler diagnostic names both the file span and the
failed target type — so the rewrite is driven off `cargo check
--message-format=json` spans instead of a hand-built pattern list.

For each E0277 diagnostic matching --trait-bound, the primary span points at
the `into` identifier; we scan the receiver expression backwards (identifiers,
paths, balanced call parens, `.` chains) and rewrite

    <receiver>.into()   →   <wrap>(<receiver>)

Usage:
  errno_into_fixer.py --trait-bound 'DispatchOutcome: From<carrick_abi::LinuxErrno>' \
      --wrap 'DispatchOutcome::errno' --expect 728 [--check] -- <cargo check args...>

--expect asserts the number of rewritten sites (all-or-nothing, like
scripts/migrate/rewrite.py); unresolvable receivers are reported and abort.
"""

import argparse
import json
import subprocess
import sys
from pathlib import Path

IDENT = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_")


def scan_receiver(src: str, dot: int) -> int:
    """Return the start index of the receiver expression ending at src[dot]
    (exclusive), i.e. the `.` of `.into()`. Handles identifiers, `::` paths,
    balanced `(...)`/`[...]` suffixes, and `.` chains. Returns -1 if the
    receiver can't be resolved confidently."""
    i = dot
    while i > 0:
        c = src[i - 1]
        if c in IDENT:
            j = i
            while j > 0 and src[j - 1] in IDENT:
                j -= 1
            i = j
            # allow a path prefix `foo::bar`
            if i >= 2 and src[i - 2 : i] == "::":
                i -= 2
                continue
            # allow a chain prefix `foo.bar`
            if i >= 1 and src[i - 1] == ".":
                i -= 1
                continue
            return i
        if c in ")]":
            close = {")": "(", "]": "["}[c]
            depth = 0
            j = i - 1
            while j >= 0:
                if src[j] == c:
                    depth += 1
                elif src[j] == close:
                    depth -= 1
                    if depth == 0:
                        break
                j -= 1
            if j < 0:
                return -1
            i = j
            continue
        return -1
    return -1


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--trait-bound", required=True)
    ap.add_argument("--wrap", required=True)
    ap.add_argument("--expect", type=int, default=None)
    ap.add_argument("--check", action="store_true")
    ap.add_argument("cargo_args", nargs="*")
    args = ap.parse_args()

    cmd = ["cargo", "check", "--message-format=json"] + args.cargo_args
    proc = subprocess.run(cmd, capture_output=True, text=True)
    needle = f"the trait bound `{args.trait_bound}` is not satisfied"

    sites: set[tuple[str, int, int]] = set()
    for line in proc.stdout.splitlines():
        try:
            m = json.loads(line)
        except json.JSONDecodeError:
            continue
        if m.get("reason") != "compiler-message":
            continue
        d = m["message"]
        if d.get("level") != "error" or d.get("message") != needle:
            continue
        for s in d.get("spans", []):
            if s.get("is_primary"):
                sites.add((s["file_name"], s["byte_start"], s["byte_end"]))

    by_file: dict[str, list[tuple[int, int]]] = {}
    for f, b0, b1 in sites:
        by_file.setdefault(f, []).append((b0, b1))

    failures: list[str] = []
    planned: dict[str, list[tuple[int, int, str]]] = {}
    total = 0
    for f, spans in by_file.items():
        raw = Path(f).read_bytes()
        src = raw.decode("utf-8")
        # byte offsets → char offsets (assume ASCII region; verify token text)
        edits = []
        for b0, b1 in sorted(spans, reverse=True):
            tok = raw[b0:b1].decode("utf-8", "replace")
            if tok != "into":
                failures.append(f"{f}@{b0}: primary span is {tok!r}, not 'into'")
                continue
            # map byte to char offsets
            c0 = len(raw[:b0].decode("utf-8"))
            c1 = len(raw[:b1].decode("utf-8"))
            if src[c1 : c1 + 2] != "()":
                failures.append(f"{f}@{b0}: no call parens after into")
                continue
            if c0 == 0 or src[c0 - 1] != ".":
                failures.append(f"{f}@{b0}: no dot before into")
                continue
            r0 = scan_receiver(src, c0 - 1)
            if r0 < 0:
                ctx = src[max(0, c0 - 80) : c1 + 2].splitlines()[-1]
                failures.append(f"{f}@{b0}: unresolvable receiver: ...{ctx}")
                continue
            recv = src[r0 : c0 - 1]
            edits.append((r0, c1 + 2, f"{args.wrap}({recv})"))
            total += 1
        planned[f] = edits

    if failures:
        print("ABORTED — unresolvable sites:", file=sys.stderr)
        for x in failures:
            print("  " + x, file=sys.stderr)
        return 1
    if args.expect is not None and total != args.expect:
        print(
            f"ABORTED — expected {args.expect} sites, found {total}",
            file=sys.stderr,
        )
        return 1
    if args.check:
        print(f"OK (dry run): {total} site(s) across {len(by_file)} file(s)")
        return 0
    for f, edits in planned.items():
        src = Path(f).read_text()
        for start, end, repl in sorted(edits, reverse=True):
            src = src[:start] + repl + src[end:]
        Path(f).write_text(src)
    print(f"rewrote {total} site(s) across {len(by_file)} file(s)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
