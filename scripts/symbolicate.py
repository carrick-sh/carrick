#!/usr/bin/env python3
"""Resolve raw addresses in DTrace output against carrick and, optionally, guest images.

DTrace symbolicates a user stack when it PRINTS it, from the mappings of the
process the sample came from. Carrick's guest processes are short-lived forked
children, so any aggregation printed after they exit -- which on a toolchain
workload is nearly all of them -- comes out as bare hex. This tool resolves that
output after the fact.

Three address spaces show up in a native-lane profile, and conflating them
produces confident nonsense:

  host carrick   the carrick binary's own code (the translator, the dispatcher).
                 Resolved with `atos` against `target/release/carrick`.
  guest ELF      the Linux binary being run. Its addresses mean nothing to the
                 host binary's symbol table; pass `--guest ELF:BASE` and they are
                 resolved against that ELF instead.
  JIT cache      translated code, which has no symbol table at all. Reported as
                 `[jit]` rather than silently mis-attributed to whichever host
                 symbol happens to precede it.

Usage:
  scripts/symbolicate.py /tmp/cpu.txt
  scripts/symbolicate.py /tmp/cpu.txt --top 40
  scripts/symbolicate.py /tmp/cpu.txt --guest /usr/local/go/bin/go:0x400000
  scripts/symbolicate.py /tmp/cpu.txt --group-by file
"""

from __future__ import annotations

import argparse
import bisect
import collections
import pathlib
import re
import shutil
import subprocess
import sys

# "PC <pid> 0x100773ac8   12345" as emitted by native-cpu-attribution.d. The
# older pid-less form is still accepted so previously captured files keep
# working; it just cannot distinguish two processes that share an address.
PC_ROW = re.compile(r"^\s*PC\s+(\d+)\s+(0x[0-9a-fA-F]+)\s+(\d+)\s*$")
PC_ROW_NOPID = re.compile(r"^\s*PC\s+(0x[0-9a-fA-F]+)\s+(\d+)\s*$")
BARE_ADDR = re.compile(r"^\s*(0x[0-9a-fA-F]+)\s*$")
# "IMGBASE host pid=123 base=0x100000000 slide=0 path=/…/carrick"
IMGBASE = re.compile(
    r"^IMGBASE\s+(host|guest)\s+pid=(\d+)\s+base=(0x[0-9a-fA-F]+)\s+"
    r"(?:slide=(-?\d+)|entry=0x[0-9a-fA-F]+)\s+path=(.*?)\s*$"
)


def default_binary() -> pathlib.Path:
    return pathlib.Path(__file__).resolve().parent.parent / "target" / "release" / "carrick"


def text_vmaddr(binary: pathlib.Path) -> int:
    """__TEXT vmaddr — the load address `atos -l` needs for a PIE image.

    Read it rather than assuming 0x100000000: it is the one input that makes
    every subsequent symbol either right or uniformly, plausibly wrong.
    """
    out = subprocess.run(
        ["otool", "-l", str(binary)], capture_output=True, text=True, check=True
    ).stdout
    seen_text = False
    for line in out.splitlines():
        line = line.strip()
        if line == "segname __TEXT":
            seen_text = True
        elif seen_text and line.startswith("vmaddr"):
            return int(line.split()[1], 16)
    raise SystemExit(f"{binary}: no __TEXT segment found")


def image_text_size(binary: pathlib.Path) -> int:
    """__TEXT vmsize — how far past a reported base an address can still be ours."""
    out = subprocess.run(
        ["otool", "-l", str(binary)], capture_output=True, text=True, check=True
    ).stdout
    seen_text = False
    for line in out.splitlines():
        line = line.strip()
        if line == "segname __TEXT":
            seen_text = True
        elif seen_text and line.startswith("vmsize"):
            return int(line.split()[1], 16)
    return 0


def symbol_table(binary: pathlib.Path) -> tuple[list[int], list[str]]:
    """Sorted (addresses, names) from `nm -n`, for range classification."""
    out = subprocess.run(
        ["nm", "-n", str(binary)], capture_output=True, text=True, check=False
    ).stdout
    addrs: list[int] = []
    names: list[str] = []
    for line in out.splitlines():
        parts = line.split()
        if len(parts) >= 3 and parts[1] in ("T", "t"):
            try:
                addrs.append(int(parts[0], 16))
            except ValueError:
                continue
            names.append(parts[2])
    return addrs, names


def atos_batch(binary: pathlib.Path, load: int, addrs: list[int]) -> dict[int, str]:
    """Symbolicate in one atos invocation — it is slow to start, fast to feed."""
    if not addrs or not shutil.which("atos"):
        return {}
    proc = subprocess.run(
        ["atos", "-o", str(binary), "-l", hex(load)] + [hex(a) for a in addrs],
        capture_output=True,
        text=True,
        check=False,
    )
    lines = proc.stdout.splitlines()
    return {a: lines[i].strip() for i, a in enumerate(addrs) if i < len(lines)}


def source_file(sym: str) -> str:
    """`foo (in carrick) (decode2.c:54288)` -> `decode2.c`.

    Grouping by file is what separates "the decoder is hot" from "one function
    is hot": a generated decoder spreads its cost over thousands of symbols, so
    a per-symbol histogram makes it look like nothing in particular is hot.
    """
    m = re.search(r"\(([^()]+?):\d+\)\s*$", sym)
    if m:
        return m.group(1).split("/")[-1]
    return "?"


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("input", type=pathlib.Path, help="DTrace output file")
    ap.add_argument("--binary", type=pathlib.Path, default=None, help="host carrick binary")
    ap.add_argument(
        "--guest",
        action="append",
        default=[],
        metavar="ELF:BASE",
        help="guest image and its load base, e.g. /usr/local/go/bin/go:0x400000",
    )
    ap.add_argument("--top", type=int, default=30, help="rows to show")
    ap.add_argument(
        "--group-by",
        choices=("symbol", "file"),
        default="symbol",
        help="aggregate by symbol (default) or by source file",
    )
    args = ap.parse_args()

    binary = args.binary or default_binary()
    if not binary.exists():
        print(f"missing host binary: {binary}", file=sys.stderr)
        return 1

    # (pid, addr) -> samples. pid 0 means "the capture did not say", which only
    # happens for older pid-less captures.
    counts: collections.Counter[tuple[int, int]] = collections.Counter()
    frames: collections.Counter[tuple[int, int]] = collections.Counter()
    # pid -> {"host": (base, path), "guest": (base, path)}
    images: dict[int, dict[str, tuple[int, str]]] = collections.defaultdict(dict)

    for line in args.input.read_text(errors="replace").splitlines():
        m = IMGBASE.match(line)
        if m:
            kind, pid, base, _slide, path = m.groups()
            images[int(pid)][kind] = (int(base, 16), path)
            continue
        m = PC_ROW.match(line)
        if m:
            counts[(int(m.group(1)), int(m.group(2), 16))] += int(m.group(3))
            continue
        m = PC_ROW_NOPID.match(line)
        if m:
            counts[(0, int(m.group(1), 16))] += int(m.group(2))
            continue
        m = BARE_ADDR.match(line)
        if m:
            frames[(0, int(m.group(1), 16))] += 1

    # The `PC` histogram is one row per sampled program counter, with its sample
    # count. A bare address inside a printed ustack() is a STACK FRAME: one
    # sample of a 12-deep stack contributes 12 of them, and the same stack is
    # reprinted in every window it survives. Adding the two together inflated a
    # 109k-sample profile to 22M and buried the real distribution -- so use the
    # histogram whenever it is present, and fall back to frames only when it is
    # not, saying so, because then the numbers mean something different.
    if counts:
        if frames:
            print(
                f"note: ignoring {sum(frames.values())} stack-frame occurrences; "
                "using the PC histogram (frames are not samples)",
                file=sys.stderr,
            )
    elif frames:
        print(
            "note: no PC histogram found — counting stack frames instead. "
            "These are frame occurrences, NOT samples: read them as relative "
            "presence on the stack, not as CPU time.",
            file=sys.stderr,
        )
        counts = frames
    else:
        print("no raw addresses found — was the run symbolicated already?", file=sys.stderr)
        return 1

    # Manual --guest overrides apply to every pid that lacks an announcement.
    fallback_guests = []
    for spec in args.guest:
        path, _, base = spec.rpartition(":")
        fallback_guests.append((pathlib.Path(path), int(base, 16)))

    host_size = image_text_size(binary)
    # Hoisted: both of these fork `otool`. Called per address they cost one
    # process launch per SAMPLE -- 46k forks on a real capture, which is why
    # symbolication took minutes rather than the second it should.
    host_vmaddr = text_vmaddr(binary)

    # Group addresses by the image they belong to, per pid, then symbolicate
    # each image in ONE atos call.
    #
    # Deciding host-vs-guest per pid is the whole point: guest processes
    # self-reexec, so process A's carrick text and process B's can sit at
    # different bases, and a global range test attributes one to the other.
    by_image: dict[tuple[str, int], list[int]] = collections.defaultdict(list)
    unmapped: collections.Counter[tuple[int, int]] = collections.Counter()

    for (pid, addr), n in counts.items():
        imgs = images.get(pid, {})
        host = imgs.get("host")
        guest = imgs.get("guest")
        placed = False
        if host and host[0] <= addr < host[0] + host_size:
            by_image[(host[1], host[0])].append(addr)
            placed = True
        elif guest and addr >= guest[0] and not (host and addr >= host[0]):
            by_image[(guest[1], guest[0])].append(addr)
            placed = True
        elif not imgs:
            # No announcement for this pid: fall back to the on-disk binary at
            # its own __TEXT vmaddr, which is right for the supervisor and for
            # any process that did not re-exec.
            if 0 < addr < host_vmaddr + host_size:
                by_image[(str(binary), host_vmaddr)].append(addr)
                placed = True
            else:
                for gpath, gbase in fallback_guests:
                    if addr >= gbase:
                        by_image[(str(gpath), gbase)].append(addr)
                        placed = True
                        break
        if not placed:
            unmapped[(pid, addr)] += n

    resolved: dict[tuple[str, int, int], str] = {}
    for (path, base), addrs_for_image in by_image.items():
        p = pathlib.Path(path)
        if not p.exists():
            continue
        for a, sym in atos_batch(p, base, sorted(set(addrs_for_image))).items():
            tag = "" if p == binary or p.name == binary.name else f"  [{p.name}]"
            resolved[(path, base, a)] = f"{sym}{tag}"

    total = sum(counts.values())
    buckets: collections.Counter[str] = collections.Counter()
    for (pid, addr), n in counts.items():
        imgs = images.get(pid, {})
        sym = None
        for kind in ("host", "guest"):
            if kind in imgs:
                key = (imgs[kind][1], imgs[kind][0], addr)
                if key in resolved:
                    sym = resolved[key]
                    break
        if sym is None:
            key = (str(binary), host_vmaddr, addr)
            sym = resolved.get(key)
        if sym is None:
            # In neither this pid's host image nor its guest image: translated
            # code, or a dylib we were not asked about. Say so, rather than
            # attributing it to the nearest host symbol, which would be fiction.
            sym = "[jit / dylib / unmapped]"
        buckets[source_file(sym) if args.group_by == "file" else sym] += n

    print(f"total samples: {total}   distinct PCs: {len(counts)}")
    print(f"host image: {binary}  ({len(images)} pids announced their own base)")
    print()
    width = 78
    for name, n in buckets.most_common(args.top):
        pct = 100.0 * n / total
        print(f"  {pct:6.2f}%  {n:>9}  {name[:width]}")
    shown = sum(n for _, n in buckets.most_common(args.top))
    print(f"\n  {100.0 * shown / total:6.2f}%  of samples shown in {args.top} rows")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
