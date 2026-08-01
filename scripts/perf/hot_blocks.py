#!/usr/bin/env python3
"""Annotated disassembly of the hottest translated blocks.

Joins the native-shape-census.d PC histogram with a CARRICK_DSR_CODE_SNAPSHOT_DIR
dump, groups samples by containing block (via the snapshot's guest->cache index),
and prints each hot block fully disassembled with per-word sample counts.
"""
import argparse
import bisect
import collections
import glob
import json
import pathlib
import re
import sys

import capstone

PC_ROW = re.compile(r"^PC (\d+) (0x[0-9a-fA-F]+) (\d+)\s*$")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("raw")
    ap.add_argument("--snapshots", required=True)
    ap.add_argument("--pid", type=int, help="restrict to one guest pid")
    ap.add_argument("--top", type=int, default=8)
    ap.add_argument("--max-words", type=int, default=220)
    args = ap.parse_args()

    snaps = {}
    for j in glob.glob(f"{args.snapshots}/*.json"):
        meta = json.load(open(j))
        pid = meta["pid"]
        if args.pid and pid != args.pid:
            continue
        code = pathlib.Path(j[: -len(".json")] + ".bin").read_bytes()
        # blocks: list of [guest_va, host_va] block entry points
        blocks = sorted((host, guest) for guest, host in meta["blocks"])
        snaps[pid] = (meta["cache_base"], code, blocks)

    per_pc = collections.Counter()
    for line in open(args.raw, errors="replace"):
        m = PC_ROW.match(line)
        if not m:
            continue
        pid, addr, count = int(m.group(1)), int(m.group(2), 16), int(m.group(3))
        if pid in snaps:
            per_pc[(pid, addr)] += count

    # Attribute each sampled PC to the nearest preceding block entry.
    block_weight = collections.Counter()
    for (pid, addr), count in per_pc.items():
        base, code, blocks = snaps[pid]
        if not (base <= addr < base + len(code)):
            continue
        hosts = [h for h, _ in blocks]
        i = bisect.bisect_right(hosts, addr) - 1
        if i < 0:
            continue
        block_weight[(pid, blocks[i][0], blocks[i][1])] += count

    md = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_LITTLE_ENDIAN)
    md.detail = False

    total = sum(per_pc.values())
    print(f"total-samples={total} blocks-with-samples={len(block_weight)}")
    for (pid, host, guest), weight in block_weight.most_common(args.top):
        base, code, blocks = snaps[pid]
        hosts = [h for h, _ in blocks]
        i = bisect.bisect_right(hosts, host) - 1
        end = hosts[i + 1] if i + 1 < len(hosts) else base + len(code)
        end = min(end, host + 4 * args.max_words)
        off = host - base
        body = code[off : off + (end - host)]
        print(f"\n== pid {pid} block host=0x{host:x} guest=0x{guest:x} "
              f"len={len(body)//4}w samples={weight} ({100.0*weight/total:.1f}%) ==")
        for insn in md.disasm(body, host):
            c = per_pc.get((pid, insn.address), 0)
            marker = f"{c:>6}" if c else "     ."
            print(f"  {marker}  0x{insn.address:x}  {insn.mnemonic:8s} {insn.op_str}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
