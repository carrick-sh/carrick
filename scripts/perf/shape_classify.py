#!/usr/bin/env python3
"""Classify sampled PCs against per-process JIT code snapshots.

Joins the native-shape-census.d PC histogram (`PC <pid> 0x<addr> <count>`
rows) with the CARRICK_DSR_CODE_SNAPSHOT_DIR dumps (`<pid>-<stamp>.bin` +
`.json`) and buckets every matched sample's instruction word by emitted-code
shape. x28 is the DsrContext register and x18 a DSR-internal scratch, so
words touching them are inserted overhead with certainty; the rest is split
into coarse families to show the texture of "guest-ish" work.
"""

from __future__ import annotations

import argparse
import collections
import json
import pathlib
import re
import sys

PC_ROW = re.compile(r"^PC (\d+) (0x[0-9a-fA-F]+) (\d+)\s*$")


def classify(word: int) -> str:
    if (word & 0xFFC003E0) == 0xF9000380:
        return "dsr:ctx-store64"
    if (word & 0xFFC003E0) == 0xF9400380:
        return "dsr:ctx-load64"
    if (word & 0xFFC003E0) == 0xB9000380:
        return "dsr:ctx-store32"
    if (word & 0xFFC003E0) == 0xB9400380:
        return "dsr:ctx-load32"
    if (word & 0xFFC003E0) == 0xA9000380 or (word & 0xFFC003E0) == 0xA9400380:
        return "dsr:ctx-pair"
    if (word & 0xFFFFFC00) == 0xC8DFFC00:
        return "dsr:guard-ldar"
    if (word & 0xFFC0001F) == 0xD3400012:
        return "dsr:window-ubfm-x18"
    if (word & 0xFF00001F) == 0xB4000012:
        return "dsr:window-cbz-x18"
    # Compact biased addressing: `orr xS, xB, #bias` with the aperture-
    # disjoint single-run bias (immr=23, imms=0 for 1<<41), and the tagged
    # invalid form (immr=17 for 1<<47).
    if (word & 0xFFFFFC00) in (0xB2570000, 0xB2510000):
        return "dsr:bias-orr"
    if (word & 0xFFFFFFE0) == 0xD51B4200:
        return "dsr:nzcv-msr"
    if (word & 0xFFFFFFE0) == 0xD53B4200:
        return "dsr:nzcv-mrs"
    if (word & 0xFF80001F) in (0x52800011, 0x72800011, 0xD2800011, 0xF2800011):
        return "dsr:x17-materialize"
    if (word & 0xFF80001F) in (0x52800012, 0x72800012, 0xD2800012, 0xF2800012):
        return "dsr:x18-materialize"
    if word == 0xD61F0220:
        return "dsr:br-x17"
    if (word & 0xFFFFFC1F) == 0xD61F0200:
        return "br-reg"
    if (word & 0xFFFFFC1F) == 0xD65F0000:
        return "ret"
    # Loads/stores whose base register is x18: DSR-only addressing (guest
    # x18 is virtualized), e.g. the per-thread target-cache probe walk.
    if ((word >> 5) & 0x1F) == 18 and (word & 0x0A000000) == 0x08000000:
        return "dsr:x18-based-ldst"
    return coarse_family(word)


def coarse_family(word: int) -> str:
    top8 = word >> 24
    if (word & 0x7C000000) == 0x14000000:
        return "guest:b/bl"
    if top8 == 0x54:
        return "guest:b.cond"
    if top8 in (0x34, 0x35, 0xB4, 0xB5):
        return "guest:cbz/cbnz"
    if top8 in (0x36, 0x37):
        return "guest:tbz/tbnz"
    if (word & 0x3B000000) == 0x39000000 or (word & 0x3B200C00) == 0x38000400:
        return "guest:ldst-imm"
    if (word & 0x3F000000) == 0x3D000000:
        return "guest:ldst-simd"
    if (word & 0x3A000000) == 0x28000000:
        return "guest:ldst-pair"
    if (word & 0x3B200C00) == 0x38200800:
        return "guest:ldst-reg"
    if (word & 0x1F000000) == 0x11000000 or (word & 0x1F000000) == 0x0B000000:
        return "guest:add/sub"
    if (word & 0x1F800000) == 0x12800000 or (word & 0x1F800000) == 0x12000000:
        return "guest:mov/logic-imm"
    if (word & 0x1F000000) == 0x0A000000:
        return "guest:logic-reg"
    if (word & 0x1F000000) == 0x1B000000:
        return "guest:muladd"
    if (word & 0x0F000000) == 0x0E000000 or (word & 0x0F000000) == 0x04000000:
        return "guest:simd"
    return "guest:other"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("raw", type=pathlib.Path)
    parser.add_argument("--snapshots", type=pathlib.Path, required=True)
    parser.add_argument("--top", type=int, default=24)
    args = parser.parse_args()

    snapshots = []
    for index_path in sorted(args.snapshots.glob("*.json")):
        meta = json.loads(index_path.read_text())
        code_path = index_path.with_suffix(".bin")
        if not code_path.exists():
            continue
        code = code_path.read_bytes()
        snapshots.append(
            {
                "pid": int(meta["pid"]),
                "base": int(meta["cache_base"]),
                "code": code,
                "blocks": meta.get("blocks", []),
            }
        )
    by_pid: dict[int, list[dict]] = collections.defaultdict(list)
    for snap in snapshots:
        by_pid[snap["pid"]].append(snap)

    total = 0
    matched = 0
    unmatched_pid = 0
    unmatched_range = 0
    buckets: collections.Counter[str] = collections.Counter()
    hot_words: collections.Counter[tuple[str, int]] = collections.Counter()
    for line in args.raw.read_text(errors="replace").splitlines():
        row = PC_ROW.match(line.strip())
        if not row:
            continue
        pid, addr, count = int(row.group(1)), int(row.group(2), 16), int(row.group(3))
        total += count
        candidates = by_pid.get(pid)
        if not candidates:
            unmatched_pid += count
            continue
        word = None
        for snap in candidates:
            offset = addr - snap["base"]
            if 0 <= offset and offset + 4 <= len(snap["code"]):
                word = int.from_bytes(snap["code"][offset : offset + 4], "little")
                break
        if word is None:
            unmatched_range += count
            continue
        matched += count
        family = classify(word)
        buckets[family] += count
        hot_words[(family, word)] += count

    print(
        f"pc-samples total={total} matched={matched} "
        f"unmatched-pid={unmatched_pid} unmatched-range={unmatched_range} "
        f"snapshots={len(snapshots)} pids={len(by_pid)}"
    )
    dsr = sum(count for family, count in buckets.items() if family.startswith("dsr:"))
    if matched:
        print(f"dsr-overhead-floor: {dsr} ({100.0 * dsr / matched:.1f}% of matched)")
    print("\n== classes ==")
    for family, count in buckets.most_common(args.top):
        print(f"{count:>8}  {100.0 * count / matched:5.1f}%  {family}")
    print("\n== hottest words per dsr class ==")
    seen: set[str] = set()
    for (family, word), count in hot_words.most_common(200):
        if not family.startswith("dsr:") or family in seen:
            continue
        seen.add(family)
        print(f"{count:>8}  {family}  word=0x{word:08x}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
