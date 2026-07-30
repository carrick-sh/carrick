#!/usr/bin/env python3
"""Classify every EMITTED word in the JIT code cache, not just sampled PCs.

`shape_classify.py` answers "where do the CYCLES go" by bucketing sampled PCs.
This answers a different question: "where do the BYTES go". They are not the
same, and the difference is the point:

  * executed share drives cycles -- a hot block's words are counted every time
    the sampler lands in them;
  * emitted share drives FOOTPRINT -- page faults on first touch, plus I-cache
    and iTLB pressure on every execution. A block emitted once and never run
    costs footprint and no cycles at all.

MEASURED on one cold go-build: 68 guest processes emit 599,208,872 bytes
(149,802,218 words), of which 71.2% are DSR-inserted. At Apple Silicon's 16 KiB
pages that is 36,573 first-touch pages -- only 2.08% of the 1,757,794
`vminfo:::zfod` faults the same workload takes (1.48% for inserted code alone).
So emitted code is NOT a meaningful driver of this workload's page faults; those
are dominated by the guest's own anonymous memory, which any runtime would pay.

That number is worth stating loudly because the estimate it replaced was wrong by
5.1x, and the reason is a trap this tool exists to avoid. `cache_used_bytes` is
reported in a PER-THREAD profile frame, so summing the frames counts each
process's cache once per thread: 444 frames, 68 processes, 4.1 GB claimed against
0.6 GB real. Measure the bytes, do not sum a gauge.

What the emitted view IS good for is that it ranks differently from the executed
view, because a block emitted once and never run costs footprint and no cycles.
On the same run `dsr:x17-materialize` is 29.1% of all emitted words -- the
largest single class, larger than any guest class -- against 13.9% of sampled
executed PCs. Exit-target materialization dominates footprint far more than it
dominates cycles.

Reads the dumps produced by `CARRICK_DSR_CODE_SNAPSHOT_DIR` and reuses
`shape_classify.classify` verbatim, so a word is bucketed by exactly the same
rules in both views.
"""

from __future__ import annotations

import argparse
import collections
import json
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))

import shape_classify  # noqa: E402

SCHEMA = "carrick.native-emitted-shape.v1"
# Apple Silicon page size. The fault accounting is per page, so this is the unit
# that converts emitted bytes into first-touch faults.
PAGE_BYTES = 16 * 1024


def classify_snapshot(code: bytes) -> collections.Counter[str]:
    buckets: collections.Counter[str] = collections.Counter()
    for offset in range(0, len(code) - 3, 4):
        word = int.from_bytes(code[offset : offset + 4], "little")
        buckets[shape_classify.classify(word)] += 1
    return buckets


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--snapshots", type=pathlib.Path, required=True)
    parser.add_argument("--top", type=int, default=20)
    parser.add_argument("--output", type=pathlib.Path)
    parser.add_argument(
        "--zfod-faults",
        type=int,
        help="total vminfo:::zfod faults for the same workload, to report the "
        "JIT's share of them",
    )
    args = parser.parse_args(sys.argv[1:] if argv is None else argv)

    buckets: collections.Counter[str] = collections.Counter()
    total_bytes = 0
    snapshots = 0
    for code_path in sorted(args.snapshots.glob("*.bin")):
        code = code_path.read_bytes()
        if not code:
            continue
        snapshots += 1
        total_bytes += len(code)
        buckets += classify_snapshot(code)

    if not snapshots:
        raise SystemExit(f"no non-empty *.bin snapshots under {args.snapshots}")

    words = sum(buckets.values())
    inserted = sum(count for name, count in buckets.items() if name.startswith("dsr:"))
    guestish = words - inserted
    pages = (total_bytes + PAGE_BYTES - 1) // PAGE_BYTES
    inserted_pages = round(pages * inserted / words) if words else 0

    print(f"snapshots={snapshots}  emitted_bytes={total_bytes:,}  words={words:,}")
    print(f"  16 KiB pages of emitted code: {pages:,}")
    print(f"\nEMITTED composition")
    print(f"  DSR-inserted : {inserted:>12,} words  {100 * inserted / words:5.1f}%")
    print(f"  guest-shaped : {guestish:>12,} words  {100 * guestish / words:5.1f}%")
    print(
        f"\n  pages attributable to inserted code: {inserted_pages:,} "
        f"({100 * inserted / words:.1f}% of {pages:,})"
    )
    if args.zfod_faults:
        print(
            f"  JIT share of {args.zfod_faults:,} zfod faults: "
            f"{100 * pages / args.zfod_faults:.2f}%  "
            f"(inserted-only: {100 * inserted_pages / args.zfod_faults:.2f}%)"
        )
    print(f"\n== emitted classes ==")
    for name, count in buckets.most_common(args.top):
        print(f"  {count:>12,}  {100 * count / words:5.1f}%  {name}")

    if args.output:
        payload = {
            "schema": SCHEMA,
            "snapshots": snapshots,
            "emitted_bytes": total_bytes,
            "words": words,
            "page_bytes": PAGE_BYTES,
            "pages": pages,
            "inserted_words": inserted,
            "guest_words": guestish,
            "inserted_pages": inserted_pages,
            "zfod_faults": args.zfod_faults,
            "classes": dict(buckets),
        }
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(payload, indent=1, sort_keys=True))
        print(f"\nwrote {args.output}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
