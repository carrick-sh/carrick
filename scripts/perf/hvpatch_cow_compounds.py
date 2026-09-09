#!/usr/bin/env python3
"""Validate COW compound census; report counts, never timing/savings estimates.

Usage: hvpatch_cow_compounds.py TRACE STDOUT STDERR EXPECTED_CHILDREN
Consumes hvpatch-cow-compound-census.d and workload JSON {pid, total_ns} rows.
DTrace buffers may arrive out of order. Every transaction must have all three
phases with identical payloads. Group within exact task/MM/source-frame/IPA;
physical addresses alone do not establish ownership across incarnations.
"""
import collections
import hashlib
import json
import pathlib
import sys


def require(condition, message):
    if not condition:
        raise ValueError(message)


def analyze(trace, stdout, stderr, expected):
    require(expected > 0, "expected child count must be positive")
    require(not any(s in stderr.lower() for s in ("drop", "error:", "failed")),
            "trace stderr reports failure or dropped records")
    events, summaries = [], []
    for line in trace.splitlines():
        if not line.startswith("COWPACK|"):
            continue
        fields = line.split("|")
        require(fields[1] in ("event", "summary"), "unknown census record")
        pairs = [field.split("=") for field in fields[2:]]
        row = {k: int(v) for k, v in pairs}
        require(len(row) == len(pairs), "duplicate record field")
        keys = ({"events", "errors", "seen", "code", "bounded"}
                if fields[1] == "summary" else
                {"guest", "mm", "phase", "va", "old_frame", "new_frame",
                 "old_ipa", "new_ipa"})
        require(set(row) == keys, "unexpected record schema")
        (summaries if fields[1] == "summary" else events).append(row)
    require(len(summaries) == 1, "missing or duplicate summary")
    summary = summaries[0]
    require(summary["errors"] == summary["code"] == summary["bounded"] == 0
            and summary["seen"] == 1, "unsuccessful trace target or capture")
    require(len(events) == summary["events"] > 0, "event count mismatch")
    transactions = collections.defaultdict(list)
    for row in events:
        transactions[row["guest"], row["mm"], row["new_frame"]].append(row)
    committed = []
    for identity, phases in transactions.items():
        require(sorted(p["phase"] for p in phases) == [0, 1, 2],
                f"incomplete or duplicated transaction {identity}")
        payloads = [{k: v for k, v in p.items() if k != "phase"} for p in phases]
        require(all(p == payloads[0] for p in payloads),
                f"transaction payload drift {identity}")
        committed.append(next(p for p in phases if p["phase"] == 2))
    guests = [json.loads(line) for line in stdout.splitlines() if line.startswith("{")]
    child_ids = [g["pid"] for g in guests if "pid" in g]
    require(len(child_ids) == len(set(child_ids)) == expected,
            "missing or duplicate completed children")
    children = []
    for child in child_ids:
        rows = [r for r in committed if r["guest"] == child]
        require(bool(rows), f"child {child} has no COW records")
        groups = collections.defaultdict(list)
        for row in rows:
            require(row["old_ipa"] % 16384 == row["new_ipa"] % 16384 == 0,
                    "physical compound receipt is unaligned")
            require(row["va"] % 4096 == 0, "semantic page receipt is unaligned")
            groups[row["mm"], row["old_frame"], row["old_ipa"]].append(row)
        shapes = []
        for (mm, frame, ipa), group in sorted(groups.items()):
            shapes.append({
                "mm": mm, "source_frame": frame, "source_ipa": ipa,
                "transactions": len(group),
                "va_compounds": sorted({r["va"] & ~16383 for r in group}),
                "pages": sorted({r["va"] for r in group}),
                "destination_frames": sorted({r["new_frame"] for r in group}),
                "destination_ipas": sorted({r["new_ipa"] for r in group}),
            })
        children.append({
            "pid": child, "mms": sorted({r["mm"] for r in rows}),
            "transactions": len(rows), "source_groups": len(groups),
            "destination_frames": len({r["new_frame"] for r in rows}),
            "destination_ipas": len({r["new_ipa"] for r in rows}),
            "multiplicity": dict(sorted(collections.Counter(len(g) for g in groups.values()).items())),
            "single_va_compound_groups": sum(len(s["va_compounds"]) == 1 for s in shapes),
            "groups": shapes,
        })
    return {"summary": summary, "transactions": len(committed), "children": children,
            "interpretation": "Counts only. Reuse eligibility and performance are unproven."}


if __name__ == "__main__":
    paths = [pathlib.Path(p) for p in sys.argv[1:4]]
    result = analyze(*(p.read_text() for p in paths), int(sys.argv[4]))
    result["inputs"] = {str(p): hashlib.sha256(p.read_bytes()).hexdigest() for p in paths}
    print(json.dumps(result, indent=2))
