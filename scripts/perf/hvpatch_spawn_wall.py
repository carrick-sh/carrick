#!/usr/bin/env python3
"""Validate serial spawn boundary captures; print a diagnostic wall budget.

Usage: hvpatch_spawn_wall.py TRACE GUEST_STDOUT TRACE_STDERR EXPECTED_CHILDREN
Consumes hvpatch-spawn-wall-boundaries.d and guest JSON {pid, total_ns} rows.
It rejects incomplete joins and retirement-as-wait substitution. Traced timings
are diagnostic only; compare a matching untraced workload before interpreting.
"""
import json
import pathlib
import statistics
import sys


def analyze(trace, stdout, stderr, expected):
    assert not any(word in stderr.lower() for word in ("drop", "error:", "failed")), stderr
    events, summaries = [], []
    for line in trace.splitlines():
        if not line.startswith("SPAWNWALL|"):
            continue
        fields = line.split("|")
        row = {k: int(v) for k, v in (f.split("=") for f in fields[2:])}
        row["kind"] = fields[1]
        (summaries if fields[1] == "summary" else events).append(row)
    assert len(summaries) == 1
    summary = summaries[0]
    assert summary["errors"] == summary["code"] == summary["bounded"] == 0
    assert summary["seen"] == 1
    events.sort(key=lambda e: e["ns"])  # DTrace buffers are per CPU.
    guests = [json.loads(l) for l in stdout.splitlines() if l.startswith("{")]
    assert len(guests) == expected and len({g["pid"] for g in guests}) == expected
    rows, used_clones = [], set()
    for guest in guests:
        child = guest["pid"]
        life = [e for e in events if e["kind"] == "event" and e["guest"] == child]
        assert [e["phase"] for e in life] == [1, 6, 2, 5], (child, life)
        assert len({e["serial"] for e in life}) == 1
        assert all(e["identity_guest"] == child for e in life)
        fork, begin, published, retired = life
        exits = [e for e in events if e["kind"] == "sysbegin"
                 and e["guest"] == child and e["nr"] in (93, 94)]
        waits = [e for e in events if e["kind"] == "waitreturn" and e["child"] == child]
        assert len(exits) == len(waits) == 1, (child, exits, waits)
        clones = [e for e in events if e["kind"] == "sysbegin"
                  and e["guest"] == fork["parent"] and e["nr"] in (220, 435)
                  and e["ns"] < fork["ns"]]
        assert clones
        clone = clones[-1]
        assert clone["ns"] not in used_clones
        used_clones.add(clone["ns"])
        times = [clone["ns"], fork["ns"], begin["ns"], published["ns"],
                 exits[0]["ns"], waits[0]["ns"]]
        assert times == sorted(times)
        outside = guest["total_ns"] - (times[-1] - times[0])
        assert outside >= 0, (child, outside)
        labels = ["clone_to_prepared", "prepared_to_exec", "exec",
                  "published_to_exit_request", "exit_request_to_wait_return"]
        rows.append({"pid": child, "total": guest["total_ns"] / 1e6,
                     **{k: (b-a)/1e6 for k, a, b in zip(labels, times, times[1:])},
                     "outside_syscall_window": outside/1e6,
                     "retirement_after_wait": (retired["ns"]-times[-1])/1e6})
    return {"units": "ms", "children": expected,
            "note": "retirement_after_wait overlaps other work; do not add to total",
            "means": {k: statistics.mean(r[k] for r in rows) for k in rows[0] if k != "pid"},
            "rows": rows}


if __name__ == "__main__":
    result = analyze(*(pathlib.Path(p).read_text() for p in sys.argv[1:4]), int(sys.argv[4]))
    print(json.dumps(result, indent=2))
