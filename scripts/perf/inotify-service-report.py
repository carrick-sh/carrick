#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0 OR MIT
"""Validate and summarize hvpatch-inotify09-hotpath.d output.

Diagnostic instrumented CPU accounting only. Reject boundary-censored windows;
never present service time as full syscall round-trip or Docker parity evidence.
"""
import argparse
import json
from pathlib import Path

NAMES = {27: "inotify_add_watch", 28: "inotify_rm_watch", 62: "lseek", 64: "write"}


def require(condition, message):
    if not condition:
        raise ValueError(message)


def summarize(text):
    rows = {}
    summaries = []
    host_checks = []
    selected_totals = []
    for line in text.splitlines():
        if not line.startswith("INOTIFYHOT1|"):
            continue
        parts = line.split("|")[1:]
        if any("=" not in part for part in parts):
            require("join_failure" not in parts, "join failure diagnostic")
            continue
        fields = dict(part.split("=", 1) for part in parts)
        if "bound_s" in fields:
            summaries.append(fields)
        elif "host_mismatch" in fields:
            host_checks.append(fields)
        elif "selected_total" in fields:
            selected_totals.append(int(fields["selected_total"]))
        elif "nr" in fields:
            nr = int(fields.pop("nr"))
            host = fields.pop("host", None)
            require(nr in NAMES, f"unexpected syscall {nr}")
            row = rows.setdefault((nr, host), {})
            require(not row.keys() & fields.keys(), "duplicate metric")
            row.update({key: int(value) for key, value in fields.items()})
    require(len(summaries) == len(host_checks) == 1, "missing or duplicate terminal receipt")
    receipt = summaries[0]
    require(receipt.get("complete") == "1", "incomplete capture")
    require(all(receipt.get(k) == "0" for k in ("nested", "mismatch", "errors")), "invalid service join")
    require(host_checks[0].get("host_mismatch") == "0", "invalid host join")
    result = []
    total_begins = 0
    for nr, name in NAMES.items():
        service = rows.get((nr, None), {})
        require(all(k in service for k in ("begins", "services", "clears", "open_services", "duration_ns", "service_cpu_ns")), f"missing service metrics: {name}")
        count = service["services"]
        require(count > 0 and service["begins"] == count == service["clears"] and service["open_services"] == 0, f"unreconciled service windows: {name}")
        total_begins += count
        hosts = []
        for (number, host), metrics in rows.items():
            if number != nr or host is None:
                continue
            require(all(k in metrics for k in ("count", "returns", "open_hosts", "wall_ns", "cpu_ns")), f"missing host metrics: {host}")
            require(metrics["count"] == metrics["returns"] > 0 and metrics["open_hosts"] == 0, f"unreconciled host windows: {host}")
            require(0 <= metrics["cpu_ns"] <= metrics["wall_ns"], f"invalid host timing: {host}")
            hosts.append({"name": host, **metrics})
        host_cpu = sum(h["cpu_ns"] for h in hosts)
        cpu = service["service_cpu_ns"]
        require(0 <= host_cpu <= cpu <= service["duration_ns"], f"invalid service timing: {name}")
        result.append({"syscall": name, "number": nr, "calls": count,
                       "service_wall_ns": service["duration_ns"], "service_cpu_ns": cpu,
                       "host_cpu_ns": host_cpu, "non_host_call_cpu_ns": cpu - host_cpu,
                       "hosts": sorted(hosts, key=lambda h: h["cpu_ns"], reverse=True)})
    require(len(selected_totals) == 1, "missing or duplicate aggregated selected total")
    require(total_begins == selected_totals[0], "selected population differs from reconciled begins")
    return {"schema": 1, "measurement": "instrumented_service_windows",
            "vm_transition_time_measured": False, "boundary_open_windows": 0,
            "services": sorted(result, key=lambda r: r["service_cpu_ns"], reverse=True)}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("capture", type=Path)
    args = parser.parse_args()
    try:
        print(json.dumps(summarize(args.capture.read_text()), indent=2))
    except (ValueError, KeyError) as error:
        parser.exit(1, f"invalid timing capture: {error}\n")
