#!/usr/bin/env python3
"""Full-suite LTP baseline: run every syscall test under Docker (the real-Linux
oracle) AND under carrick, classify the pair HONESTLY, and emit a per-area
verified-MATCH tally — the denominator + target for the LTP-conformance goal.

This is the instrument for Milestone 1. It is RESUMABLE: results are appended
to a JSONL file and already-recorded tests are skipped, so a multi-hour sweep
can run incrementally across sessions (Ctrl-C safe — each result is flushed).

Classification (the honest-accounting part — see the ltp-conformance skill's
"Reading results honestly"):
  MATCH      carrick's verdict == Docker's verdict (count-level; the
             probe suite is what makes a specific invariant *verified*).
  DIFF       a real divergence (carrick fails/differs where Docker passes).
  TBROK      carrick's framework setup broke (broken>0) while Docker's didn't
             — a hidden test, not a real assertion fail. Clear the blocker.
  TCONF      both sides skipped (conf>0, nothing ran) — not exercised.
  TIMEOUT    carrick hung (rc 124) — the worst class.
  INVERSION  carrick passed where Docker failed/broke — usually Docker-VM
             timing jitter (carrick more correct) BUT can mask an
             under-enforced check; flagged for individual manual review,
             NEVER auto-counted as a win.

Usage:
  ltp-baseline.py [--area AREA]... [--limit N] [--list]
  ltp-baseline.py --tally        # re-emit the per-area tally from results
The inventory comes from docs/ltp-baseline/inventory.json (built from the
image's runtest/syscalls manifest).
"""
import argparse
import json
import os
import re
import subprocess
import sys
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
INVENTORY = os.path.join(ROOT, "docs", "ltp-baseline", "inventory.json")
RESULTS = os.path.join(ROOT, "docs", "ltp-baseline", "results.jsonl")
CARRICK = os.environ.get("CARRICK", os.path.join(ROOT, "target", "release", "carrick"))
KILL = os.environ.get("KILL", os.path.join(ROOT, "scripts", "sudo", "kill.sh"))
DOCKER_IMAGE = os.environ.get("LTP_DOCKER_IMAGE", "ltp:arm64")
CARRICK_IMAGE = os.environ.get("LTP_CARRICK_IMAGE", "localhost:5050/ltp:arm64")
CARRICK_TIMEOUT = int(os.environ.get("LTP_CARRICK_TIMEOUT", "45"))
DOCKER_TIMEOUT = int(os.environ.get("LTP_DOCKER_TIMEOUT", "60"))

os.environ.setdefault("CARRICK_INSECURE_REGISTRIES", "localhost:5050")


def parse_verdict(text):
    """Return (passed, failed, broken, conf) from a test's output. Prefers the
    new-API `Summary: passed/failed/broken` block; falls back to counting
    old-API per-line TPASS/TFAIL/TBROK/TCONF (those print no Summary)."""
    p = f = b = c = 0
    m = dict(re.findall(r"(passed|failed|broken|conf|warnings)\s+(\d+)", text))
    if "passed" in m or "failed" in m or "broken" in m:
        return (int(m.get("passed", 0)), int(m.get("failed", 0)),
                int(m.get("broken", 0)), int(m.get("conf", 0)))
    p = len(re.findall(r"TPASS", text))
    f = len(re.findall(r"TFAIL", text))
    b = len(re.findall(r"TBROK", text))
    c = len(re.findall(r"TCONF", text))
    return (p, f, b, c)


def sweep_guests():
    try:
        subprocess.run(["sudo", "-n", KILL], stdout=subprocess.DEVNULL,
                       stderr=subprocess.DEVNULL, timeout=20)
    except Exception:
        pass


def run_docker(test):
    try:
        r = subprocess.run(
            ["docker", "run", "--rm", "--platform", "linux/arm64", DOCKER_IMAGE,
             "sh", "-c", f"/opt/ltp/testcases/bin/{test} 2>&1"],
            capture_output=True, text=True, timeout=DOCKER_TIMEOUT)
        return r.stdout + r.stderr, r.returncode
    except subprocess.TimeoutExpired:
        return "<docker timeout>", 124


def run_carrick(test):
    sweep_guests()
    try:
        r = subprocess.run(
            [CARRICK, "run", CARRICK_IMAGE, "--raw", "--fs", "host",
             "/bin/sh", "-c", f"/opt/ltp/testcases/bin/{test}"],
            capture_output=True, text=True, timeout=CARRICK_TIMEOUT)
        out, rc = r.stdout + r.stderr, r.returncode
    except subprocess.TimeoutExpired:
        out, rc = "<carrick timeout>", 124
    sweep_guests()
    # Strip carrick's own scratch warnings before parsing.
    out = "\n".join(l for l in out.splitlines()
                    if "case-insensitive" not in l and "Pass `--fs" not in l)
    return out, rc


def classify(dverd, drc, cverd, crc):
    """A test is a valid differential signal ONLY when Docker (the oracle)
    CLEANLY PASSES it — passed>0, no fails/breaks. If Docker itself fails,
    breaks, skips (TCONF), or produces nothing (e.g. its own seccomp blocks
    the syscall), the test isn't a usable oracle on this image → NO_ORACLE,
    excluded from the verified-MATCH denominator. This keeps the headline
    number honest: it measures carrick vs a KNOWN-GOOD Linux verdict."""
    dp, df, db, dc = dverd
    cp, cf, cb, cc = cverd
    docker_clean_pass = dp > 0 and df == 0 and db == 0
    if not docker_clean_pass:
        return "NO_ORACLE"
    # From here Docker cleanly passed → carrick is judged against that.
    if crc == 124:
        return "TIMEOUT"
    if cb > 0:
        return "TBROK"          # carrick framework setup broke
    if cp > 0 and cf == 0 and cb == 0 and cverd == dverd:
        return "MATCH"          # same clean pass, same counts
    if cp > 0 and cf == 0 and cb == 0 and cp != dp:
        return "MATCH_PARTIAL"  # carrick passed, no fails, but a different
                                # (usually lower) count — fewer subtests ran
    return "DIFF"               # carrick failed / produced nothing / diverged


def load_done():
    done = {}
    if os.path.exists(RESULTS):
        with open(RESULTS) as f:
            for line in f:
                try:
                    rec = json.loads(line)
                    done[rec["test"]] = rec
                except Exception:
                    pass
    return done


def tally():
    done = load_done()
    by_area = {}
    for rec in done.values():
        a = rec["area"]
        by_area.setdefault(a, {}).setdefault(rec["class"], 0)
        by_area[a][rec["class"]] += 1
    classes = ["MATCH", "MATCH_PARTIAL", "DIFF", "TBROK", "TIMEOUT", "NO_ORACLE"]
    print(f"{'area':12s} " + " ".join(f"{c:>9s}" for c in classes) + f" {'total':>6s}")
    tot = {c: 0 for c in classes}
    for a in sorted(by_area):
        row = by_area[a]
        n = sum(row.values())
        print(f"{a:12s} " + " ".join(f"{row.get(c,0):9d}" for c in classes) + f" {n:6d}")
        for c in classes:
            tot[c] += row.get(c, 0)
    grand = sum(tot.values())
    print(f"{'TOTAL':12s} " + " ".join(f"{tot[c]:9d}" for c in classes) + f" {grand:6d}")
    # Honest denominator = tests with a valid oracle (Docker cleanly passed).
    oracle = grand - tot["NO_ORACLE"]
    good = tot["MATCH"] + tot["MATCH_PARTIAL"]
    if oracle:
        print(f"\nverified-MATCH: {tot['MATCH']}/{oracle} = "
              f"{100*tot['MATCH']/oracle:.0f}% strict "
              f"({good}/{oracle} = {100*good/oracle:.0f}% incl. partial-pass) "
              f"of oracle-valid tests; {tot['NO_ORACLE']} NO_ORACLE excluded; "
              f"swept {grand} of ~1436.")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--area", action="append", default=[])
    ap.add_argument("--limit", type=int, default=0)
    ap.add_argument("--list", action="store_true")
    ap.add_argument("--tally", action="store_true")
    args = ap.parse_args()

    if args.tally:
        tally()
        return

    with open(INVENTORY) as f:
        inv = json.load(f)
    areas = args.area or sorted(inv.keys())
    queue = []
    for a in areas:
        for t in inv.get(a, []):
            queue.append((a, t))

    if args.list:
        for a, t in queue:
            print(f"{a}\t{t}")
        print(f"# {len(queue)} tests in areas: {areas}", file=sys.stderr)
        return

    done = load_done()
    todo = [(a, t) for (a, t) in queue if t not in done]
    if args.limit:
        todo = todo[: args.limit]
    print(f"baseline: {len(todo)} to run ({len(done)} already recorded) "
          f"in areas {areas}", flush=True)

    os.makedirs(os.path.dirname(RESULTS), exist_ok=True)
    with open(RESULTS, "a") as out:
        for i, (area, test) in enumerate(todo, 1):
            dtext, drc = run_docker(test)
            ctext, crc = run_carrick(test)
            dverd, cverd = parse_verdict(dtext), parse_verdict(ctext)
            cls = classify(dverd, drc, cverd, crc)
            rec = {"test": test, "area": area, "class": cls,
                   "docker": dverd, "carrick": cverd,
                   "drc": drc, "crc": crc, "ts": int(time.time())}
            out.write(json.dumps(rec) + "\n")
            out.flush()
            print(f"[{i}/{len(todo)}] {cls:9s} {area}/{test} "
                  f"docker{dverd} carrick{cverd}", flush=True)


if __name__ == "__main__":
    main()
