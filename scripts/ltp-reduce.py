#!/usr/bin/env python3
"""ltp-reduce — collapse an LTP DIFF into a focused, syscall-level triage card.

The sweep (ltp-baseline.py) records only verdict COUNTS [pass,fail,brok,conf].
That tells you a test diverges, not WHICH assertion or WHICH syscall. This tool
does the "Reduce" focusing move (see the ltp-conformance skill) mechanically:

  1. Run the test under Docker linux/arm64 (the oracle) and capture its
     per-line TPASS/TFAIL/TCONF assertions.
  2. Run it under carrick with CARRICK_TRACE_TRAPS=1 — a non-root, non-DTrace
     per-syscall stream (entry args + return/errno). `carrick trace` auto-sudos
     and can mask a non-root divergence, so this path is deliberately direct.
  3. Align the assertion lines, find the first divergence, and connect it to the
     syscall in carrick's trace whose return diverges (or, for a hang, the last
     syscall with no return line — the one carrick wedged in).
  4. Emit a markdown triage card → docs/ltp-baseline/reductions/<test>.md.

The card is the input to writing a conformance probe: it names the syscall, its
args, what Docker expects, and what carrick gives. It does NOT replace the probe
(the probe is the durable line-exact gate) — it removes the hand-tracing.

Usage:
  scripts/ltp-reduce.py mknod06 epoll_ctl05 ...      # explicit tests
  scripts/ltp-reduce.py --from-diffs                 # all current diffs.json
  scripts/ltp-reduce.py --from-diffs --class TIMEOUT # only the hangs
  scripts/ltp-reduce.py --from-diffs --area ipc --limit 8

SERIAL constraint: runs carrick (HVF + shared kill.sh). Do NOT run while a sweep
is in flight.
"""
import argparse
import json
import os
import re
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DIFFS = os.path.join(ROOT, "docs", "ltp-baseline", "diffs.json")
OUTDIR = os.path.join(ROOT, "docs", "ltp-baseline", "reductions")
CARRICK = os.environ.get("CARRICK", os.path.join(ROOT, "target", "release", "carrick"))
KILL = os.environ.get("KILL", os.path.join(ROOT, "scripts", "sudo", "kill.sh"))
DOCKER_IMAGE = os.environ.get("LTP_DOCKER_IMAGE", "ltp:arm64")
CARRICK_IMAGE = os.environ.get("LTP_CARRICK_IMAGE", "localhost:5050/ltp:arm64")
CARRICK_TIMEOUT = int(os.environ.get("LTP_CARRICK_TIMEOUT", "45"))
DOCKER_TIMEOUT = int(os.environ.get("LTP_DOCKER_TIMEOUT", "60"))
os.environ.setdefault("CARRICK_INSECURE_REGISTRIES", "localhost:5050")

ANSI = re.compile(r"\x1b\[[0-9;]*m")
VERDICT = re.compile(r"\b(TPASS|TFAIL|TCONF|TBROK|TWARN)\b\s*:?\s*(.*)")
# errno mentioned in an LTP assertion message: "errno:14", "errno=EINVAL (22)",
# "EINVAL (22)", "TEST_ERRNO=…". Capture either the number or the symbol.
ERRNO_NUM = re.compile(r"errno[:=]\s*(\d+)")
ERRNO_SYM = re.compile(r"\b(E[A-Z0-9]{2,})\b")

# Entry:  [tid#N ]trap#K: x8=NR (name) x0=0x.. x1=0x.. ...
# Return: [tid#N ]trap#K:   -> errno=N (NAME)   |   -> ret=0x.. (N)
# Forked children restart trap# at 1, so key by (tid, k) to avoid collisions.
TRAP_ENTRY = re.compile(
    r"(?:tid#(\d+)\s+)?trap#(\d+):\s+x8=(\d+)\s+\(([^)]*)\)\s+(.*)")
TRAP_RET = re.compile(
    r"(?:tid#(\d+)\s+)?trap#(\d+):\s+->\s+(errno=(\d+)\s+\(([^)]*)\)|ret=(\S+)\s+\((-?\d+)\))")


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
        return ANSI.sub("", r.stdout + r.stderr), r.returncode
    except subprocess.TimeoutExpired:
        return "<docker timeout>", 124


TRAP_LINE = re.compile(r"trap#\d+:")


def run_carrick_traced(test):
    """Run under carrick with the per-syscall trap stream on stderr. Returns
    (test_output, trap_stream, rc). The trap stream and the LTP framework's own
    stderr share fd 2 and interleave, so split them: lines matching `trap#N:`
    are the trap stream, everything else is test output (LTP writes TPASS/TFAIL
    to BOTH stdout and stderr). kill.sh brackets the run (wedged guests)."""
    sweep_guests()
    env = dict(os.environ, CARRICK_TRACE_TRAPS="1")
    try:
        r = subprocess.run(
            [CARRICK, "run", CARRICK_IMAGE, "--raw", "--fs", "host",
             "/bin/sh", "-c", f"/opt/ltp/testcases/bin/{test}"],
            capture_output=True, text=True, timeout=CARRICK_TIMEOUT, env=env)
        stdout, stderr, rc = r.stdout, r.stderr, r.returncode
    except subprocess.TimeoutExpired as e:
        stdout = e.stdout.decode() if isinstance(e.stdout, bytes) else (e.stdout or "")
        stderr = e.stderr.decode() if isinstance(e.stderr, bytes) else (e.stderr or "")
        rc = 124
    sweep_guests()
    trap_lines, test_err = [], []
    for line in stderr.splitlines():
        (trap_lines if TRAP_LINE.search(line) else test_err).append(line)
    out = "\n".join(l for l in ANSI.sub("", stdout + "\n" + "\n".join(test_err)).splitlines()
                    if "case-insensitive" not in l and "Pass `--fs" not in l)
    return out, "\n".join(trap_lines), rc


def parse_assertions(text):
    """Per-line LTP assertions → [(verdict, errno_or_None, message)]."""
    out = []
    for line in text.splitlines():
        line = ANSI.sub("", line)
        m = VERDICT.search(line)
        if not m:
            continue
        verdict, msg = m.group(1), m.group(2).strip()
        if verdict in ("TWARN",):  # carry warnings but don't align on them
            out.append((verdict, None, msg))
            continue
        errno = None
        mn = ERRNO_NUM.search(msg)
        if mn:
            errno = int(mn.group(1))
        else:
            ms = ERRNO_SYM.search(msg)
            if ms:
                errno = ms.group(1)
        out.append((verdict, errno, msg))
    return out


def parse_traps(stream):
    """Trap stream → ordered list of dicts {k,tid,nr,name,args,ret} where ret is
    ('errno', n, name) | ('ret', n) | None (no return line seen → wedged)."""
    traps = {}
    order = []
    for line in stream.splitlines():
        me = TRAP_ENTRY.search(line)
        if me:
            tid, k, nr, name, args = me.groups()
            key = (tid, int(k))
            traps[key] = {"k": int(k), "tid": tid, "nr": int(nr), "name": name,
                          "args": args.strip(), "ret": None}
            order.append(key)
            continue
        mr = TRAP_RET.search(line)
        if mr:
            tid, k = mr.group(1), int(mr.group(2))
            key = (tid, k)
            if key in traps:
                if mr.group(4) is not None:
                    traps[key]["ret"] = ("errno", int(mr.group(4)), mr.group(5))
                else:
                    traps[key]["ret"] = ("ret", int(mr.group(7)))
    return [traps[key] for key in order if key in traps]


def assertion_summary(verdict_lines):
    return [v for v, _, _ in verdict_lines if v in ("TPASS", "TFAIL", "TCONF", "TBROK")]


def fmt_assertion(a):
    if a is None:
        return "—"
    v, e, msg = a
    es = "" if e is None else f" [errno {e}]"
    return f"{v}{es}: {msg[:70]}"


def reduce_test(test, area="?", verbose=False):
    dout, drc = run_docker(test)
    cout, traps_stream, crc = run_carrick_traced(test)
    da = parse_assertions(dout)
    ca = parse_assertions(cout)
    traps = parse_traps(traps_stream)

    # Align TPASS/TFAIL/TCONF/TBROK assertions by ordinal (ignore TWARN/TINFO).
    da_seq = [a for a in da if a[0] in ("TPASS", "TFAIL", "TCONF", "TBROK")]
    ca_seq = [a for a in ca if a[0] in ("TPASS", "TFAIL", "TCONF", "TBROK")]

    lines = []
    w = lines.append
    hang = (crc == 124)
    w(f"# reduction: {test}   (area: {area})")
    w("")
    w(f"- docker rc={drc}  ({len(da_seq)} assertions)")
    w(f"- carrick rc={crc}  ({len(ca_seq)} assertions){'  ⟵ HANG/TIMEOUT' if hang else ''}")
    w(f"- carrick traps observed: {len(traps)}")
    w("")

    # --- assertion alignment ---
    w("## assertion diff (docker oracle ‖ carrick)")
    w("```")
    n = max(len(da_seq), len(ca_seq))
    first_div = None
    for i in range(n):
        d = da_seq[i] if i < len(da_seq) else None
        c = ca_seq[i] if i < len(ca_seq) else None
        diverge = (
            d is None or c is None or d[0] != c[0]
            or (d[1] is not None and c[1] is not None and str(d[1]) != str(c[1]))
        )
        mark = "  ✗" if diverge else "  ✓"
        if diverge and first_div is None:
            first_div = (i, d, c)
        w(f"[{i+1:2d}]{mark}")
        w(f"   docker : {fmt_assertion(d)}")
        w(f"   carrick: {fmt_assertion(c)}")
    if n == 0:
        w("(no per-line assertions parsed on either side)")
    w("```")
    w("")

    # --- syscall localisation ---
    w("## syscall localisation")
    if hang:
        # The wedge: last entry with no return line. (When the trap stream is
        # truncated by the kill, the final entries lack returns; the *last* one
        # is the syscall carrick never returned from.)
        no_ret = [t for t in traps if t["ret"] is None]
        culprit = no_ret[-1] if no_ret else (traps[-1] if traps else None)
        if culprit:
            w(f"HANG: last syscall with no return (wedged here):")
            w("```")
            w(f"  trap#{culprit['k']} {culprit['name']}(nr={culprit['nr']}) {culprit['args']}")
            w(f"     -> (never returned)")
            w("```")
            w("Tail of the trap stream (last 12):")
            w("```")
            for t in traps[-12:]:
                rs = ("-> " + _ret_str(t["ret"])) if t["ret"] else "-> (no return)"
                w(f"  trap#{t['k']:>4} {t['name']:<16} {rs}")
            w("```")
        else:
            w("(no traps parsed — was CARRICK_TRACE_TRAPS honored? check the raw stream)")
    elif first_div is not None:
        i, d, c = first_div
        w(f"First divergent assertion is #{i+1}:")
        w(f"  docker : {fmt_assertion(d)}")
        w(f"  carrick: {fmt_assertion(c)}")
        # Connect to a syscall: find carrick traps whose returned errno matches
        # carrick's (wrong) errno on this assertion, or whose ret diverges.
        c_errno = c[1] if (c and isinstance(c[1], int)) else None
        d_errno = d[1] if (d and isinstance(d[1], int)) else None
        cands = []
        for t in traps:
            if t["ret"] and t["ret"][0] == "errno":
                if c_errno is not None and t["ret"][1] == c_errno:
                    cands.append((t, "carrick errno here"))
        # Always list syscalls that returned an errno (the usual culprits).
        errno_traps = [t for t in traps if t["ret"] and t["ret"][0] == "errno"]
        w("")
        if cands:
            w("Candidate diverging syscall(s) — carrick returned the assertion's errno:")
            w("```")
            for t, why in cands:
                w(f"  trap#{t['k']} {t['name']}(nr={t['nr']}) {t['args']}")
                w(f"     -> {_ret_str(t['ret'])}   ({why})")
            w("```")
        if d_errno is not None or c_errno is not None:
            w(f"Probe target: docker expects errno {d_errno}, carrick gives errno {c_errno}.")
        w("")
        w("All syscalls that returned an errno (scan for the culprit):")
        w("```")
        for t in errno_traps[-20:]:
            w(f"  trap#{t['k']:>4} {t['name']:<16} {t['args'][:48]}  -> {_ret_str(t['ret'])}")
        if not errno_traps:
            w("  (none — divergence may be a wrong success VALUE, not an errno;"
              " inspect ret= lines)")
        w("```")
    else:
        w("No assertion-level divergence found, yet the sweep flagged this as a "
          "DIFF — likely a COUNT mismatch (carrick ran fewer subtests) or a "
          "summary-only test. Compare the assertion counts above.")
    w("")

    if verbose:
        w("## raw carrick stdout")
        w("```")
        w(cout[:3000])
        w("```")

    card = "\n".join(lines) + "\n"
    os.makedirs(OUTDIR, exist_ok=True)
    path = os.path.join(OUTDIR, f"{test}.md")
    with open(path, "w") as f:
        f.write(card)
    return card, path, (hang, first_div is not None)


def _ret_str(ret):
    if ret is None:
        return "(no return)"
    if ret[0] == "errno":
        return f"errno={ret[1]} ({ret[2]})"
    return f"ret={ret[1]}"


def load_diffs(cls=None, area=None):
    with open(DIFFS) as f:
        d = json.load(f)
    out = []
    for rec in d:
        if cls and rec.get("class") != cls:
            continue
        if area and rec.get("area") != area:
            continue
        out.append((rec["test"], rec.get("area", "?")))
    return out


def main():
    ap = argparse.ArgumentParser(description="Reduce an LTP DIFF to a triage card")
    ap.add_argument("tests", nargs="*", help="explicit test names")
    ap.add_argument("--from-diffs", action="store_true",
                    help="pull tests from docs/ltp-baseline/diffs.json")
    ap.add_argument("--class", dest="cls", help="filter diffs by class (DIFF/TIMEOUT/TBROK)")
    ap.add_argument("--area", help="filter diffs by area")
    ap.add_argument("--limit", type=int, default=0, help="cap number of tests")
    ap.add_argument("--verbose", action="store_true", help="include raw carrick stdout")
    args = ap.parse_args()

    work = [(t, "?") for t in args.tests]
    if args.from_diffs:
        work += load_diffs(args.cls, args.area)
    if not work:
        ap.error("give test names or --from-diffs")
    if args.limit:
        work = work[:args.limit]

    print(f"reducing {len(work)} test(s) -> {OUTDIR}\n")
    for test, area in work:
        print(f"=== {test} ({area}) ===")
        try:
            card, path, _ = reduce_test(test, area, args.verbose)
        except Exception as e:
            print(f"  ERROR: {e}")
            continue
        print(card)
        print(f"  [card written: {os.path.relpath(path, ROOT)}]\n")


if __name__ == "__main__":
    main()
