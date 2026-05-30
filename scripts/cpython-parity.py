#!/usr/bin/env python3
"""Differential CPython-regrtest parity: carrick vs Docker linux/arm64.

For each test module, run `python3 -m test -v --randseed 0 <module>` under BOTH
Docker (the oracle) and carrick, with the matching CPython Lib/test bind-mounted
into the image's stdlib path. Parse the unittest verbose output into a
{test_id: outcome} map on each side and diff. A carrick-only failure/error, a
divergent skip, a missing test, or a TIMEOUT/crash is a conformance gap.

Output: one JSON line per module to stdout (and a human summary to stderr).
Deterministic by construction — we compare outcome CATEGORIES per test id, never
timings/tracebacks. Skip *reasons* are recorded but only the skipped/ran
distinction gates parity.

Usage:
  scripts/cpython-parity.py [--carrick PATH] [--image IMG] [--testdir DIR]
                            [--timeout SECS] [--jsonl OUT] MODULE [MODULE...]
"""
import argparse, json, os, re, subprocess, sys, time, signal, random

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
# We mount the PARENT of Lib/test and put it on PYTHONPATH rather than bind-
# mounting test/ over the stdlib dir: carrick does not reflect a leaf bind-mount
# in its parent directory's readdir, so Python's FileFinder can't discover a
# `test` package mounted that way (it scandirs the parent). Mounting the parent
# makes `test` a real entry of the mount root, which both Docker and carrick
# enumerate identically.
MOUNT_DEST = "/opt/cpy"

# `<method> (<dotted.id>) ... <outcome>`  (unittest verbose)
LINE = re.compile(r"^(\S+) \(([\w.]+)\)(?: \[\d+\])? \.\.\. (.*)$")

def classify(rest):
    r = rest.strip()
    if r.startswith("ok"):
        return "ok", ""
    if r.startswith("FAIL"):
        return "FAIL", ""
    if r.startswith("ERROR"):
        return "ERROR", ""
    if r.startswith("skipped"):
        return "skipped", r[len("skipped"):].strip().strip("'\"")
    if r.startswith("expected failure"):
        return "xfail", ""
    if r.startswith("unexpected success"):
        return "uxsuccess", ""
    return "other", r

def parse(text):
    """-> (dict id->outcome, dict id->reason, summary dict)"""
    outcomes, reasons = {}, {}
    for line in text.splitlines():
        m = LINE.match(line)
        if not m:
            continue
        tid, rest = m.group(2), m.group(3)
        oc, reason = classify(rest)
        # First occurrence wins (a subtest failure may add later lines).
        outcomes.setdefault(tid, oc)
        if reason:
            reasons.setdefault(tid, reason)
    summary = {}
    mr = re.search(r"^Result:\s*(\w+)", text, re.M)
    summary["result"] = mr.group(1) if mr else None
    mt = re.search(r"Total tests:\s*run=(\d+)", text)
    summary["run"] = int(mt.group(1)) if mt else None
    # Module-level breakage that never reaches per-test lines.
    summary["import_error"] = ("ModuleNotFoundError" in text
                               or "Traceback (most recent call last)" in text and not outcomes)
    return outcomes, reasons, summary

def run_docker(module, image, testroot, timeout):
    cmd = ["docker", "run", "--rm", "--platform", "linux/arm64",
           "-v", f"{testroot}:{MOUNT_DEST}:ro", "-e", f"PYTHONPATH={MOUNT_DEST}", image,
           "python3", "-m", "test", "-v", "--randseed", "0", module]
    return _run(cmd, timeout)

def run_carrick(module, carrick, image, testroot, timeout, run_id):
    env = dict(os.environ)
    env["CARRICK_INSECURE_REGISTRIES"] = env.get("CARRICK_INSECURE_REGISTRIES", "localhost:5050")
    env["CARRICK_RUN_ID"] = run_id
    _kill(run_id)
    cmd = [carrick, "run", "-v", f"{testroot}:{MOUNT_DEST}:ro", "-e", f"PYTHONPATH={MOUNT_DEST}",
           image, "--raw", "--fs", "host",
           "/usr/local/bin/python3", "-m", "test", "-v", "--randseed", "0", module]
    out, rc, dur, timed = _run(cmd, timeout, env=env)
    _kill(run_id)
    # Strip carrick's own advisory lines (mirrors scripts/run-probe.sh).
    out = "\n".join(l for l in out.splitlines()
                    if "case-insensitive" not in l and "Pass --fs" not in l
                    and not l.startswith("Pass `--fs"))
    return out, rc, dur, timed

def _kill(run_id):
    sh = os.path.join(REPO, "scripts/sudo/kill.sh")
    subprocess.run(["sudo", "-n", sh, run_id],
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    subprocess.run(["pkill", "-9", "-f", f"carrick:{run_id}"],
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

def _run(cmd, timeout, env=None):
    t0 = time.time()
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout,
                           env=env, errors="replace")
        return (p.stdout + "\n" + p.stderr), p.returncode, time.time() - t0, False
    except subprocess.TimeoutExpired as e:
        out = (e.stdout or "") + "\n" + (e.stderr or "") if isinstance(e.stdout, str) \
              else ((e.stdout or b"").decode("utf-8", "replace") + "\n" +
                    (e.stderr or b"").decode("utf-8", "replace"))
        return out, None, time.time() - t0, True

def compare(module, dk, ck):
    d_oc, d_rsn, d_sum = dk
    c_oc, c_rsn, c_sum = ck
    ids = set(d_oc) | set(c_oc)
    diffs = []
    for tid in sorted(ids):
        do, co = d_oc.get(tid, "<absent>"), c_oc.get(tid, "<absent>")
        if do != co:
            diffs.append({"id": tid, "docker": do, "carrick": co,
                          "carrick_reason": c_rsn.get(tid, ""),
                          "docker_reason": d_rsn.get(tid, "")})
    return diffs, d_sum, c_sum

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("modules", nargs="*")
    ap.add_argument("--modules-file", default=None,
                    help="file with whitespace-separated module names (avoids shell word-split pitfalls)")
    ap.add_argument("--carrick", default=os.path.join(REPO, "target/release/carrick"))
    ap.add_argument("--image", default="python:3.12")
    ap.add_argument("--testroot", default="/tmp/cpy",
                    help="host dir CONTAINING the `test` package (mounted on PYTHONPATH)")
    ap.add_argument("--timeout", type=int, default=180)
    ap.add_argument("--jsonl", default=None)
    args = ap.parse_args()

    modules = list(args.modules)
    if args.modules_file:
        modules += open(args.modules_file).read().split()
    if not modules:
        ap.error("no modules given (positional args or --modules-file)")

    jf = open(args.jsonl, "a") if args.jsonl else None
    for module in modules:
        rid = f"cpy-{os.getpid()}-{random.randint(0, 1<<30)}"
        d_out, d_rc, d_dur, d_to = run_docker(module, args.image, args.testroot, args.timeout)
        c_out, c_rc, c_dur, c_to = run_carrick(module, args.carrick, args.image,
                                               args.testroot, args.timeout, rid)
        dk, ck = parse(d_out), parse(c_out)
        diffs, d_sum, c_sum = compare(module, dk, ck)

        if d_to:
            verdict = "DOCKER_TIMEOUT"     # oracle itself hung — exclude/ignore
        elif c_to:
            verdict = "CARRICK_TIMEOUT"    # a hang = blocked syscall (real gap)
        elif not dk[0] and not ck[0]:
            # Neither produced per-test lines: both import-failed/skipped wholesale.
            verdict = "BOTH_EMPTY" if d_sum == c_sum else "DIFF_EMPTY"
        elif diffs:
            verdict = "DIFF"
        else:
            verdict = "MATCH"

        rec = {"module": module, "verdict": verdict,
               "docker": {"n": len(dk[0]), "result": d_sum.get("result"),
                          "run": d_sum.get("run"), "to": d_to, "dur": round(d_dur, 1)},
               "carrick": {"n": len(ck[0]), "result": c_sum.get("result"),
                           "run": c_sum.get("run"), "to": c_to, "dur": round(c_dur, 1)},
               "ndiff": len(diffs), "diffs": diffs[:40]}
        print(json.dumps(rec))
        sys.stdout.flush()
        if jf:
            jf.write(json.dumps(rec) + "\n"); jf.flush()
        # human line to stderr
        sys.stderr.write(
            f"{verdict:14s} {module:28s} docker(n={len(dk[0])},{d_sum.get('result')}) "
            f"carrick(n={len(ck[0])},{c_sum.get('result')}) ndiff={len(diffs)} "
            f"[{d_dur:.0f}s/{c_dur:.0f}s]\n")
        sys.stderr.flush()
    if jf:
        jf.close()

if __name__ == "__main__":
    main()
