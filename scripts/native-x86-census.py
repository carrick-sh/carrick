#!/usr/bin/env python3
# Parallel strict conformance census. Each probe runs in its OWN process group
# (start_new_session) so we reap its whole tree with killpg on timeout/finish —
# no global pkill, so parallel workers never kill each other. Strict OK = the
# guest reached `[native_run] exit=` AND asserted no failure (no =false/panic).
import os, sys, glob, signal, subprocess, concurrent.futures

RUNNER = sys.argv[1]
PROBES = sys.argv[2]
OUT    = sys.argv[3]
PAR    = int(sys.argv[4]) if len(sys.argv) > 4 else 6
TIMEOUT = int(sys.argv[5]) if len(sys.argv) > 5 else 20

def classify(o, timed_out):
    has_exit  = "[native_run] exit=" in o
    has_false = ("=false" in o) or ("panic" in o.lower())
    if has_exit and not has_false: return "OK"
    if has_exit and has_false:     return "EXIT_FALSE"
    if timed_out:                  return "TIMEOUT"
    if "dispatch outcome" in o:
        seg = o.split("outcome",1)[1].split()[0] if "outcome" in o else "?"
        return "OUT:" + seg.strip(".:,")
    if "no-progress" in o: return "NOPROG"
    if "guest fault" in o: return "FAULT"
    if "emit" in o.lower(): return "EMIT"
    return "OTHER"

def run_one(path):
    name = os.path.basename(path)
    env = dict(os.environ, CARRICK_MMAP_ARENA_GIB="1")
    try:
        p = subprocess.Popen([RUNNER, path], stdout=subprocess.PIPE,
                             stderr=subprocess.STDOUT, start_new_session=True, env=env)
    except Exception:
        return (name, "SPAWNERR")
    timed_out = False
    try:
        out, _ = p.communicate(timeout=TIMEOUT)
    except subprocess.TimeoutExpired:
        timed_out = True
        try: os.killpg(os.getpgid(p.pid), signal.SIGKILL)
        except Exception: pass
        try: out, _ = p.communicate(timeout=5)
        except Exception: out = b""
    # reap the whole group (orphaned guest fork/thread children) regardless
    try: os.killpg(os.getpgid(p.pid), signal.SIGKILL)
    except Exception: pass
    o = out.decode("utf-8", "replace") if out else ""
    return (name, classify(o, timed_out))

probes = sorted(p for p in glob.glob(PROBES + "/*")
                if os.path.isfile(p) and os.access(p, os.X_OK)
                and not p.endswith((".d", ".so")))
done = 0
ok = 0
with open(OUT, "w") as f, concurrent.futures.ThreadPoolExecutor(max_workers=PAR) as ex:
    futs = {ex.submit(run_one, p): p for p in probes}
    for fut in concurrent.futures.as_completed(futs):
        name, r = fut.result()
        f.write(f"{r}\t{name}\n"); f.flush()
        done += 1; ok += (r == "OK")
    f.write(f"CENSUS_DONE {done}\n")
print(f"done: {ok}/{done} OK")
