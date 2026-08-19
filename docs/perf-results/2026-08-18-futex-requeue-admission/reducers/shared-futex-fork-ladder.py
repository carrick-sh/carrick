"""Where does LTP `futex_cmp_requeue01`'s time actually go, before any requeue?

The suite forks N children that park in a MAP_SHARED FUTEX_WAIT, then walks
`/proc/<pid>/stat` for EVERY child until it reads 'S' -- `TST_PROCESS_STATE_WAIT
(pid,'S',0)`, a 1 ms poll with NO timeout -- and only THEN issues the requeue.
Each child's own wait deadline is 5000 ms, so if fork+scan exceeds that, every
child has already left the futex when the requeue lands and the requeue
truthfully reports 0. That is exactly what the current artifact does: test 3
(100 waiters) returns 100 and PASSES, test 4 (the SAME 100 waiters, later in the
run) returns 0 with zero children woken.

This reducer reproduces ONLY the two pre-requeue phases and times them
separately. It issues no requeue at all, so a collapse here cannot be futex
semantics -- it is fork admission or /proc.

Two suspected costs, both structural:
  1. a shared-futex wait KEEPS its HVF vCPU lease when the pool looks spare
     (`vcpu_loop/threads.rs` -> `should_keep_vcpu_for_blocking_wait`), while the
     PRIVATE futex path reclaims unconditionally under a comment describing this
     exact workload;
  2. `/proc/<pid>/stat` rebuilds a whole-carrier census per read
     (`kernel/core.rs` live_processes + oom_score_adj_by_pid) and then finds the
     pid by linear scan -- Theta(N) work per call, issued N times.

RED: fork_ms shows a knee near the vCPU budget, and/or scan_ms is super-linear.
GREEN (and Docker): both linear and small.
"""

import ctypes, ctypes.util, os, sys, time

libc = ctypes.CDLL(ctypes.util.find_library("c") or "libc.so.6", use_errno=True)

FUTEX_WAIT, FUTEX_WAKE = 0, 1
SYS_futex = 98                      # aarch64
PROT_READ, PROT_WRITE = 1, 2
MAP_SHARED, MAP_ANON = 0x01, 0x20
MAP_FAILED = ctypes.c_void_p(-1).value

LADDER = [int(x) for x in (sys.argv[1:] or ["32", "64", "128", "256"])]
CHILD_TIMEOUT_SECS = 300            # >> the phases timed, so no child zombifies
SCAN_BOUND_S = 20.0

libc.mmap.restype = ctypes.c_void_p
libc.mmap.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_int,
                      ctypes.c_int, ctypes.c_int, ctypes.c_long]


class Timespec(ctypes.Structure):
    _fields_ = [("tv_sec", ctypes.c_long), ("tv_nsec", ctypes.c_long)]


def stat_state(pid):
    try:
        with open(f"/proc/{pid}/stat", "rb") as f:
            buf = f.read()
    except OSError:
        return None
    close = buf.rfind(b")")
    if close < 0:
        return None
    return buf[close + 1:].lstrip()[:1].decode("ascii", "replace")


for n in LADDER:
    page = libc.mmap(None, 4096, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANON, -1, 0)
    if page == MAP_FAILED:
        print(f"n={n} map=failed", flush=True)
        break
    word = ctypes.cast(page, ctypes.POINTER(ctypes.c_uint))
    word[0] = 0

    t0 = time.monotonic()
    pids = []
    for _ in range(n):
        pid = os.fork()
        if pid == 0:
            to = Timespec(CHILD_TIMEOUT_SECS, 0)
            # No FUTEX_PRIVATE_FLAG: this is the SHARED wait path.
            libc.syscall(SYS_futex, ctypes.c_void_p(page), FUTEX_WAIT,
                         ctypes.c_uint(0), ctypes.byref(to), None, 0)
            os._exit(0)
        pids.append(pid)
    fork_s = time.monotonic() - t0

    # TST_PROCESS_STATE_WAIT(pid, 'S', 0), bounded so we report instead of hang.
    # One settled pass over EVERY child: is the mispublication one child or
    # many, and is it positional? LTP stops at the first non-'S' child, which
    # hides that answer.
    time.sleep(1.0)
    from collections import Counter
    hist = Counter(stat_state(p) for p in pids)
    bad = [i for i, p in enumerate(pids) if stat_state(p) != "S"]
    print(f"    settled_states={dict(hist)} non_S_indices={bad[:8]}"
          f"{'...' if len(bad) > 8 else ''} non_S_count={len(bad)}", flush=True)

    t1 = time.monotonic()
    polls, stuck, seen, idx = 0, 0, None, -1
    for i, pid in enumerate(pids):
        deadline = time.monotonic() + SCAN_BOUND_S
        while True:
            polls += 1
            st = stat_state(pid)
            if st == "S":
                break
            if time.monotonic() >= deadline:
                stuck, seen, idx = pid, st, i
                break
            time.sleep(0.001)
        if stuck:
            break
    scan_s = time.monotonic() - t1

    # `seen` is the discriminator: 'R' means the child never reached its futex
    # (an admission problem); 'S' arriving late is timing; anything else --
    # including None for an unreadable /proc entry -- is a publication problem.
    print(f"n={n} fork_ms={fork_s*1000:.0f} scan_ms={scan_s*1000:.0f} "
          f"polls={polls} stuck_pid={stuck} stuck_idx={idx} stuck_state={seen!r} "
          f"fork_per_child_ms={fork_s*1000/n:.2f}", flush=True)

    # Wake-to-reap latency is the discriminator for a stuck child: if the
    # cohort was genuinely PARKED, one FUTEX_WAKE releases it and the reap is
    # immediate, so a 'R' reading was a stale run-state publication. If the
    # child never reached its futex at all, the wake finds no waiter and the
    # reap has to wait for the child to get scheduled and time out on its own.
    word[0] = 1
    t2 = time.monotonic()
    libc.syscall(SYS_futex, ctypes.c_void_p(page), FUTEX_WAKE, 0x7fffffff, None, None, 0)
    for pid in pids:
        try:
            os.waitpid(pid, 0)
        except ChildProcessError:
            pass
    print(f"    wake_to_reap_ms={(time.monotonic()-t2)*1000:.0f}", flush=True)
    libc.munmap(ctypes.c_void_p(page), 4096)
