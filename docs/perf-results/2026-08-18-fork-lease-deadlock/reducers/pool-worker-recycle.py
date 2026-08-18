"""Reduce the `test_pool_worker_lifetime` stall that blocks both
`cpython-multiprocessing_fork` and `cpython-multiprocessing_forkserver`.

Both suites now clear the vCPU-admission bug and then stop at
`WithProcessesTestPoolWorkerLifetime.test_pool_worker_lifetime` after ~86
tests. That test builds a Pool with `maxtasksperchild`, so every worker exits
after N tasks and the pool must notice the exit and spawn a replacement. It is
therefore a repeated create/exit/reap cycle under a multi-threaded parent --
the shape of the already-recorded "lost child-exit wake" defect, where a
`wait4(-1)` parks before the child's exit is published.

Two probes, cheapest first, so a hang localizes itself:

  STAGE 1 (raw): fork children in a loop and reap with `wait4(-1)` from a
  process that also has live sibling threads. If this hangs, the defect is in
  child-exit publication versus the waiter's park, and multiprocessing is
  merely the messenger.

  STAGE 2 (Pool): the actual maxtasksperchild recycle, minus the rest of the
  CPython suite.

RED: a stage prints STAGE<n>-TIMEOUT or never returns. GREEN: both print OK.
"""

import multiprocessing
import os
import sys
import threading
import time

DEADLINE = float(os.environ.get("REDUCER_DEADLINE", "45"))
ROUNDS = int(os.environ.get("REDUCER_ROUNDS", "40"))
THREADS = int(os.environ.get("REDUCER_THREADS", "8"))


def stage1():
    stop = threading.Event()
    noise = [
        threading.Thread(target=lambda: [time.sleep(0.002) for _ in iter(lambda: not stop.is_set(), False)],
                         daemon=True)
        for _ in range(THREADS)
    ]
    for t in noise:
        t.start()

    started = time.time()
    reaped = 0
    for i in range(ROUNDS):
        if time.time() - started > DEADLINE:
            stop.set()
            print(f"STAGE1-TIMEOUT after {reaped} reaps in {time.time()-started:.1f}s", flush=True)
            return False
        pid = os.fork()
        if pid == 0:
            os._exit(7)
        # wait4(-1): the "any child" form, which is what parks.
        wpid, status = os.wait()
        assert wpid == pid, (wpid, pid)
        assert os.WEXITSTATUS(status) == 7, status
        reaped += 1
    stop.set()
    print(f"STAGE1-OK {reaped} fork/wait(-1) cycles under {THREADS} threads "
          f"in {time.time()-started:.1f}s", flush=True)
    return True


def stage1b():
    """The real discriminator: does WNOHANG ever block?

    `waitpid(pid, WNOHANG)` must return immediately, always -- it is the whole
    point of the flag. Static reading says carrick ignores the nohang argument
    and, in consuming mode, additionally requires the WAITING process's own
    task to be unreserved; a concurrent `fork` holds exactly that reservation
    from admission through child materialization. So a WNOHANG poll issued
    while a sibling thread forks should park for the duration of the fork.

    Measures the worst single WNOHANG call while another thread forks in a
    loop. Under Linux this is microseconds. RED: max call time tracks fork
    duration (milliseconds or worse).
    """
    stop = threading.Event()
    forked = []

    def forker():
        while not stop.is_set():
            pid = os.fork()
            if pid == 0:
                os._exit(0)
            forked.append(pid)
            time.sleep(0.001)

    t = threading.Thread(target=forker, daemon=True)
    t.start()

    started = time.time()
    worst = 0.0
    calls = 0
    while time.time() - started < 5.0:
        for pid in list(forked):
            t0 = time.perf_counter()
            try:
                os.waitpid(pid, os.WNOHANG)
            except ChildProcessError:
                pass
            dt = time.perf_counter() - t0
            calls += 1
            if dt > worst:
                worst = dt
            try:
                forked.remove(pid)
            except ValueError:
                pass
        time.sleep(0.0005)
    stop.set()
    t.join(timeout=5)
    verdict = "OK" if worst < 0.010 else "SLOW"
    print(f"STAGE1B-{verdict} {calls} WNOHANG calls during concurrent fork, "
          f"worst={worst*1000:.2f}ms (Linux: microseconds)", flush=True)
    return worst < 0.010


def _task(x):
    return x * 2


def stage2():
    started = time.time()
    # maxtasksperchild forces worker recycle: each worker exits after 1 task
    # and the pool must reap it and spawn a replacement.
    with multiprocessing.Pool(processes=3, maxtasksperchild=1) as pool:
        results = pool.map(_task, range(30))
    assert results == [x * 2 for x in range(30)], results
    print(f"STAGE2-OK pool recycled through 30 tasks in {time.time()-started:.1f}s", flush=True)
    return True


if __name__ == "__main__":
    multiprocessing.set_start_method(os.environ.get("REDUCER_START", "fork"), force=True)
    ok = stage1()
    if not ok:
        sys.exit(1)
    stage1b()
    stage2()
