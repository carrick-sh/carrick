"""Reduce the HVPatch fork/vCPU-lease hold-and-wait deadlock.

Hold more live guest threads than the bounded vCPU pool has slots (the HVF
budget is min(hv_vm_get_max_vcpu_count, physical cores) -- 10 on the canonical
host), then fork repeatedly from that thread-saturated process.

A fork coordinator wins the quiesce barrier and only then waits for its child's
slot, while the siblings the barrier just parked are the only threads that can
release one. RED: this hangs (or takes minutes). GREEN: it prints DONE in a
couple of seconds.
"""

import os
import sys
import threading
import time

THREADS = int(os.environ.get("REDUCER_THREADS", "24"))
FORKS = int(os.environ.get("REDUCER_FORKS", "40"))
DEADLINE = float(os.environ.get("REDUCER_DEADLINE", "60"))

stop = threading.Event()
running = threading.Barrier(THREADS + 1)


def worker():
    running.wait()
    # Stay live and schedulable so the thread keeps asking for a vCPU slot.
    while not stop.is_set():
        time.sleep(0.001)


started = time.time()
workers = [threading.Thread(target=worker, daemon=True) for _ in range(THREADS)]
for t in workers:
    t.start()
running.wait()

for i in range(FORKS):
    if time.time() - started > DEADLINE:
        stop.set()
        print(f"TIMEOUT after {i} forks in {time.time()-started:.1f}s", flush=True)
        sys.exit(1)
    pid = os.fork()
    if pid == 0:
        os._exit(0)
    os.waitpid(pid, 0)

stop.set()
print(f"DONE {FORKS} forks under {THREADS} threads in {time.time()-started:.1f}s", flush=True)
