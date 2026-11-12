# x86 KVM: starting a Python thread kills the carrier (idle peer FaultDoorbellWord(14))

Found while working on #2217 (main 70a498456, release build, real KVM).
This is where `py-thread` stops next once #1482 lets the heap regrow.

To get past #2217's heap crash without compiling any module, start a raw
`_thread` thread:

```
CARRICK_RUN_ID=t3 carrick run --rm -w /tmp python:3.12-slim python3 -P -c \
  'import _thread; _thread.start_new_thread(print,("x",)); import time; time.sleep(1)'
```

exits 125:

```
executor worker died index=1 error=hypervisor operation failed: idle CPL0 peer needs a host task handback: FaultDoorbellWord(14)
carrick: configuration refused: hypervisor operation failed: idle CPL0 peer needs a host task handback: FaultDoorbellWord(14)
```

The new thread runs on the idle peer (CPU 1) and takes a page fault (vector
14) that the peer's lane hands to the host as a fault doorbell. The idle lane
has no task lease to serve it, so the carrier dies. Not investigated
further. `_thread.get_ident`, `get_native_id`, `allocate_lock` and
`_set_sentinel` all work.

**Acceptance.** A red-first KVM witness (a second thread's first touch of
its stack or TLS on the idle peer), a fix that keeps the fault in ring, and
then the `py-thread` scoreboard row.
