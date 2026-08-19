# `cpython-importlib` SIGSEGV — reduced and localized (2026-08-18)

349 diverging rows. Carrick crashes where the oracle passes 1,191 assertions.

## Reducer (~1 s, intermittent, roughly 1 run in 2)

```sh
CARRICK_RUN_ID=lk timeout 90 ./target/release/carrick run --name lk \
  --max-traps 18446744073709551615 --raw --fs host \
  localhost:5050/cpython-test:3.12.13 \
  /usr/local/bin/python3 -m unittest test.test_importlib.test_locks
```

`Segmentation fault (core dumped)`, exit 139, in
`Source_DeadlockAvoidanceTests.test_deadlock` / `test_no_deadlock`. Under
`-m test` regrtest instead, Python's faulthandler intercepts and prints a guest
traceback with the threads in `threading.notify_all` -> `Condition._release`;
under plain `unittest` there is no faulthandler, so the guest really dies and
carrick writes a core.

## Getting a core

The guest's `core_pattern` is `core` and `ulimit -c` is already `unlimited`, so
the core lands in the guest CWD — **not** on a `-v` bind mount, and the crash is
intermittent, so loop INSIDE one guest and copy the core out when it appears:

```sh
... -v "$OUT:/out" ... /bin/sh -c 'ulimit -c unlimited; cd /tmp; i=0
  while [ $i -lt 8 ]; do rm -f /tmp/core
    /usr/local/bin/python3 -m unittest test.test_importlib.test_locks >/dev/null 2>&1
    [ -f /tmp/core ] && { cp /tmp/core /out/core; break; }; i=$((i+1)); done'
```

`carrick debug core <core>` then summarizes it.

## What the core says

- `signal: 11`, `signal_code: 1` (SEGV_MAPERR), **`fault_address: 0`** — a NULL
  dereference, not a wild pointer.
- Faulting thread `tid 44` of **11 threads**, `x0 = 0`,
  `pc = 0x6000196604`, `sp = 0x600333f640`.
- That PC is inside `/usr/local/lib/libpython3.12.so.1.0`, mapped at
  `0x6000010000`, so file offset `0x186604`. `nm -D` puts
  `_PyEval_EvalFrameDefault` at `0x185e60`, i.e. the fault is at
  **`_PyEval_EvalFrameDefault+0x7a4`** — the same address an earlier
  investigation recorded, now with a preserved core behind it.

So the Python bytecode interpreter dereferences NULL while eleven threads are
contending on a lock. Something carrick does corrupts a Python object or frame
pointer; this is a memory-integrity bug, not a missing syscall.

## What it is NOT

- **Not the M:N vCPU admission path.** 3/6 runs crash with reclaim ON and 3/6
  with `CARRICK_HVF_VCPU_RECLAIM=0`, so it is independent of the bound that
  explained `go-os_exec`, `cpython-threading` and `asyncio`.
- Not load-only: it reproduces standalone on a quiet host.

## Next step

Attribute the corruption. The interpreter-visible symptom is a NULL where a
live object pointer belongs, under heavy thread contention — the same family as
the fork/COW row-drop fixed in `6bbf968c6`, so start by asking whether any
stage-1/stage-2 or frame-inventory publication can be observed torn by a
sibling thread. The core is reproducible on demand with the loop above.
