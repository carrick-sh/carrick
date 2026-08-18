"""Deterministic reducer for the `cpython-threading` gating regression.

Both failing rows (`test_main_thread_after_fork`,
`test_2_join_in_forked_process`) reduce to this: a python process imports
`test.support`, forks, and waits.  The CHILD runs an ordinary interpreter
shutdown; the PARENT then SIGSEGVs (or aborts with `free(): invalid
pointer`) in its own shutdown, because one 16 KiB granule of its live
pymalloc arena now holds the CHILD's writes.

Run it under the canonical lane:

    carrick run --rm --raw --fs host -v <dir>:/probe \
      localhost:5050/cpython-test:3.12.13 \
      /bin/sh -c '/usr/local/bin/python3 /probe/cpython-fork-shutdown-parent-segv.py 8'

Docker: `BAD_ITERS 0 of 8`.  Carrick: iteration 0 passes and every later
iteration fails, 100% reproducibly.

Two ingredients are load-bearing and were each isolated in a fresh carrier
(one `carrick run` per case, because the trigger accumulates):

  * a PREVIOUS python process must have imported `test.support`, so the
    payload reads `.pyc` files that process wrote.  `-B` on the predecessor,
    or deleting `__pycache__` between the two, makes it pass.  `import
    asyncio` / `import unittest` / `/bin/true` / a bare-fork python
    predecessor do NOT arm it.
  * the child must run a FULL interpreter shutdown.  `os._exit(0)`,
    `gc.collect()`, `malloc_trim(0)` and an `sbrk` shrink in the child all
    leave the parent healthy.

The corruption is present the instant the parent reaps: a single
`gc.collect()` after `waitpid` crashes in `_PyObject_GC_UNTRACK` on
`str x3,[x2]` with `_gc_prev == 0`.
"""

import subprocess
import sys

CODE = "from test import support\nimport os\npid = os.fork()\nif pid:\n    os.waitpid(pid, 0)\n"


def main() -> int:
    reps = int(sys.argv[1]) if len(sys.argv) > 1 else 8
    bad = 0
    for i in range(reps):
        proc = subprocess.run(
            [sys.executable, "-X", "faulthandler", "-I", "-c", CODE],
            capture_output=True,
            check=False,
        )
        status = "OK" if proc.returncode == 0 else "BAD"
        print(f"iter {i}: rc={proc.returncode} {status}", flush=True)
        if proc.returncode != 0:
            bad += 1
            print(
                "  ERR: " + proc.stderr.decode(errors="replace").strip()[:400],
                flush=True,
            )
    print(f"BAD_ITERS {bad} of {reps}", flush=True)
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
