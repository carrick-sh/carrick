"""Does a forked guest child EVER publish a blocked run state?

`/proc/<pid>/stat` field 3 is the state character. LTP's
`TST_PROCESS_STATE_WAIT(pid,'S',0)` polls it every 1 ms with NO timeout, so a
child that never reads `S` hangs the parent forever — which is what makes
`ltp-futex_cmp_requeue01` a 989-row cluster.

This probe forks one child per BLOCKING-WAIT KIND and reads each child's state
once the cohort has settled. It deliberately spans four kinds, because the
answer decides how wide the defect is: if only the shared futex reads `R` it is
a futex bug, and if all four do it is the forked child's run-state publication.

Measured 2026-08-18 on signed carrick vs the native-arm64 Docker oracle:

    kind            Docker   carrick
    pipe_read         S        R
    nanosleep         S        R
    shared_futex      S        R
    private_futex     S        R

All four. No forked child ever publishes a blocked state. Note also that
carrick renders the child's comm as the fork-time placeholder
`(hvpatch-child-of-2)` where Docker shows the inherited `(python3)`, which
points at the same record: `/proc/<pid>` is being rendered from the fork-time
seed rather than from anything the child publishes afterwards.

RED: any kind reads a state other than `S`. Run under carrick and under Docker
one at a time, never concurrently.
"""

import os, time, signal, ctypes, ctypes.util
libc = ctypes.CDLL(ctypes.util.find_library("c") or "libc.so.6", use_errno=True)
libc.mmap.restype = ctypes.c_void_p
libc.mmap.argtypes=[ctypes.c_void_p,ctypes.c_size_t,ctypes.c_int,ctypes.c_int,ctypes.c_int,ctypes.c_long]
class Ts(ctypes.Structure): _fields_=[("s",ctypes.c_long),("ns",ctypes.c_long)]

def state(pid):
    try: return open(f"/proc/{pid}/stat").read().split(") ")[1][:1]
    except Exception: return "?"

kinds = {}
# 1. blocked on a pipe read
r, w = os.pipe()
pid = os.fork()
if pid == 0:
    os.close(w); os.read(r, 1); os._exit(0)
kinds["pipe_read"] = pid
# 2. blocked in nanosleep
pid = os.fork()
if pid == 0:
    time.sleep(300); os._exit(0)
kinds["nanosleep"] = pid
# 3. blocked in a SHARED futex
page = libc.mmap(None, 4096, 3, 0x01|0x20, -1, 0)
wd = ctypes.cast(page, ctypes.POINTER(ctypes.c_uint)); wd[0]=0
pid = os.fork()
if pid == 0:
    libc.syscall(98, ctypes.c_void_p(page), 0, ctypes.c_uint(0), ctypes.byref(Ts(300,0)), None, 0)
    os._exit(0)
kinds["shared_futex"] = pid
# 4. blocked in a PRIVATE futex (FUTEX_WAIT_PRIVATE = 128)
priv = libc.mmap(None, 4096, 3, 0x02|0x20, -1, 0)
pw = ctypes.cast(priv, ctypes.POINTER(ctypes.c_uint)); pw[0]=0
pid = os.fork()
if pid == 0:
    libc.syscall(98, ctypes.c_void_p(priv), 128, ctypes.c_uint(0), ctypes.byref(Ts(300,0)), None, 0)
    os._exit(0)
kinds["private_futex"] = pid

time.sleep(1.5)
for k, pid in kinds.items():
    print(f"{k:15s} pid={pid} state={state(pid)}")
for pid in kinds.values():
    os.kill(pid, signal.SIGKILL)
    try: os.waitpid(pid, 0)
    except ChildProcessError: pass
