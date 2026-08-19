# What else can carrick answer without leaving the guest?

## The framing correction that matters

"Decouple from the OS syscall" is the wrong target on its own. Measured on this
host, there are FOUR tiers, not two:

| tier | what happens | cost |
|---|---|---:|
| 0 | pure guest userspace (vDSO) | **199 ns** (`clock_gettime` via libc) |
| 1 | EL1 shim: serviced inside the guest, NO VM exit | **135 ns** (`getpid`, `gettid`) |
| 2 | VM exit -> carrick's kernel, no Darwin syscall | **~1,850 ns** |
| 3 | VM exit -> carrick -> Darwin syscall | ~1,850 ns + host work |

The gap that dominates is **tier 2 vs tier 1: 13.7x**, and it is paid whether or
not Darwin is involved. A large set of syscalls ALREADY touch no Darwin syscall —
`uname`, `getrlimit`/`prlimit`, `sigaction`/`sigprocmask`, `sched_getaffinity`,
`fcntl(F_GETFD/F_GETFL)`, `epoll_create`/`epoll_ctl`, `getpgrp`, `getcpu`,
anything answered from the in-memory VFS layers — and every one still costs
~1,850 ns because the VM exit is the price, not the host call.

So the question to ask of each syscall is not "does this reach Darwin?" but
**"can the guest answer this from memory that is already mapped to it?"**

`clock_gettime` is the proof: it is tier 0 today at 199 ns against 2,115 ns for
the raw syscall (10.6x), because the answer lives in a page the guest can read.
Nothing about that required removing a Darwin call — Darwin was never in the path.

## What tier 1 needs that it does not have

The EL1 shim can answer a syscall when the value is (a) in guest-readable memory
or a non-trapping register, and (b) kept coherent by whoever mutates it.

Today it has exactly two homes:

- the **per-process identity page** — one page, shared by every vCPU in the
  process. `getpid` lives here.
- **`CONTEXTIDR_EL1`** — one per-vCPU register. `gettid` lives here, and its
  history is a warning: the tid moved registers and the vCPU restore path was not
  updated, so the fast path was silently dead for every threaded workload until
  2026-08-19.

The missing home is a **per-THREAD memory slot**, and it already exists: `SP_EL1`
points at this vCPU's syscall mailbox page, so the shim can do `ldr w0,[sp,#OFF]`
with no extra register pressure and no new mapping. That one addition unblocks
every per-thread value.

## Ranked candidates

**Blocked on the per-thread slot (credentials are per-THREAD on Linux):**

- `getuid`, `geteuid`, `getgid`, `getegid` — ~1,850 ns each today. Note the
  identity page's own comment forbids putting them there ("Linux credentials may
  diverge per thread, while this page is shared by every vCPU"), and that is
  correct: a stale credential answer is a security bug, not a slow path.
  Invalidation: the `setuid`/`setgid` families, `execve` with setuid bits,
  capability changes.

**Page-eligible now (per-process, no new machinery):**

- `getppid` — invalidation: reparenting (subreaper adoption, parent death).
- `getpgrp`, `getsid` — invalidation: `setpgid`, `setsid`.
- `umask` (read side) — invalidation: `umask` itself.

**Already tier 0, worth re-measuring rather than re-building:**

- `clock_gettime`/`gettimeofday`/`time` are on the vDSO at 199 ns. Native Linux
  vDSO is nearer 20-25 ns, so there may be ~8x left — but the 199 ns figure
  includes ctypes/Python call overhead that the raw-syscall figure also carries,
  so the honest next step is the SAME harness against the Docker oracle before
  assuming carrick's vDSO is slow.

**Deliberately not candidates:**

- Anything whose value carrick must observe atomically with a mutation it does
  not control (`rt_sigprocmask` write side, `futex`, fd-table mutations).
- Anything requiring the host (real I/O, blocking waits).

## Measure before wiring

Ranking these by intuition is how the last floor table ended up quoting a
`clock_gettime` cost real programs never pay. What decides the order is the
syscall HISTOGRAM of the real workloads (cold go-build, cpython, node), which
`carrick trace` can produce and which nobody has taken. A syscall that is fast to
wire but called 400 times a build is worth less than one called 4 million times.

## The other axis: amplification, not tiers

Separately from tier promotion, the biggest measured waste is carrick issuing
MANY Darwin calls per guest call — guest `open` -> 8.69 host opens on the cold
build. That is tier-3 work that no EL1 shim can help; it needs better lowering.
The two efforts are complementary and should not be confused: tier promotion
removes the exit, amplification work removes the host work behind it.
