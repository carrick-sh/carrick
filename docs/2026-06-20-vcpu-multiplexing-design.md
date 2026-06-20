# vCPU multiplexing: decoupling guest threads from host vCPUs

Status: DESIGN (2026-06-20). Supersedes the implicit "1 host vCPU per guest
thread, bound for the thread's lifetime" model. Motivated by #10 (bhyve
`hw.vmm.maxcpu`=8 caps thread-heavy Go), but it is a **cross-backend** change —
HVF and KVM lifetime-bind too; bhyve just hits the wall first because its cap is
lowest.

## The question this answers

> If the VMM imposes a hard limit on vCPUs, how do we run workloads that need
> more threads than that?

A Linux guest expects threads to be near-free. On an 8 GB / 4-core box
`kernel.threads-max` is **468,201** and per-process `RLIMIT_NPROC` is **234,100**
— scaling with RAM (~RAM_KB/16), *independent of core count*. Real programs (a Go
server, a JVM, nginx) routinely run dozens-to-hundreds of threads. No hypervisor
offers that many vCPUs: HVF caps ~64, bhyve at `hw.vmm.maxcpu` (= host ncpu, 8
here; a read-only loader tunable — raising it only moves the wall, never to 234k).

So the cap can NOT be "the number of guest threads." It has to be **the number of
guest threads RUNNING at one instant** — which is naturally bounded by the host's
core count regardless. The fix is to make a vCPU a *schedulable resource*, not a
per-thread fixture.

## Today's model (and why it breaks)

```
guest thread  <--- 1:1 --->  host thread  <--- 1:1 --->  host vCPU (lifetime)
   clone()                 std::thread::spawn          vm_activate_cpu(id++)
```

`crates/carrick-runtime/src/vcpu_loop/threads.rs` spawns one host thread per guest
thread; each calls `materialize_sibling` → a dedicated vCPU it holds until the
guest thread exits — *even while the thread is blocked in a futex or a host
syscall*, where the vCPU sits idle but allocated. bhyve's `add_sibling_vcpu` draws
monotonic ids, so the (cap+1)-th thread gets id ≥ `hw.vmm.maxcpu` →
`vm_activate_cpu` EINVAL. The current handling (`wait_for_vcpu_slot` is a no-op on
bhyve) logs the error and marks the thread exited — but `clone()` already returned
success to the guest, so Go waits forever on a thread that never ran. **A hang,
and a corrupting one** (the guest's thread accounting now disagrees with reality).

## Target model: a vCPU pool the guest threads time-share

```
M guest threads  <- 1:1 ->  M host threads  --- acquire/release --->  pool of N vCPUs
   (up to 234k)              (up to 234k)        (N = hw.vmm.maxcpu / host cap)
```

- The **host thread stays 1:1 with the guest thread** — that does not change.
  Thread identity (the guest register file + FP/SIMD state, signal mask, TLS) is
  owned by the host thread, in carrick's memory, NOT pinned to a vCPU.
- A vCPU is just "a CPU to execute on." A host thread **acquires** a vCPU slot to
  run guest code and **releases** it when the guest thread blocks. The pool has N
  slots (vCPU ids `0..N`), recycled.
- At any instant ≤ N guest threads are *running* (holding a slot); any number are
  *alive* (blocked, holding nothing). This is precisely the kernel's own
  M-threads-on-N-CPUs scheduler, mirrored one level up.

### The acquire/release seam

Guest threads are blocked the vast majority of wall-clock time, and carrick
*already* services those blocks on the host thread with the vCPU idle. The seam is
the set of points where the host thread is about to sleep:

- futex `FUTEX_WAIT` (the big one — `PlatformFutex::private_wait`/`shared_wait`),
- blocking host I/O (poll/select/epoll_wait/read/recvmsg/accept/…),
- `nanosleep`/`clock_nanosleep`, `waitid`/`wait4`, `pause`,
- the idle/parked state between syscalls.

These are already distinguishable in the dispatcher (a syscall that returns a
"will block" outcome vs. one that returns immediately). Fast, non-blocking
syscalls do NOT release — the switch has a cost, and round-tripping a vCPU through
`getpid()` would be absurd.

### Lazy reclaim — preserve the ≤N fast path

Saving/restoring a register set per block would tax the common case. Instead:

- A running thread **holds** its slot. A thread that blocks marks its slot
  **reclaimable** but does NOT eagerly save/free it.
- A thread that needs a slot and finds none free **reclaims** a reclaimable
  (blocked) thread's slot: it `vm_get_register_set`s that thread's guest state out
  into the victim host-thread's saved-state buffer, then takes the id.
- The reclaimed thread, on wake, re-acquires *some* slot and
  `vm_set_register_set`s its state back before resuming `vm_run`.

Consequence: with ≤ N alive threads there is never contention → no save/restore →
the current 1:1 lifetime-bind behaviour and performance are exactly preserved.
The machinery only engages when a workload genuinely exceeds N — and then it costs
one register-set copy per reclaim, amortized against a block that was already
going to sleep for µs–ms.

## Per-backend lifecycle (the trait seam)

A small addition to the `HostBackend`/engine trait — three operations, each
already expressible in every backend's existing FFI:

| op | bhyve | HVF | KVM |
|---|---|---|---|
| acquire slot `i` | reuse vcpu id `i` (no re-`vm_activate_cpu` if kept warm) | `hv_vcpu_create` or a warm pool | the vCPU fd |
| save guest state | `vm_get_register_set` (GPR+seg+RIP/RSP/RFLAGS) + FP scratch | `hv_vcpu_get_reg`×… + FP | `KVM_GET_REGS`/`KVM_GET_FPU` |
| restore guest state | `vm_set_register_set` | `hv_vcpu_set_reg`×… | `KVM_SET_REGS`/`KVM_SET_FPU` |

The pool itself (a semaphore over N ids + the reclaim policy) is **shared
generic** in carrick-hal — only the get/set-register-set + slot-activate calls are
per-backend, exactly the leverage shape used for the signal pump and fork
coordinator. N is read from the backend (`hw.vmm.maxcpu` on bhyve, the HVF cap,
host `nproc` on KVM) — and carrick's coupled `X86_FP_SCRATCH_SLOTS=8` becomes
`N` (the FP scratch GPA region must be sized for N pages).

## Interactions to get right

- **Fork/clone**: clone no longer activates a vCPU (it spawns a host thread that
  will acquire lazily). `fork_quiesce` already stops the world around `libc::fork`;
  the pool is drained/rebuilt there. A fork child gets a fresh N-slot pool.
- **Signals / vCPU kick**: a kick must reach the host thread whether or not it
  currently holds a vCPU. The kick already targets the host thread (the registry
  is keyed by `ThreadId`), so a blocked (slot-less) thread is kicked via its futex
  wake / the signal pump, unchanged.
- **Per-thread vCPU state that ISN'T general registers**: anything a backend keeps
  in the vCPU beyond the saved set (e.g. local APIC, pending-event, XCR0/XSAVE
  area, debug regs) must be in the save/restore set or provably thread-invariant.
  This is the highest-risk area and needs a per-backend audit (x86 XSAVE/YMM is
  already serialized for fork snapshots — reuse that path).
- **Starvation/fairness**: reclaim should prefer the longest-blocked slot; a
  runnable thread waiting for a slot must not be starved by a hot thread that
  never blocks (a preemption tick — the existing async-preempt SIGURG kick — can
  force a hot thread to yield its slot if others are waiting).

## Incremental migration (each step shippable + verifiable)

1. **Admission gate (safety, no scale yet)** — implement bhyve's
   `wait_for_vcpu_slot` as a real counting gate over N ids with recycling, so the
   (N+1)-th thread BLOCKS for a slot instead of failing `vm_activate_cpu`. With ≤N
   alive it's a no-op; with >N alive-and-needed it's a clean wait (still a
   liveness stall for go-net_http, but NO corruption / no false `clone` success).
   Kills the deadlock-*corruption* class immediately. Verify: `threadspawn` peak
   plateaus cleanly at N, no EINVAL spam, no silent thread loss.
2. **Lazy reclaim** — add save/restore + the reclaim policy so a blocked thread's
   slot can be handed to a waiting one. Now >N alive threads run (≤N at once).
   Verify: `threadspawn` N=14 → peak 8 BUT all 14 *complete* on bhyve; go-net_http
   stops hanging.
3. **Generalize + audit** — lift the pool into carrick-hal generic, wire HVF/KVM
   onto it (lifting HVF's 64 wall too), per-backend non-GPR-state audit, fairness
   tick. Verify: full conformance unchanged on every backend; a 200-thread reducer
   passes on an 8-core bhyve.

## Why not just raise `hw.vmm.maxcpu`?

It's a read-only loader tunable (`/boot/loader.conf` + reboot) and bhyve can
overcommit vCPUs, so 8 → 64 is possible and would make go-net_http fit. But it is
a band-aid: it moves the wall, doesn't remove it; it wastes a kernel vCPU per
idle guest thread; and it does nothing for HVF/KVM or for a guest that wants 1,000
threads. Multiplexing is the model that matches what the guest's kernel actually
promises. (Raising the tunable is still worth doing as belt-and-suspenders once N
is read dynamically — a bigger pool is strictly better.)
