# NetBSD/x86_64 host-primitive grounding for the native lane

**Date:** 2026-07-25
**Task:** Task 0 (grounding scout) of the NetBSD native-lane plan
(`docs/superpowers/plans/2026-07-24-netbsd-native-lane.md`).
**Host:** willow VM 201 — `root@10.14.14.136`, NetBSD 10.1 amd64 (GENERIC),
gcc 10.5, rust 1.96, libclang at `/usr/pkg/lib`.
**Method:** throwaway C probes compiled with `cc` on the box + `/usr/include`
header citations. All probe binaries/sources were removed from `/tmp` after the
run. The committed snapshot at `/root/carrick` (branch `feat/netbsd-native-lane`
@ `e395c7e6`) was left in place (it is a disposable git-archive snapshot, not a
working tree).

Every primitive below carries a **mechanism decision** or a **BLOCKED-with-gap**,
plus the C-probe evidence and header citations that ground it.

---

## Summary of decisions

| Primitive | Decision | Key finding |
|---|---|---|
| JIT / W^X + fork-repair | **GO** — named `shm_open`+`shm_unlink` dual-map | No `SHM_ANON`; `remap_for_fork_child` = **Fresh** (shared dual-map is inherited-shared across fork, exactly like FreeBSD) |
| Fault shim (mcontext) | **GO** | `__gregs[_REG_*]` array (not named fields); indices captured |
| Futex (`SYS___futex`=166) | **GO** — Linux-shaped, **no waiter-table needed** | Cross-process YES, WAKE returns woken COUNT, REQUEUE/CMP_REQUEUE native |
| Threads (`_lwp_create`) | **GO** | Raw lwp shares address space; stack/TLS via `_lwp_makecontext` |
| Verbatim-reuse (`carrick-dsr-x86`+`identity_memory`+`carrick-mem`) | **GO with 1 shared-seam gap** | `libc::__error()` → NetBSD wants `libc::__errno()` (single cfg fix) |

---

## 1. JIT / W^X + fork-repair — **GO**

**`SHM_ANON`: ABSENT.** `grep SHM_ANON /usr/include/sys/mman.h` → no match. FreeBSD's
anonymous-SHM dual-map source is unavailable, as predicted.

**Relevant `mman.h` flags** (`/usr/include/sys/mman.h`):
`MAP_SHARED=0x0001`, `MAP_PRIVATE=0x0002`, `MAP_FIXED=0x0010`, `MAP_TRYFIXED=0x0400`,
`MAP_ANON=MAP_ANONYMOUS=0x1000`. `MAP_EXCL` is **absent** (confirms the waiter-key
seam's `exclusive_fixed_map_flag` → 0 for NetBSD; overlap protection stays in
`NativeMappingTransaction`, same as Darwin). `shm_open`/`shm_unlink` are declared
at `mman.h:239-240`.

**Chosen mechanism: named `shm_open` + immediate `shm_unlink` + dual `MAP_SHARED` map.**
The minimal delta from `carrick-native-freebsd::jit` — swap `shm_open(SHM_ANON,…)`
for `shm_open(unique_name, O_RDWR|O_CREAT|O_EXCL, 0600)` followed immediately by
`shm_unlink(name)` (the object survives via the open fd / live maps; the name is
gone so it is effectively anonymous). Then two `MAP_SHARED` maps of the one fd:
`PROT_READ|PROT_EXEC` (exec alias) and `PROT_READ|PROT_WRITE` (write alias). Writers
write through the RW alias; executors run the RX alias; **no `mprotect` flip ever
happens.**

**`mprotect` RW↔RX toggle: REJECTED** for the same reason FreeBSD rejected it. The
lwp probe (§4) proves NetBSD threads share one address space, so an `mprotect`
flip is process-wide and would yank X from a concurrently-executing sibling guest
thread. The dual-map avoids all flips.

**Fork-repair contract: `remap_for_fork_child` = `Fresh`** (same answer as
`FreebsdHostJit`). Probe evidence (`jit_probe.c`):

```
parent: exec via RX before fork returned 0x11 (expect 0x11)
parent: after child wrote INHERITED alias, RX returned 0x22
  INHERITED_SHARED_ACROSS_FORK=YES (0x22 => shared => Fresh REQUIRED)
parent: reset RX returned 0x11 (expect 0x11)
child(Fresh) exited status=0 (0 => child ran 0x22 on its own object)
parent: after child used FRESH object, RX returned 0x11
  FRESH_LEAVES_PARENT_UNAFFECTED=YES
```

- Write via RW alias, execute via RX alias → correct value `0x11` (W^X works with no flip).
- A fork child writing `0x22` through the **inherited** RW alias corrupts the
  parent's exec view (`RX` returns `0x22`): a `MAP_SHARED` dual map is genuinely
  shared with the fork child → the child MUST NOT keep executing/appending into it.
- A fork child that maps its **own fresh** object writes `0x22` there and the
  parent's exec view stays `0x11` → `Fresh(new_region_of_same_capacity)`
  satisfies the contract.

So the NetBSD JIT's `remap_for_fork_child` returns `Ok(ForkChildJit::Fresh(..))` —
a brand-new shm object of the same capacity — exactly mirroring FreeBSD. Fork
repair is entirely region replacement; there is no in-place protection repair.

---

## 2. Fault shim — mcontext layout — **GO**

**Layout differs structurally from FreeBSD.** NetBSD amd64 (`/usr/include/amd64/mcontext.h`,
via `/usr/include/sys/ucontext.h`) exposes registers as an **indexed array**, not
named struct fields:

```c
struct __ucontext { uint uc_flags; ucontext_t *uc_link; sigset_t uc_sigmask;
                    stack_t uc_stack; mcontext_t uc_mcontext; ... };
typedef struct { __gregset_t __gregs;   /* __greg_t[_NGREG], _NGREG=26 */
                 __greg_t _mc_tlsbase;
                 __fpregset_t __fpregs;  /* char[512], fxsave format */ } mcontext_t;
```

A signal handler reads `uc->uc_mcontext.__gregs[_REG_RIP]` etc — **not** FreeBSD's
`mc.mc_rip` / `mc.mc_r15` named fields. This is the load-bearing porting difference
for `fault.rs`.

**Register indices** (`_REG_*`, from `frame_regs.h`; captured by `mcontext_probe.c`,
since the values come from a macro expansion rather than literal `#define`s):

| reg | index | reg | index | reg | index |
|---|---|---|---|---|---|
| `_REG_RDI` | 0 | `_REG_RSI` | 1 | `_REG_RDX` | 2 |
| `_REG_RCX` | 3 | `_REG_R8` | 4 | `_REG_R15` | 11 |
| `_REG_RBP` | 12 | `_REG_RBX` | 13 | `_REG_RAX` | 14 |
| `_REG_TRAPNO` | 19 | `_REG_ERR` | 20 | `_REG_RIP` | 21 |
| `_REG_RFLAGS` | 23 | `_REG_RSP` | 24 | | |

`_NGREG=26`, `sizeof(mcontext_t)=728`. `_REG_URSP` aliases `_REG_RSP` (24),
`_REG_RFL` aliases `_REG_RFLAGS` (23). The gateway context pointer the FreeBSD shim
reads from `mc_r15` is `__gregs[_REG_R15]` (index 11) on NetBSD.

**Probe evidence** (`mcontext_probe.c` — SA_SIGINFO SIGSEGV handler, deliberate
write to `0xdead0000`):

```
  handler: sig=11 si_code=1 si_addr=0xdead0000
  handler: mc RIP=0x400da2 RSP=0x7f7fff09b780 TRAPNO=6 ERR=0x6
  MATCH_si_addr_is_fault_target=YES
```

`si_addr` matches the fault target; `__gregs[_REG_RIP]` reads the trap RIP; `ERR=0x6`
is the x86 page-fault error code (write + user + not-present — correct for a write to
an unmapped user page). The shim's dispatch key (`si_code` + `si_addr` + RIP-in-code-cache)
is fully readable. The FreeBSD `fault.rs` logic (RIP-in-region test, rewrite
`__gregs[_REG_RIP]` to the signal stub, read gateway ctx from `__gregs[_REG_R15]`)
ports directly; only field access changes from `mc.mc_*` to `__gregs[_REG_*]`.

---

## 3. Futex — `SYS___futex` (166) — **GO, and NO waiter-table workaround needed**

`SYS___futex = 166` (`/usr/include/sys/syscall.h:471`; matches the in-repo
`carrick-host/src/netbsd_futex.rs`). `/usr/include/sys/futex.h` states the API is
**"intended to be ABI-compatible with the Linux futex(2) system call"** and defines
`FUTEX_WAIT`(0), `FUTEX_WAKE`(1), `FUTEX_REQUEUE`(3), `FUTEX_CMP_REQUEUE`(4),
`FUTEX_WAKE_OP`(5), `FUTEX_WAIT_BITSET`(9), `FUTEX_WAKE_BITSET`(10),
`FUTEX_PRIVATE_FLAG`(bit7), `FUTEX_CLOCK_REALTIME`(bit8). The kernel entry is
`do_futex(int *uaddr, int op, int val, const struct timespec *timeout, int *uaddr2,
int val2, int val3, register_t *retval)` — the 7-argument Linux-shaped signature
(`futex.h:178`), and the userland stub is the 7-arg `syscall(166, uaddr, op, val,
timeout, uaddr2, val2, val3)` the in-repo `netbsd_futex.rs` already calls.

**This is the decisive divergence from FreeBSD.** FreeBSD's `_umtx_op(UMTX_OP_WAKE)`
returns 0 (not the woken count) and has no atomic requeue, which is the entire
reason `carrick-native-freebsd::futex` carries a fork-shared waiter-count table +
logical-requeue machinery. NetBSD's `__futex` provides both natively:

**Probe evidence** (`futex_probe.c` + `futex_probe2.c`, file-backed `MAP_SHARED`):

```
=== A/B: file-backed MAP_SHARED, 2 waiters(child) / waker(parent) ===
  FUTEX_WAKE(INT_MAX) returned 2 (expect 2 = woken count)
  FILE_BACKED_CROSS_PROCESS_WAKE=YES  WAKE_RETURNS_COUNT=YES
=== D: FUTEX_REQUEUE A->B (file-backed), 2 waiters(child) ===
  FUTEX_REQUEUE(wake=0, requeue=MAX) returned 0
  FUTEX_WAKE(B, INT_MAX) returned 2 (expect 2 if requeue moved them)
  children woken via B=2/2   REQUEUE_SUPPORTED=YES
```

- **Cross-process wake:** YES, across the fork boundary, both directions
  (child-waits/parent-wakes and parent-waits/child-wakes), 3/3 iterations each.
- **`FUTEX_WAKE` returns the woken count:** YES (2 for two waiters, 1 for one) —
  Linux semantics.
- **`FUTEX_REQUEUE` / `FUTEX_CMP_REQUEUE`:** native. Requeue A→B then a wake on B
  released both moved waiters.

**Decision:** the NetBSD futex module can be a thin `SYS___futex` wrapper with
**Linux-native semantics** — it does NOT need FreeBSD's waiter-count side table or
logical-requeue emulation. This meaningfully simplifies Task 3 (the mirror is
smaller than the FreeBSD peer). The `shared_futex_waiter_key` seam likely returns a
trivial/zero key on NetBSD (the kernel already keys shared futexes by backing
object), rather than the FreeBSD `kern.proc.vmmap` vnode-identity derivation — to be
finalized in Task 3.

**Honest caveat — anon `MAP_SHARED` also crosses fork on NetBSD 10.1.** The in-repo
`carrick-host/src/netbsd_futex.rs` doc comment asserts that `MAP_SHARED|MAP_ANON`
stores are coherent but "FUTEX_WAKE finds no waiter in the child." **This probe
contradicts that on NetBSD 10.1:** `MAP_SHARED|MAP_ANON` cross-process wake worked
deterministically, both directions, 3/3 iterations (`ANON_SHARED_CROSS_PROCESS_WAKE=YES`,
wake returned the count). The note may reflect an older NetBSD, a different mapping
setup, or the NVMM guest aperture specifically. **The design's conservative choice —
a file-backed `MAP_SHARED` shared aperture — is fully proven and remains the safe
default;** the anon result is reported for accuracy and as a possible future
relaxation, not a mandate to change the aperture backing. Note also that the FreeBSD
lane's own waiter table uses `MAP_SHARED|MAP_ANON` and relies on fork-shared
coherence there — NetBSD's anon-shared cross-process wake is consistent with that.

---

## 4. Threads — `_lwp_create` — **GO**

`/usr/include/lwp.h`:

```c
lwpid_t _lwp_self(void);
int     _lwp_create(const ucontext_t *, unsigned long /*flags*/, lwpid_t *);
int     _lwp_wait(lwpid_t, lwpid_t *);
void    _lwp_makecontext(ucontext_t *, void (*)(void *), void *arg,
                         void *private, void *stack_base, size_t stack_size);
int     _lwp_kill(lwpid_t, int);  int _lwp_detach(lwpid_t);
int     _lwp_park(...);  int _lwp_unpark(lwpid_t, const void *);  /* + unpark_all */
```

Flags (`/usr/include/sys/lwp.h`): `LWP_DETACHED=0x40`, `LWP_SUSPENDED=0x80`. The
stack + entry + TLS-private pointer are handed in via a `ucontext_t` built by
`_lwp_makecontext(ucp, func, arg, private, stack_base, stack_size)`. **All `_lwp_*`
stubs live in libc — link with plain `cc`, NOT `-llwp` (that library does not
exist).**

**Probe evidence** (`lwp_probe.c` — spawn an lwp, have it write a shared global,
`_lwp_wait` it):

```
_lwp_create ok: new lwpid=12021
g_shared=0x1042 (expect 0x1042 => address space shared)
lwp ran self=12021   LWP_GO=YES
```

The lwp shares the address space (wrote `0x1042` to a parent global), reports its
own tid via `_lwp_self`, and is reaped by `_lwp_wait`. This is the NetBSD analog of
guest `clone(CLONE_VM|CLONE_THREAD)`.

**Design note for Task 4 (threads):** NetBSD exposes raw `_lwp_create` — a
lower-level primitive than FreeBSD's pthread-based `spawn_clone_thread`. The caller
supplies the stack + entry directly (via `_lwp_makecontext`), mapping more directly
onto guest `clone` than a pthread wrapper. Whether the lane uses `_lwp_create`
directly or a pthread for host-runtime consistency is a Task-4 decision, not a
blocker — both are available.

---

## 5. Verbatim-reuse thesis — **GO with exactly ONE shared-seam gap**

On the box: `cargo build -p carrick-dsr-x86 -p carrick-dsr -p carrick-mem`
(`LIBCLANG_PATH=/usr/pkg/lib`; `identity_memory` lives in `carrick-dsr`).

- **`carrick-dsr-x86` (the x86 ISA engine): compiles CLEAN.**
- **`carrick-mem`: compiles CLEAN.**
- **`carrick-dsr` (contains `identity_memory`): ONE gap.**

```
error[E0425]: cannot find function `__error` in crate `libc`
   --> crates/carrick-dsr/src/identity_memory.rs:528:25
    | unsafe { *libc::__error() = libc::EIO };
    | similarly named function `__errno` defined here (libc netbsdlike)
```

`identity_memory.rs` uses `libc::__error()` (the Darwin/FreeBSD errno accessor) at
three sites — lines **456, 528, 556** — to set errno on injected host-failure
paths. NetBSD's libc exposes the thread errno location as `libc::__errno()`
instead. These calls compile unconditionally (they are the bodies of otherwise
dead-in-release fault-injection branches), so the whole crate fails to build on
NetBSD.

**This is a SHARED-SEAM item, not NetBSD-local work.** `identity_memory` is a
verbatim-reuse crate; the fix belongs in the shared layer (e.g. a small
`#[cfg(target_os="netbsd")] libc::__errno()` / else `libc::__error()` errno-location
helper, or routing through `carrick-portable`). Per the plan's rules it must be
fixed in the shared layer during Task 1/2, not patched NetBSD-locally.

**Scope is minimal — the thesis holds.** A throwaway on-box `sed
's/libc::__error()/libc::__errno()/'` of the disposable snapshot made **all three
crates compile clean in 1.99s** with no further gaps surfacing. So the same-ISA
"host-glue only" claim survives: `carrick-dsr-x86` + `identity_memory` + the shared
crates need exactly one cfg-guarded errno-accessor to build on NetBSD/amd64. (The
snapshot was restored to its committed state afterward.)

---

## Consolidated go/BLOCKED

- JIT/W^X: **GO** — named-shm dual-map; `remap_for_fork_child` = **Fresh**.
- Fault shim: **GO** — `__gregs[_REG_*]` indices captured; handler reads verified.
- Futex: **GO** — `SYS___futex` is Linux-shaped; cross-process + count + requeue all
  native; **no waiter-table workaround needed** (simpler than the FreeBSD lane).
- Threads: **GO** — `_lwp_create` (libc, no `-llwp`); shares address space.
- Verbatim reuse: **GO** — one shared-seam errno-accessor cfg gap
  (`__error`→`__errno`), fixed in the shared layer.

No BLOCKED-with-gap. Nothing requires maintainer escalation before Task 1. The one
shared-layer change Task 1/2 must make is the errno-accessor cfg; the one shared
change Task 3 must make (already anticipated by the plan) is futex lane dispatch —
and NetBSD's native count+requeue means that dispatch targets a *thin* NetBSD futex,
not another waiter-table.
