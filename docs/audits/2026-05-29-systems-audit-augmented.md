# Carrick Systems Audit — Augmented & Dynamically Validated

Date: 2026-05-29
Supersedes (does not replace): `2026-05-29-deep-static-systems-audit.md` (static-only).

## What this is

The original audit was an explicit **static-only** pass: every finding was
"confirmed by static inspection" and flagged "needs a dynamic repro before
implementation." This document closes that gap. It:

1. **Vets** all 18 original findings against the *current* source (the audit's
   line numbers had drifted — commits landed after it was written), recalibrates
   their severity honestly, and cross-references the live LTP campaign.
2. **Augments** with new findings from a 12-lane subsystem sweep, each
   adversarially verified by an independent skeptic that tried to refute it.
3. **Validates dynamically** — the high-severity findings are reproduced with
   deterministic conformance probes / raw-ELF fixtures run under `carrick`
   vs a Docker `linux/arm64` oracle, line-diffed. The probes are now in-tree and
   become permanent regression gates.

Method note (why this matters for public release): a static audit over-rates
severity and produces false positives. Running the findings is what separates a
release-blocker from a non-issue — and an audit a reader can trivially disprove
by running it would damage the project's credibility more than the bugs do.

## Headline

- **The original audit had no true P0s.** All five of its "P0"s were
  recalibrated down by code re-reading: F_SETFL→P2, openat2→P2 (partially fixed
  since), mremap→P2, internal-fd-relocation→P3, and the **child-CPU-accounting
  race is REFUTED** (the `wait4`/process-exit cross-process barrier dominates the
  Acquire/Release pair — the window is unreachable).

- **The real release-blocker is a class the original audit missed entirely:
  guest-reachable host crashes / containment failures.** A normal (let alone
  malicious) Linux guest can, in a handful of ordinary syscalls, abort the
  carrick host process or violate `MAP_PRIVATE` isolation. For a runtime whose
  entire pitch is "run untrusted Linux binaries," this — not the syscall-fidelity
  backlog — is what determines public reception. **8 such findings are confirmed
  with hard evidence below.**

- **Dynamic validation also demoted an overstated discovery finding:** the
  `msgsnd`/`msgrcv` `8 + msgsz` unchecked-add is real, but the host kernel's own
  `MSGMAX` check rejects the oversized length with `EINVAL` *before reading*, so
  it is **not an exploitable OOB in the release build** (it is a debug-build DoS +
  defense-in-depth gap). Publishing it as a "P0 OOB read" would have been
  trivially disprovable.

## How to reproduce (everything is in-tree)

```sh
./scripts/build-signed.sh                       # signed+entitled carrick
./scripts/build-probes.sh                        # static aarch64-musl probes
./scripts/build-linux-fixtures.sh                # raw-asm fixtures (sp_fault)
export CARRICK_INSECURE_REGISTRIES=localhost:5050
scripts/run-probe.sh <name> ubuntu:24.04         # carrick vs Docker, line-diff
```

The probes added by this audit: `fsetfl`, `readpasteof`, `bigread`,
`rosharedbus`, `mapfixed`, `forkaltstack`, `pselecteintr`, `forkfpregs`,
`msgoverflow`; the fixture `carrick-linux-aarch64-sp-fault`. `maskfork` is an
existing probe used here to reconcile a conflict.

Caveats that bit during validation, recorded so the next person doesn't relearn
them: `run-probe.sh` is the **faithful threaded path**; `run-elf` is a lighter
single-threaded path that can *pass* a signal/threading probe the gate fails.
The `readpasteof` panic only triggers under `--fs memory` (in-memory
`File`/`SyntheticFile`); `--fs host` makes it a `HostFile` (safe). The
`run-probe.sh` global `kill.sh` force-kills *all* carrick guests, so probe runs
must be serialized (not a true HVF-instance limit — separate processes run their
own VMs fine; it's the global pkill and per-process RSS, not the hypervisor).

---

## Part A — Vet of the original 18 findings

Every line number in the original had drifted. Recalibrated severities (honest,
accounting for mitigations and guest-reachability):

| Original finding | Original | **Recalibrated** | Verdict | Current location |
|---|---|---|---|---|
| F_SETFL stores raw status flags | P0 | **P2** | confirmed (validated) | `dispatch/fs.rs:1867/1899` |
| openat2 accepts RESOLVE_* unenforced | P0 | **P2** | partially_addressed | `dispatch/fs.rs:2614/2659` |
| mremap FIXED/DONTUNMAP ignored | P0 | **P2** | confirmed | `dispatch/mem.rs:648/653` |
| Internal fd relocation low-fd fallback | P0 | **P3** | drift_only | `carrick-hvf/src/host_signal.rs:566` |
| Child CPU accounting publishes pid first | P0 | **not-a-bug** | **REFUTED** | `carrick-host/src/guest_cpu.rs:148` |
| SIGWINCH relay not rollback-safe | P1 | **P3** | confirmed | `dispatch/pty_relay.rs:221` |
| Wait-fd pinning raw-fd fallback | P1 | **P3** | confirmed | `carrick-hvf/src/io_wait.rs:56` |
| waitid leaks raw Darwin errno | P1 | **P2** | confirmed | `dispatch/proc.rs:1211` |
| io_uring_enter ignores args/bound | P1 | **P2** | confirmed | `dispatch/mem.rs:804`, `ioring.rs:334` |
| Late HVF stage-2 mapping | P1 | **P2** | partially_addressed | `dispatch/mem.rs:277-343` |
| mprotect guest-visible only in arena | P1 | **P2** | confirmed | `dispatch/mem.rs:731-755` |
| POSIX timer/timerfd kqueue leverage | P2 | **P3** | drift_only | `carrick-hvf/src/posix_timer.rs` |
| APFS clone fast-path ordering | P2 | **P3** | drift_only | `darwin_fs.rs:19-31` |
| TTY/session boundary spread | P2 | **P3** | partially_addressed | `dispatch/proc.rs:1129-1164` |
| Guest ABI/fd/errno centralization | P2 | **P2** | partially_addressed | `dispatch/ioring.rs:226-239` (concrete: see below) |
| shmat ignores addr/flags | (disp.) | **P3** | confirmed-intentional | `dispatch/sysv.rs:397` |
| Fork-quiesce panic exceptions | (disp.) | **P3** | partially_addressed | `carrick-hvf/src/fork_quiesce.rs:6` |
| Packed ABI structs | (disp.) | **not-a-bug** | drift_only | `carrick-abi/src/lib.rs:87` |

Notable corrections:

- **Child-CPU race — REFUTED.** `record_child_exit` does publish `pid` (CAS,
  AcqRel) before storing `guest_ns` (Release), but `reap_child_guest_ns` only
  runs *after* `wait4` reaps the child, and process-exit + `wait4` is a strong
  cross-process barrier that dominates the pair. The window is not reachable.
  Optional clarity-only hardening (store `guest_ns` first) is fine but not a bug.

- **openat2 — re-scope and resolve a ROADMAP conflict.** `openat2` validation
  *landed since the audit* (probe `openat2valid`; `openat201/203`). The residual
  is `RESOLVE_*` bits accepted but unenforced → **P2 fidelity** (silent success
  under a weaker policy than requested), not P0/security. **Do NOT adopt the
  audit's "map `RESOLVE_NO_SYMLINKS`→ELOOP / `NO_XDEV`→EXDEV" fix** — ROADMAP #5's
  adversarial verdict shows it breaks `openat202`'s `resolve=0` success cases and
  `EXDEV` needs per-mount `st_dev` carrick lacks. Correct path: enforce
  `RESOLVE_BENEATH`/`NO_SYMLINKS` *in the resolver*, or return a compat-gap error
  for the unenforceable bits only.

- **`abi-fd-errno-central` has a concrete bug, not just a smell:** `io_uring`'s
  local `read_iovecs` (`ioring.rs:226-239`) caps only `count>1024` and lacks the
  `IOV_MAX` + per-iovec/cumulative `SSIZE_MAX` checks the central
  `dispatch/mod.rs::read_iovecs` enforces. Delete the clone, route through the
  central helper.

The other downgrades (SIGWINCH, wait-fd pinning, timers, APFS, TTY) are real but
are non-guest-reachable hygiene / scoped-limitation / performance items — keep as
backlog, not release-blockers.

---

## Part B — New findings: the host-robustness / guest-containment cluster

These are what the static audit missed. All P0/P1 entries are **dynamically
validated** (carrick vs Docker oracle). They collapse into **four shared root
causes**, which is also the fix leverage.

### Root cause 1 — `write_guest_bytes` ignores mapping permissions

`trap.rs:1941` gates guest-buffer writes on the PROT_NONE set only; it never
consults a mapping's read-only state, and `MAP_FIXED` placement is trusted at any
address (`mem.rs:81`).

**[P1] Write through a read-only `MAP_SHARED` file alias → host SIGBUS** — probe `rosharedbus`
```
- linux:   child_exited_clean=true   child_read_efault=true   child_killed_by_signal=false
+ carrick: child_exited_clean=false  child_read_efault=false  child_killed_by_signal=true
```
`open(O_RDONLY)` → `mmap(PROT_READ, MAP_SHARED)` → `read(pipe, mapped_ptr, n)`:
carrick's host `write_volatile` into the genuinely read-only host page faults
SIGBUS, and `host_signal` treats the synchronous fault as a fatal carrick bug →
the process dies. Linux returns EFAULT to the task. Three unprivileged syscalls.

**[P1] `MAP_FIXED|MAP_PRIVATE` write leaks to the parent's shared page** — probe `mapfixed`
```
- linux:   parent_value_preserved=true   parent_clobbered_by_child=false
+ carrick: parent_value_preserved=false  parent_clobbered_by_child=true
```
A child that `MAP_FIXED`-replaces a shared page with a private mapping and writes
to it corrupts the *parent's* page — `MAP_PRIVATE` is not private. Same root
cause; the write path goes through to the shared backing. (The static audit also
noted `MAP_FIXED` can target carrick's own EL1 page tables / vector table — not
re-run here because it corrupts the running VM, but it shares this exact gap.)

> **Fix (one change, both findings):** `write_guest_bytes` (and `read_guest_bytes`
> for symmetry) must consult a per-mapping software permission / read-only set and
> synthesize `MemoryError → EFAULT` for a write into a non-writable or
> non-user-owned mapping — exactly as it already does for PROT_NONE. Reject
> `MAP_FIXED` targets outside the user mapping range.

### Root cause 2 — guest length → eager host allocation, no `MAX_RW_COUNT` clamp

Read-side handlers do `vec![0u8; guest_count]` before bounding the count. Only
`sendfile` caps (it even documents why — `fs/sendfile.rs:156`).

**[P1] Unbounded `vec![0u8; guest_count]` aborts the runtime** — probe `bigread`
```
- linux:   child_exited_clean=true   child_killed_by_signal=false   (short read = 4 bytes)
+ carrick: child_exited_clean=false  child_killed_by_signal=true     (alloc abort)
```
`read(pipe, buf16, 1<<46)` makes carrick attempt a 64 TiB host allocation →
`handle_alloc_error → abort()`. No host masking — carrick allocates before any
host call. Sites: `mod.rs:3665` (`read`/stdin), `net.rs:2323` (`recvfrom`),
`proc.rs:1488` (`getrandom`), `fs.rs:3148/3242` (`pread`/`preadv`),
`ioring.rs:421/468`. **[P2]** `ppoll`/`poll` have the sibling defect:
`Vec::with_capacity(nfds)` from an unbounded guest `nfds` (`net.rs:1703`).

> **Fix:** a shared `MAX_RW_COUNT` (0x7ffff000) page-clamp + chunked staging,
> mirroring `sendfile`. Linux's own short-read semantics make this conformance-safe.

### Root cause 3 — guest input → Rust index panic (no `.get()`, no `panic=abort`)

**[P1] `GPR_TABLE[31]` out-of-bounds on an SP-relative faulting load** — fixture `sp_fault`
```
carrick run-elf -> GUEST ABORT:
  index out of bounds: the len is 31 but the index is 31
  at crates/carrick-hvf/src/trap.rs:1752
docker -> exit 139 (SIGSEGV)
```
The EL0-fault *diagnostic* indexes `GPR_TABLE[rn]` with `rn` possibly 31 (SP/XZR
encoding) into a `[Reg; 31]`. Any `ldr x0,[sp]` to a bad page — extremely common
(stack overflow, guard-page touch) — aborts carrick instead of delivering the
guest's SIGSEGV. One-char fix: `.get(rn)`; the safe pattern is already used 142
lines away at `trap.rs:1894`.

**[P1] `read()` after `lseek` past EOF panics** — probe `readpasteof`
```
carrick run-elf --fs memory -> GUEST ABORT exit 101:
  range start index 1048576 out of range for slice of length 0
  at crates/carrick-runtime/src/dispatch/fs.rs:3043
docker -> read_past_eof_rc=0
```
The in-memory `File`/`SyntheticFile` read slices `&contents[*offset..]` unguarded;
`lseek` stores any offset past EOF. `pread64` right beside it is guarded. Triggers
on `--fs memory` (and synthetic `/proc` files); `--fs host` is safe. Fix: mirror
`pread64`'s `if offset < contents.len()` guard.

> Note: carrick's panic hook turns these into a "GUEST ABORT" (guest-process exit),
> not always a host-wide crash. But `panic = "abort"` is **not** set, so a panic
> unwinds across the HVF/FFI vCPU boundary — undefined in practice. See Part E.

### Root cause 4 — fork vCPU rebuild drops per-thread/CPU state

**[P1] SIMD/FP register file (V0–V31) zeroed across fork/clone** — probe `forkfpregs`
```
- linux:   parent_v0_ok=true   parent_v20_ok=true   child_v0_preserved=true   child_v20_preserved=true
+ carrick: parent_v0_ok=false  parent_v20_ok=false  child_v0_preserved=false  child_v20_preserved=false
```
`VcpuSnapshot` carries no V/FPSR/FPCR fields; FP save/restore is wired only to the
signal path. Across a raw `clone`, **both parent and child** resume with zeroed
vector state. Masked for ordinary libc `fork()` (AAPCS only callee-saves V8–V15),
so it's latent for C programs but real for any runtime keeping live caller-saved
V-state across a raw clone svc (Go, inline-svc clone, NEON memcpy in flight).
> **Fix:** add `[u128;32]+fpsr+fpcr` to `VcpuSnapshot`; capture via
> `get_simd_fp_reg`/`Reg::FPSR`/`FPCR` and restore via the **`set_simd_fp_reg_v` C
> shim** — NOT applevisor's `set_simd_fp_reg`, which is the known V-reg-zeroing ABI
> bug (see `project_simd_fp_abi_bug`).

**[P1] `sigaltstack` not inherited across fork** — probe `forkaltstack`
```
- linux:   child_inherits_altstack=true
+ carrick: child_inherits_altstack=false
```
Per-tid altstack (`signal.rs:44`) + the child gets a new tid (`runtime.rs:1611`).
The signal-**mask** half of this finding was **REFUTED** — `maskfork` MATCHES
(`child_inherits_blocked_mask=true`), so the child *does* inherit the mask; the
skeptic's `this_tid`-rekey reading doesn't bite. Only the altstack is lost.

### Other root-cause-independent findings

**[P1] Signal delivery to an unmapped/PROT_NONE stack → fatal TrapError / sibling deadlock**
(`trap.rs:2307`, `runtime.rs:1330/1808`): an inject-failure becomes a generic
`TrapError` instead of Linux's "force SIGSEGV, terminate thread-group"; on a
sibling thread the catch path skips the `clear_child_tid` futex wake, so peers
blocked in `pthread_join` deadlock while the process looks healthy. *(Code-confirmed;
a deterministic probe needs an SP-corruption + multi-thread harness — deferred.)*

**[P1] `select()`/`pselect6` blocks uninterruptibly (no EINTR)** — probe `pselecteintr`
```
- linux:   select_returned=true  select_rc_negative=true  select_eintr=true
+ carrick: (no output — never returned)
```
The all-host fast path calls a blocking `libc::poll` directly (`net.rs:1494`) with
no signal-wake fd; asymmetric with `ppoll`, which hands off to the
signal-interruptible `WaitOnFds` waiter. A guest SIGALRM never wakes it → indefinite
hang for select-based event loops. (aarch64 routes both glibc `select()` and
`pselect()` here.) Fix: mirror `ppoll`'s `WaitOnFds` handoff.

**[P2 downgraded — masked by host] `msgsnd`/`msgrcv` `8 + msgsz` unchecked add** — probe `msgoverflow`
```
both: huge_msgsnd_failed=true  huge_msgsnd_einval=true  small_msgsnd_ok=true   (MATCH)
```
The unchecked add (`sysv.rs:568/593`, no `[profile.release] overflow-checks`) is
real, but any `msgsz` large enough to overflow `8+sz` is far larger than `MSGMAX`,
so the host kernel returns `EINVAL` before reading — **no OOB in release**.
Remains: a debug-build DoS (overflow-checks panic) + a defense-in-depth gap.
Harden with a `MSGMAX` clamp + `checked_add`; not a live P0.

### Other verified new findings (P2/P3), by area

| Area | Sev | Finding | Location |
|---|---|---|---|
| signals | P2 | `rt_sigsuspend` busy-poll misses thread-directed (tkill/tgkill) wakeups (only polls process-global) — up to 5s hang | `dispatch/signal.rs:564-581` |
| signals | P3 | SI_USER siginfo has `si_pid=si_uid=0` — `LinuxSiginfo` ABI struct lacks the fields entirely | `carrick-abi/src/lib.rs:844-868`, `trap.rs:2264` |
| proc | P2 | `waitid` doesn't account reaped-child CPU into RUSAGE_CHILDREN/`tms_cutime` (asymmetric with `wait4`) | `dispatch/proc.rs:1166-1268` |
| proc | P3 | `clone`/`clone3` `exit_signal` ignored — child exit always SIGCHLD | `dispatch/proc.rs:338-427`, `runtime.rs:587` |
| proc | P3 | `cred_ipc` euid in world-readable `/tmp/carrick-cred-<pid>`, no isolation/staleness guard | `cred_ipc.rs:18-62` |
| net | P2 | epoll overflow queue keyed by `epoll_data` but cleared by fd — stale events when `data != fd` | `dispatch/net.rs:1264-1278` |
| net | P2 | `SO_RCVTIMEO`/`SO_SNDTIMEO` accepted but never honored (blocking recv/send → block-forever) | `dispatch/net.rs:188-215`, `net/support.rs:721` |
| net | P2 | `recvmsg`/`recvfrom` never report `MSG_TRUNC`; always zero `msg_controllen` | `dispatch/net.rs:2765-2769` |
| abi | P2 | `LinuxSysinfo` mid-struct padding shifts `totalhigh..mem_unit` by 2 bytes vs Linux aarch64 ABI | `carrick-abi/src/lib.rs:800-814` |
| mem | P2 | `mprotect` ignores PROT_EXEC: removing it never sets UXN (no NX); PROT_EXEC-only → PROT_NONE (spurious faults) | `dispatch/mem.rs:731`, `trap.rs:1532`, `page_table.rs:583` |
| mem | P2 | `MAP_FIXED` into the arena bypasses bump cursor/free-list → later mmap can alias a live mapping | `dispatch/mem.rs:81-127` |
| ioctl/tty | P2 | termios `c_cflag` CSIZE/CSTOPB/parity copied 1:1 but Linux≠Darwin bit positions | `host_tty.rs:54-57/198` |
| ioctl/tty | P2 | termios `c_iflag` IXON/IXOFF mistranslated (Linux 0x400/0x1000 vs Darwin 0x200/0x400) | `host_tty.rs:36-42/188` |
| ioctl/tty | P3 | TIOCSWINSZ on stdio → ENOTTY (no resize/SIGWINCH); FIONREAD on tty → 0/ENOTTY; set-side ioctls swallow errno | `dispatch/fs.rs:2081-2303` |
| time | P2 | `timer_settime` ignores TIMER_ABSTIME + skips timespec validation (no EINVAL on tv_nsec≥1e9) | `dispatch/time.rs:374-411` |
| time | P3 | `clock_getres` reports 1ms for all clocks (Linux hi-res = 1ns); CPU-clock nanosleep treated as wall-clock; overrun counter wrong; `adjtimex(modes=0)` → EPERM | `dispatch/time.rs` |
| fs | P3 | `linkat` validates the wrong AT flag (accepts NOFOLLOW 0x100, rejects FOLLOW 0x400 which the ABI lacks) | `dispatch/fs.rs:4834` |
| fs | P3 | raw `mkfifoat`/`fchmodat` in host backend bypass cap-std symlink-escape protection | `fs_backend.rs:1148-1175` |

(Full per-finding evidence + adversarial verdicts in the workflow transcript;
`/tmp/validation_evidence.md` holds the validated diffs verbatim.)

---

## Part C — Security posture for public release (threat model)

Carrick's value proposition is *running untrusted Linux binaries on macOS*. The
honest posture today:

- **Guest containment of the filesystem is reasonable** (cap-std-backed host
  backend; the path-escape lane found only narrow gaps — `mkfifoat`/`fchmodat`
  bypass cap-std, P3).
- **Host-process robustness against a hostile/buggy guest is the weak point.**
  The Root-cause-1/2/3 cluster means a guest can **deterministically abort the
  carrick host process** (`read(huge)`, `ldr [sp]` to a bad page, RO-MAP_SHARED
  write, `lseek`-past-EOF read on `--fs memory`) and **violate `MAP_PRIVATE`
  isolation** (`mapfixed`). None require privilege; most are ≤3 syscalls.
- **Not found:** an arbitrary-host-code-execution or host-FS-escape primitive.
  The `MAP_FIXED`-into-EL1-page-tables case (static) is the closest to memory
  corruption and should be treated as the highest-priority item in the cluster.

For a public launch, the defensible framing is: **"carrick isolates the guest
filesystem and runs the Linux ABI faithfully; it is not yet a hardened sandbox
against a deliberately hostile guest — these N host-robustness items are tracked
and gated."** Shipping that statement *with the cluster fixed* is far stronger
than shipping silence. The fixes are small (see Part D); landing them flips the
posture from "a hostile guest can crash the host" to "a hostile guest gets an
errno," which is the line reviewers will look for.

---

## Part D — Release-blocker priority & fix plan

Ordered by (impact × low-effort). All probe-gated; the probes already exist.

1. **`MAX_RW_COUNT` read/recv clamp** (Root cause 2) — gates `bigread` + the
   `read`/`recvfrom`/`getrandom`/`pread`/`preadv`/`io_uring`/`ppoll` DoS. Shared
   helper, mirror `sendfile`. *Small, high impact.*
2. **`GPR_TABLE.get(rn)`** (Root cause 3, `sp_fault`) — one line.
3. **`read`-past-EOF guard** (Root cause 3, `readpasteof`) — mirror `pread64`.
4. **`write_guest_bytes` read-only/permission check** (Root cause 1,
   `rosharedbus` + `mapfixed`) — synthesize EFAULT for non-writable targets;
   reject out-of-user-range `MAP_FIXED`. *Highest containment value.*
5. **`F_SETFL` mutable-status mask** (`fsetfl`) — preserve access mode, mask to
   `O_APPEND|O_NONBLOCK|O_DIRECT|O_NOATIME|O_ASYNC`.
6. **`pselect6` → `WaitOnFds` handoff** (`pselecteintr`) — mirror `ppoll`.
7. **SIMD/FP in `VcpuSnapshot`** (`forkfpregs`) — via `set_simd_fp_reg_v` shim.
8. **`sigaltstack`/signal-state fork inheritance** (`forkaltstack`); **signal
   inject-failure → forced SIGSEGV + sibling futex-wake** (the deadlock finding).
9. Backlog (P2/P3 table): `msgsnd` MSGMAX clamp + `checked_add`; `io_uring`
   iovec central-helper; termios bit translation; `SO_*TIMEO`; epoll overflow
   keying; `LinuxSysinfo` padding; `timer_settime` ABSTIME; `mprotect` PROT_EXEC.

### Status — fixes landed & verified this session (probe-gated)

Scope landed (each rebuilt via `build-signed.sh`, verified carrick-vs-Docker, no
regression across an 8-probe read/recv/fork subset):

- **`MAX_RW_COUNT` read clamp** — new `pub(crate) const MAX_RW_COUNT = 0x7fff_f000`
  (`dispatch/mod.rs`), applied at `read_host_pipe`, `recvfrom` (`net.rs`),
  `getrandom` (`proc.rs`), `pread64` (`fs.rs`). `bigread` → **MATCH**
  (`runtime_survived_huge_read=true`).
- **`GPR_TABLE.get(rn)`** (`trap.rs:1751`) — `sp_fault` → carrick now delivers the
  guest fault instead of the host index-OOB abort (no more `trap.rs:1752` panic).
- **read-past-EOF guard** — `contents.get(*offset..).unwrap_or(&[])`
  (`fs.rs:3043`). `readpasteof` → carrick returns `read_past_eof_rc=0` like Linux.
- **`msgsnd`/`msgrcv` checked-add + `MAX_RW_COUNT` bound** (`sysv.rs`) —
  `msgoverflow` MATCH (was already host-masked; now also debug-build-safe & the
  `msgrcv` eager-alloc is bounded). `sysvmsg` MATCH (no regression).

Follow-up surfaced by validation: post-clamp, `read(huge_count)` returns a short
read where Linux returns **EFAULT** (its `access_ok` rejects `buf+count`
overflowing the user VA range). Minor fidelity gap; the security goal (no host
DoS) is met. Tracked.

Deferred to their own review (bigger / HVF-trap surface — confirmed but NOT
fixed this session): `write_guest_bytes` permission check (`rosharedbus` +
`mapfixed`), `F_SETFL` mutable-status mask (`fsetfl`), `pselect6`→`WaitOnFds`
(`pselecteintr`), SIMD/FP `VcpuSnapshot` (`forkfpregs`), `sigaltstack`/signal
fork inheritance (`forkaltstack`), and the signal-inject-failure → forced SIGSEGV
deadlock. These remain confirmed P1/P2 release-blockers in the backlog above.

---

## Part E — Static enforcement & build-config hardening

Config gaps that make the above worse and are trivial to close:

- **No `[profile.release] overflow-checks`** — the `msgsnd` `8+sz` wrap is silent
  in release. Enabling overflow-checks converts silent wraps into panics
  (DoS > corruption) and is cheap insurance for an ABI emulator doing arithmetic
  on guest-controlled integers everywhere. (Pair with explicit `checked_*` at the
  hot sites so the result is `EINVAL`, not a panic.)
- **No `[profile.release] panic = "abort"`** — guest-triggered panics currently
  *unwind* across the HVF/FFI vCPU boundary (UB in practice). Either set
  `panic = "abort"` (clean, deterministic guest kill) or — better — eliminate the
  guest-reachable panics (items 2/3) so the question is moot.
- The workspace `panic = "deny"` is a **clippy lint on the `panic!` macro only** —
  it does NOT stop runtime index-OOB / slice / alloc panics. Three findings here
  were such panics. The lints to evaluate: `clippy::indexing_slicing`,
  `clippy::undocumented_unsafe_blocks`, `unsafe_op_in_unsafe_fn`.

Semgrep rules (the original audit's candidates, refined by what validation found):
- `carrick.guest-len-must-clamp`: `vec![0u8; $N]` / `Vec::with_capacity($N)` where
  `$N` derives from a syscall arg without a `MAX_RW_COUNT`-class clamp.
- `carrick.gpr-table-index`: forbid `GPR_TABLE[$I]` indexing; require `.get(`.
- `carrick.write-guest-bytes-perms`: writes resolved through a mapping must check
  a permission/RO set, not only PROT_NONE.
- `carrick.f-setfl-must-mask-status`: `set_status_flags($ARG)` unless `$ARG` flows
  through the mutable-status mask helper.
- `carrick.host-errno-must-translate`: forbid `DispatchOutcome::errno($E)` where
  `$E` came from `raw_os_error()`/`*libc::__error()` outside the translation helper.
- `carrick.fd-ffi-allowlist`: restrict direct `libc::{close,dup,pipe,socketpair}` /
  `fcntl(F_DUPFD*)` to the host fd wrappers.

---

## Reconciliation with the LTP conformance campaign

This audit is a **different lens** from the LTP campaign (`docs/ltp-baseline/`):
LTP measures per-test syscall *fidelity* (568/896 = 63% verified-MATCH); this
audit finds *bug classes* (host crashes, isolation, races, ABI layout) that are
mostly invisible to LTP's pass/fail counting. Overlaps and conflicts:

- The host-robustness cluster is **not** in LTP's DIFF queue — LTP tests don't try
  to crash the runtime, so these need the dedicated probes added here.
- The audit's openat2 `RESOLVE_*` fix **conflicts** with ROADMAP #5's adversarial
  verdict (see Part A) — do not apply the naive version.
- Several P2/P3 items overlap ROADMAP clusters (errno/termios/`SO_*`/`mprotect`)
  and should be folded into that work queue, probe-gated, not duplicated.

The new probes are wired into the same `tests/conformance.rs` gate, so each fix
lands with a permanent regression guard — the campaign's "a MATCH without a probe
is not done" rule.

---

## Appendix — validated-evidence index

| Finding | Probe / fixture | Result | Severity |
|---|---|---|---|
| RO MAP_SHARED → SIGBUS | `rosharedbus` | DIFF (carrick killed) | P1 |
| MAP_PRIVATE isolation | `mapfixed` | DIFF (parent clobbered) | P1 |
| Unbounded read alloc | `bigread` | DIFF (carrick killed) → **MATCH after clamp** | P1 (fixed) |
| GPR_TABLE[31] OOB | `sp_fault` (fixture) | GUEST ABORT `trap.rs:1752` → **guest fault after `.get()`** | P1 (fixed) |
| read past EOF | `readpasteof` | GUEST ABORT `fs.rs:3043` → **rc=0 after guard** | P1 (fixed) |
| SIMD/FP across fork | `forkfpregs` | DIFF (all-false) | P1 |
| sigaltstack across fork | `forkaltstack` | DIFF | P1 |
| select no EINTR | `pselecteintr` | DIFF (carrick hang) | P1 |
| F_SETFL clobber | `fsetfl` | DIFF | P2 |
| msgsnd overflow | `msgoverflow` | **MATCH** (host-masked) | P2/P3 |
| fork signal mask | `maskfork` | **MATCH** (refutes mask half) | n/a |
