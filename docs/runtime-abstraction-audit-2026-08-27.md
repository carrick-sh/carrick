# Runtime abstraction audit — 2026-08-27

What carrick's file-descriptor layer costs today, what the rest of the runtime
needs after it, and why most of it is one defect wearing four costumes.

Written 2026-08-27 from a read-only review of `carrick-runtime`,
`carrick-vmm-hvf`, `carrick-kernel` and `carrick-abi` at `28a8678c4`. **Nothing
in this document was executed** — no build, no test, no guest, no gate. Every
count is a grep or a hand read of the named line, and every claim carries a
`file:line` or the command that produced it. Where something is inferred from
reading control flow rather than observed, it says so **in bold**. Treat the two
inferences as hypotheses with a named way to check them, not as findings.

Companion to [`identity-and-scope-domains.md`](identity-and-scope-domains.md),
which this document extends rather than replaces: Part 2 is largely a status
check on that document's ranked list plus one domain it does not name.

---

## The shape

Four of the five findings here are the same defect:

> **An invariant the type system does not carry, enforced instead by a match arm,
> a doc comment, or a process abort — and made load-bearing by an execution-model
> change that broke nothing and compiled cleanly.**

The file-descriptor enum encodes "what kind of fd is this" as 25 match arms in 17
functions. The identity domains encode "which process does this state belong to"
as a doc comment. The 420 aborts encode "this transition must not fail" as
`std::process::abort()`. The lock hierarchy encodes its nine levels as a module
doc and a validator no shipping binary runs.

None of these is rot. Each was proportionate under the retired
one-process-per-guest model and became disproportionate under HVPatch, without a
single compile error. That is the same observation
[`identity-and-scope-domains.md`](identity-and-scope-domains.md) closes on, and
it generalizes further than that document claims.

---

# Part 1 — the file-descriptor description layer

## What exists

Linux has three layers: fd number → open file description → inode/object.
Carrick models two and a half.

| Layer | Where it lives | State |
|---|---|---|
| fd number | `kernel::FileTable` (`kernel/objects.rs:1045`) | real, typed, fork/exec-aware |
| description | `kernel::FileDescription` + `FileDescriptionBacking` (`kernel/objects.rs:506`) | real seam, **carries no operations** |
| object / inode | — | **missing**; faked with `u64` ids in side registries |

`FileDescriptionBacking` has six methods — `is_epoll`, `snapshot_until`,
`retain_fd_ref`, `release_fd_ref`, `fd_ref_count`, `as_any`. No read, no write,
no poll, no ioctl, no close. Every operation instead downcasts to
`RwLock<OpenDescription>` and matches a 25-variant enum (`dispatch/fd_table.rs:890`)
whose variants each carry a copy of a 21-field `OpenDescriptionBase`
(`dispatch/fd_table.rs:242`) holding socket options, pipe capacity, memfd seals,
leases and SIGIO owners — inapplicable to most variants that carry them.

## Measurements

| Measurement | Value | How |
|---|---|---|
| `OpenDescription` variants | 25 | `reexec_kind_name` (`fd_table.rs:1250`) enumerates them |
| `OpenDescriptionBase` fields | 21 | field count, `fd_table.rs:242-341` |
| References to concrete `OpenDescription::` variants | 1,074 in 25 files | `grep -rn "OpenDescription::" --include='*.rs' crates` |
| Functions enumerating **all 25** variants | 17 | per-function distinct-variant census (script below) |
| Functions enumerating ≥6 variants | 34 | same census |
| Types implementing `FileDescriptionBacking` | 2 | `RwLock<OpenDescription>`, `ioring::IoUringBacking` |
| `FileAuthorityCore::execute_call` production callers | **0** | `grep -rn "execute_call" crates/carrick-runtime/src --exclude-dir=file_authority` |
| K1 legacy authority-escape call sites | 361 in 9 families | `scripts/migrate/k1-file-authority-callsite-taxonomy.json` |
| Gates running the K1 drift checkers | **0** | `grep -rn "check-k1" justfile scripts .github` |

The census:

```sh
python3 - <<'EOF'
import re, os, collections
root, worst = 'crates/carrick-runtime/src', collections.Counter()
for dp, _, fns in os.walk(root):
    for fn in (f for f in fns if f.endswith('.rs')):
        p = os.path.join(dp, fn)
        lines = open(p, encoding='utf8', errors='replace').read().split('\n')
        starts = [(i, m.group(6)) for i, l in enumerate(lines)
                  if (m := re.match(r'\s*(pub(\([^)]*\))?\s+)?(async\s+)?(const\s+)?(unsafe\s+)?fn\s+(\w+)', l))]
        starts.append((len(lines), None))
        for (s, name), (e, _) in zip(starts, starts[1:]):
            n = len(set(re.findall(r'OpenDescription::(\w+)', '\n'.join(lines[s:e]))))
            if n >= 6:
                worst[f"{p}::{name}"] = n
for k, v in worst.most_common():
    print(v, k)
print("functions matching >=6 variants:", len(worst))
EOF
```

The seventeen all-variant functions are `read`, `readv`, `pread64`, `preadv`,
`pwrite64`, `pwritev`, `lseek`, `fchdir`, `fd_access`, `sendfile_offset`,
`sendfile_bytes`, `readlink_target`, `snapshot_until`, `stat_source`,
`poll_ready_events`, and — the tell — **`base()` and `base_mut()`**
(`fd_table.rs:1741`, `:1774`), 25 arms each whose only job is to reach fields
every variant already has.

## Three process aborts stand in for three missing types

- `OpenDescription::base()` (`fd_table.rs:1741`) aborts on `Closed` — the
  draining identity shell the module doc says is deliberately snapshot-visible.
- `OpenDescription::base_mut()` (`fd_table.rs:1774`) does the same.
- `FileDescription::open_description()` (`fd_table.rs:1518`) aborts with
  *"model-only file description escaped into dispatch"* for any backing that is
  not one of the two known ones.

So the extension seam is open in the type system and closed at runtime by
`std::process::abort()`. This is Part 2's Finding A in miniature.

## The three pressure tests

**epoll — two readiness authorities for one object.** `epoll_ready_events`
(`dispatch/net.rs:1054`) and `poll_ready_events` (`dispatch/net.rs:1958`) are
near-duplicate state machines with asymmetric coverage. Measured with a
variant-set diff over the two function bodies:

- poll names 14 variants epoll does not: `Closed`, `Directory`, `Epoll`,
  `Fanotify`, `File`, `FsContext`, `HostFile`, `InMemoryFile`, `Inotify`,
  `Netlink`, `PerfEvent`, `Pidfd`, `SignalFd`, `SyntheticFile`
- epoll names one poll does not: `Mqueue`
- eight are shared

Everything epoll does not name falls through to a host `poll(2)` and returns 0
when `host_fd_for_poll` yields `None`.

> **Inferred, not executed.** `host_fd_for_poll` (`net.rs`, in the
> `fn host_fd_for_poll` body) has no `Netlink` arm, and a synthetic
> `OpenDescription::Netlink` has no host fd — its readable bytes live in
> `recv_queue`. Reading that control flow, `epoll_pwait` on an AF_NETLINK socket
> with a queued rtnetlink dump reports nothing, while `poll(2)` reports POLLIN
> from the `Netlink { recv_queue }` arm at `net.rs:2250`. glibc's `__check_pf`
> and `getaddrinfo` poll netlink. **Check it before believing it:** install a
> `Netlink` description with a non-empty `recv_queue` and assert both surfaces,
> as Task 6 of the plan does.

epoll's own interest map is `HashMap<i32, EpollInterest>` keyed by **guest fd
number**. That is why `EpollInterest` (`fd_table.rs:62`) needs `reg_gen`,
`io_gen`, `last_ready`, `last_read_avail` and a
`target: Option<Arc<FileDescription>>` to re-derive the identity the key threw
away. And `epoll_rearm_after_io` must be hand-called from 13 sites in the I/O
paths — a cross-cutting concern with no seam to hang on.

**inotify — the good pattern sitting next to the bad one.** `InotifyBackend`
(`inotify.rs:299`) is exactly right: a trait with `NativeLinuxInotify` and
`VnodeDiffInotify` behind it, chosen per host. But the VFS has no notify hook, so
in-memory files cannot be observed by `EVFILT_VNODE`, and events are hand-emitted
by 11 explicit `self.inotify_*` calls in `dispatch/fs.rs` plus 5 more for
fanotify. Two event sources for one object, the second being "remember to call
it." Two of those calls sit inline in the `read(2)` prologue.

**io_uring — the one that escaped, and the proof the seam does not work.** It is
the only fd type that is not an `OpenDescription` variant: it implements
`FileDescriptionBacking` directly and is reached through
`concrete_backing::<IoUringBacking>()` at 11 sites. That should be the success
story. Instead:

- it carries a **shadow `RwLock<OpenDescription>`** (`ioring.rs:248`,
  `open_metadata()`) purely so the rest of dispatch can reach status flags and
  the fd-reference count, because those generic fields live inside the enum's
  `base` rather than on `FileDescription`;
- every generic predicate needs a hand-written pre-check — `epoll_ready_events`,
  `poll_ready_events`, `read`, `stat`, `mmap` all open with
  `if let Some(ring) = …concrete_backing()`;
- and the file opens with
  `#![allow(dead_code)] // complete_sqe/opcode_serviced are the unit-tested reference; the wired enter path inlines the op match for borrow simplicity`
  (`ioring.rs:19-20`). **The tested opcode implementation is not the shipped
  one**, because the fd layer offers no callable per-op interface that survives
  the borrow checker inside the enter loop. Two implementations of io_uring
  opcode semantics, with the gate on the dead one.

## The missing object layer, concretely

`pipe_buffered_bytes` (`dispatch/fs.rs:4371`) **linearly scans the entire fd
table** to find a pipe's peer end by matching `pipe_id`, because there is no pipe
object — only a `u64` smeared across two descriptions. That is the absent third
layer showing up as an O(n) walk on a hot path.

## The cost lands on both gates

`read(2)` (`dispatch/fs.rs:10013`) makes seven independent fd-table round trips
before a byte moves: `fd_is_o_path`, `io_uring_description`, `fd_is_secretmem`,
`fd_is_controlling_tty`, `io_is_nonblocking`, `inotify_emit_for_fd`,
`fanotify_emit_for_fd`. Each is `resources::files()` → `Arc` clone → `RwLock`
read on `HashMap<i32, FileSlot>` → slot clone (another `Arc`) → `RwLock` read on
the description → match → drop. There is no "resolve the fd once, get a typed
handle, ask it questions" step, because the abstraction has no typed handle to
hand back.

That is carrick's own host userspace — the bucket AGENTS.md names as never
properly attacked — and it is structural, not tuning.

## The replacement is already in flight, and unrouted

`file_authority/` is ~9,000 lines across 24 commits, 2026-08-23 → 2026-08-26. It
is the right diagnosis: three real layers (`FileTableState` /
`FileDescriptionState` / `VfsObjectId`+`PipeId` objects), typed non-zero domains,
per-object generations and revisions, and epoll as a first-class `EpollState`
with `EpollHostPlan` separating "what host registration should exist" from
"mutate the state" — the seam the legacy epoll path lacks.

Its public API is `launch()` (`file_authority/root.rs:35`) and `execute_call()`
(`file_authority/core.rs:185`). **`execute_call` has zero callers outside the
module.** All 26 external references are lifecycle and binding. It is exercised
only by its own 2,934 lines of tests. Four days old and moving fast, so
"abandoned" is the wrong word — but it is a second model of file descriptors
growing beside the one that ships, which is the failure mode AGENTS.md names
("Opt-OUT, not opt-in").

Two design corrections to make **before** any family routes through it:

1. **The RPC shape has outlived its reason.** `Command` (~50 variants),
   `Outcome` (~46), the `Request`/`Response` wrapper and
   `MAX_TERMINAL_DEDUP_ENTRIES` all exist to survive lost datagrams to a helper
   process deleted in `36d141d69`; `file_authority/transport.rs:26` still
   describes "the datagram client". The approved plan's Transport section argues
   for IPC on behalf of the native and VMM host-process lanes — which AGENTS.md
   records as retired in favour of the consolidated HVPatch kernel. In-process
   that layer buys nothing and reintroduces a god-enum one layer up. **Amend the
   approved plan before acting; do not silently contradict it.**
2. **`AuthorityBacking` is closed too.** `file_authority/backing.rs:12` is a
   10-variant enum whose own doc says further kinds "are added here as their
   operation families move." It has no inotify, fanotify, netlink, mqueue, bpf,
   perf, pidfd, fscontext or pty. On that trajectory it converges back to 25
   variants — and it pulls io_uring, the one type that escaped, back into an
   enum as `AuthorityBacking::IoUring`.

Execution plan for the above:
[`superpowers/plans/2026-08-27-fd-description-seam.md`](superpowers/plans/2026-08-27-fd-description-seam.md)
(9 tasks: gate the K1 burndown, hoist `DescriptionCommon` onto
`FileDescription`, delete the three aborts, unify readiness, open
`AuthorityBacking`, route the first family). It implements the unscheduled
Wave 2 of
[`superpowers/plans/2026-08-12-per-run-file-authority-atomic-migration.md`](superpowers/plans/2026-08-12-per-run-file-authority-atomic-migration.md);
Waves 4–5 stay with that document.

---

# Part 2 — what the rest of the runtime needs

## Status of the four identity domains

[`identity-and-scope-domains.md`](identity-and-scope-domains.md) (2026-08-16, 42
audited defects) is the correct ranked list and should stay the controlling
document. The original audit baseline was `28a8678c4`; the status column below
is maintained through code head `7a2af1aee` using the cited source censuses,
tests, and implementation receipts:

| Domain | Prescribed fix | Status |
|---|---|---|
| **Scope** — a `static` carries no mark saying carrier vs. one Linux process | `CarrierGlobal<T>` + closed `CarrierScope` | **In flight, different shape.** No `CarrierGlobal` type exists (`grep -rl CarrierGlobal crates` → 0). `carrick-embed` Phase B is executing it instead: all 228 statics classified container-state vs. carrier-infra with per-row `Container` destinations ([`identity-and-scope-domains-embed-census.md`](identity-and-scope-domains-embed-census.md)). The census route is arguably better than the wrapper type; it should be recorded as the accepted answer so the wrapper is not also built. |
| **Ownership** — no type separates the current `mm` from another process's | `MmToken`, `CurrentMm`/`ForeignMm` split, `CowBroken` witness | **Barely started.** `kernel/foreign_mm.rs` exists; `MmToken` and `CurrentMm` do not (0 files each). |
| **Populations** — eight distinct thread sets, all `usize` | delete `count() -> usize`, replace with a witness type | **Closed 2026-08-28.** `VcpuRegistry::count()` is deleted; fork/crash protected work holds an identity-aware `VcpuLeaseDrainGuard`; purpose-specific exact participant witnesses are minted from `Task`; and `GuestExecutorCensus` stores exact identities. The monotone source gate reports zero production findings across 162 Rust leaves. |
| **Lifecycle** — "alive" vs. per-purpose "can reach a safe point" | explicit run state on kernel `Thread` | **Closed 2026-08-28.** The existing scheduler-owned `ThreadExecutionState` is the sole run-state authority. Purpose-specific Task witnesses, dynamic `CrashQuorum` membership, generation-stamped crash RAII, and exact non-final-exit survivors avoid duplicating lifecycle state. |
| **Lock order** — make the hierarchy structural | a token only the outer acquisition can mint | **Shipped as a dead gate — see Finding B.** |

The two "cheapest, do first" mechanical gates are now implemented as monotone
source/compiler censuses: `check-runtime-global-state.py` covers process-global
state and `check-host-authority-transitions.py` covers host-identity/authority
operations. Both are wired through `just lint-domains`; the compiler census
continues to fail closed on position-only drift rather than silently
rebaselining it.

One worked example from that document's scope class closed on the day of this
audit: `AliasOwnershipScope::Root` became `ContainerRoot(ContainerRootToken)` in
`2aaefa800` (merge `cc23cdcf4`), carrying its own discriminator instead of
inferring container identity from `mm_root_slot.is_none()`. One down; see
Finding D for the rest of that file.

## Finding A — 420 process aborts, and a blast radius that changed underneath them

```sh
grep -rn 'std::process::abort()' --include='*.rs' crates/carrick-runtime/src crates/carrick-vmm-hvf/src | wc -l   # 420
grep -rn 'std::process::abort()' --include='*.rs' crates | wc -l                                                  # 462
```

Concentration: `carrick-vmm-hvf/src/trap.rs` 92, `vcpu_loop/mod.rs` 74,
`dispatch/mem.rs` 35, `vcpu_loop/quiesce.rs` 33, `dispatch/mod.rs` 25,
`vcpu_loop/executor.rs` 22, `kernel/scheduler.rs` 18, `dispatch/fs.rs` 16.

Sampling the messages, these are not "the host lied" — they are internal state
transitions that cannot fail: *"claim persistent process terminal owner"*,
*"publish logical exec terminal result failed"*, *"reserve persistent failure
inventory"*, *"classify persistent terminal MM ownership"*, *"begin persistent
failure sibling drain"*. Each is an invariant that could not be encoded in a
type, enforced by killing the process.

The important part is not the count. It is that **the blast radius changed and
the code did not.** Under one-process-per-guest an abort killed one guest
process. Under HVPatch the carrier hosts every guest process in the container, so
one bad state in one guest now kills all of them — and `abort()` skips
destructors, so nothing flushes. Nothing broke; the calls still compile and still
read as proportionate.

This is a fifth domain for
[`identity-and-scope-domains.md`](identity-and-scope-domains.md), with the same
signature as its other four: correct under the retired model, wrong under the
current one, invisible to a gate whose smoke lane runs one guest process.

The work is not "remove all 420." It is to classify them the way the statics were
classified — genuinely unrecoverable carrier faults versus transitions that
should now return a typed error — and to record the verdict per site so the set
can only shrink.

## Finding B — the lock-order validator gates nothing

`dispatch/lock_order.rs` originally documented a clean nine-level hierarchy (`PtPause`,
`HostAlias`, `FdTable`, `FsState`, `PtyTable`, `Proc`, `SysV`, `Signal`,
`ThreadRegistry`) and validated it. Two facts made it inert:

1. Its checks were `#[cfg(debug_assertions)]` (`lock_order.rs:57`, `:80`), and the
   justfile says so itself, in the `build-debug-profile` comment: *"Every other
   signed lane is a release build, so every `debug_assert!` … is compiled out and
   can never fire in any runnable configuration. Without this recipe those
   assertions are decoration: an invariant that looks guarded and is not."* That
   recipe is explicitly *"never a perf or conformance artifact"*, so no gate runs
   it.
2. There were **two** real acquisition sites in the whole tree
   (`vcpu_loop/executor.rs:5198` and `:8431`), plus one boundary check at
   `:1857`. Both acquisitions declared the same level, `LockLevel::Proc`. Eight of
   the nine documented levels were never declared by anyone.

So the hierarchy was documentation, not enforcement — which is what
[`identity-and-scope-domains.md`](identity-and-scope-domains.md) item 5 already
concluded on different evidence: discipline has failed here twice, wedging a
carrier at 0% CPU once and turning an intended `ENOMEM` into an unkillable hang
via an alias-cleanup self-deadlock. The debug-only generic validator was deleted.
The concrete edges are now structurally closed with mintable tokens rather than a
nine-level runtime hierarchy: MM `PtPause` -> `HostAlias` was closed via the
`MmToken` subsystem, and SysV per-process -> shared namespace was structurally
sealed via `SysvProcessGuard` -> `SysvNamespacePermit` -> `SysvPairedNamespaceGuard`
with the fail-closed `check-dispatch-lock-authority.py` gate.

## Finding C — a field's scope lives in one constructor, not in its type

`SyscallDispatcher` (`dispatch/mod.rs:2740`, fork constructor
`fork_clone_with_prepared_mm` at `:4423`, its struct literal at `:4468`) has 18
fields, 35 `impl SyscallDispatcher` blocks, and ~1,828 functions in the
`dispatch` module excluding `tests.rs`.

The dispatcher is **per-Linux-process**, not per-carrier: guest `fork` builds a
`child_dispatcher` in `fork_clone_with_prepared_mm`. So there is no aliasing bug
here — I checked for one and there is not one. The finding is subtler and still
real: **that constructor is the only place any field's scope is decided**, and it
uses three different disciplines in eighteen adjacent lines.

- shared with the parent — `sysv: Arc::clone(&self.sysv)`, `mqueue`, `network`,
  `observers`, `file_authority`, `container`, `page_geometry`
- copied with fork semantics — `io.fork_clone()`, `proc.fork_clone(parent, child)`,
  `fs.fork_clone()`, `seccomp.fork_clone()`, `fork_sysv_process_attachments()`
- reset in the child — `timer_delivery: RwLock::new(None)`,
  `signal_pump_requested: AtomicBool::new(false)`

Nothing in a field's *type* says which of the three is correct for it. A new
field compiles under all three, and the reviewer of the commit that adds it sees
one plausible-looking line in a long struct literal. This is the scope domain in
struct form, and the statics census cannot see it — that survey greps
`static`/`OnceLock`/`env::var` and a struct field is none of those.

The class is not hypothetical here: `fs: fs::FsState` is process-local by
`fork_clone`, and the approved authority migration already names that as a defect
to fix ("Move the writable `--fs memory` namespace and file contents out of
process-local `FsState`… parent and child reopen different fork-local namespace
copies, which is another authority and is forbidden").

Three fields are `RwLock<Option<T>>` — `container`, `timer_delivery`,
`file_authority` — so "not yet bound" is a state every caller must re-check and
no caller can be prevented from mishandling.

## Finding D — `trap.rs` is the largest and least factored thing in the tree

27,808 lines — nearly 2× `dispatch/fs.rs`, the next largest — with 741 function
definitions, 189 `#[test]`s, and 36 process-global mutable statics, among them
the shared VM cell, the alias backing registry, the global-frame IPA allocator,
the alias version registry, the carrier stage-2 lease owner,
`GLOBAL_FRAME_OWNER_GENERATION`, and the vCPU permit table.

Every one of those statics is an instance of the scope domain awaiting the same
treatment `AliasOwnershipScope` just received. The structural-leverage note that
HVF is the factoring holdout still reads true from the outside: `carrick-x86` has
`X86EngineCore`, `carrick-vmm-hvf` has `hvf_aarch64_engine.rs`, but the trap loop
itself has not been decomposed behind it.

> **Inferred, not verified.** I did not trace how much of `trap.rs` is
> HVF-specific versus HVPatch-kernel logic that could move behind the HAL. The
> line count and static count are facts; "least factored" is a judgement from
> reading its top-level item list. **Check it** by classifying its 741 functions
> the way the statics census classified statics, before planning any split.

## What is not a problem

Stated so the list above is credible. I went looking for a second god-enum in the
filesystem layer and did not find one. `Vfs` (`vfs/mod.rs:499`, 10
implementations, mount table) sits cleanly over `FsBackend`
(`fs_backend.rs:195`, 2 implementations, the writable overlay), and
`vfs/mod.rs:37` documents the split as deliberate. Its only gaps are the two Part
1 already routes to follow-on work: no object layer between path lookup and open
description, and no notify hook. `InotifyBackend` is the best-factored seam in
the runtime and is the pattern to copy, not fix.

---

## What to build

Ranked by leverage, not effort. Items 1, 3 and 4 are
[`identity-and-scope-domains.md`](identity-and-scope-domains.md)'s own ranking,
unchanged; 2 and 5 are this audit's additions.

1. **The two mechanical gates** — a `static` lint and a
   `getpid`/`process::id()`/`proc_listallpids` ban in Linux-semantics paths, both
   on monotonic baselines that fail on a new finding *and* on a baseline entry
   that stops matching, so fixing one forces deleting its entry. Days, not weeks,
   and the `carrick-embed` census has already done their classification work.
   The same baseline mechanism serves item 2.
2. **Classify the 420 aborts** (Finding A). Same shape as the statics census:
   every site gets a verdict — carrier fault versus typed error — recorded in a
   file that can only shrink. Start with `vcpu_loop/` (129 sites across `mod.rs`,
   `quiesce.rs`, `executor.rs`), where the transitions are internal publication
   steps rather than host failures.
3. **Populations and lifecycle as types.** Delete `count() -> usize`; mint
   per-purpose participant sets from the `Task`. Copy `CrashQuorum`. This fixes
   live bugs and is the prerequisite for N:M guest-thread decoupling, which is
   frightening today *only* because the populations are conflated.
4. **`MmToken` / `CurrentMm` vs `ForeignMm`.** Unblocks three syscall families
   (`process_vm_readv/writev`, ptrace PEEK/POKE, `/proc/<pid>/mem`) that each
   independently invented a workaround instead of one of them building the
   capability.
5. **Lock order as a mintable token** (Finding B), deleting the
   `debug_assertions` validator in the same change rather than leaving a
   green-looking artifact beside it.

The file-descriptor work of Part 1 runs in parallel with all of these — it is
scoped to `carrick-runtime`'s dispatch and kernel object modules and shares no
files with items 1–5.

## Sequencing

1 and 2 are cheap and stop the bleeding. 3 fixes live bugs. 4 unblocks stalled
syscall families. Part 1's Tasks 1–5 (the `DescriptionCommon` hoist) are
independent of every one of them and can start immediately.

## Accepted decisions — 2026-08-28

- The reviewed `carrick-embed` census plus the monotone global-state ledger
  supersedes `CarrierGlobal<T>` / `CarrierScope`; do not build both. The dated
  decision is recorded in [`identity-and-scope-domains.md`](identity-and-scope-domains.md#accepted-scope-implementation--2026-08-28).
- FileAuthority operates as one direct canonical in-carrier core. The retired
  helper/IPC production transport is amended out of the migration plan; its
  historical design remains documentation, not scheduled work. See
  [`2026-08-12-per-run-file-authority-atomic-migration.md`](superpowers/plans/2026-08-12-per-run-file-authority-atomic-migration.md#decision-2026-08-28-direct-canonical-core).

## Abort-ledger implementation receipt — 2026-08-28

The `420` in Finding A remains the historical raw-text count at `28a8678c4`;
it is not a current ceiling. The token-aware, production-capable source census
now requires three exact shards and classifies **460** current calls at
`bfdee9aac`:

| Shard | Carrier fault | Typed-error debt | Total |
|---|---:|---:|---:|
| `runtime.json` | 141 | 49 | 190 |
| `hvf.json` | 120 | 0 | 120 |
| `vcpu-loop.json` | 147 | 3 | 150 |
| **Total** | **408** | **52** | **460** |

These are machine-counted classifications, not removals. Full `--check` fails
closed unless all three named ledgers exist, match every current source leaf,
and keep each shard's typed-error debt ceiling equal to its checked row count.
`just lint-domains` runs that exact gate after the process-global-state census.

## Global-state ledger reconciliation — 2026-08-29

The monotone source census is reconciled with current accepted runtime state.
Three new test-harness leaves are classified `test_only`: the isolated
one-vCPU subprocess sentinel and the two foreign-COW fixture locks. The
`EXACT_MM_STAGE1` thread-local is classified `carrier_infra`: it is a
per-service-thread weak lookup stack for synchronous re-entry, while authority
remains in the upgraded exact-MM lease and executor census. The stale
`dispatch/lock_order.rs::HELD_LOCKS` row was removed with the deleted
debug-only validator required by item 5, and the carrier-global host-frame owner
fingerprint was refreshed against its current accepted definition without
changing its classification. `check-runtime-global-state.py --check` now exits
zero with no additions, removals, or fingerprint drift.

## Population/lifecycle implementation receipt — 2026-08-28

Code head `7a2af1aee` completes item 3 without inventing one generic "live
thread" predicate. `ForkBarrierParticipants`, `CrashBarrierParticipants`,
`ThreadExitParticipants`, `CrashCaptureParticipants`, and
`CoreNoteParticipants` retain exact Task identities for their individual
purposes. Owner-sensitive minting authenticates the exact `ThreadKey` under one
Task-membership lock. `GuestExecutorCensus` owns exact thread or anonymous
identities; duplicate admission, identity exhaustion, and crash participation
failure are typed and transactional. Generation-stamped crash-participation
RAII prevents a stale guard from clearing a successor.

Fork/crash decisions use only boolean witness questions; numeric projections
exist solely at the fixed-width probe ABI. `CrashQuorum` refreshes membership
on every poll, and non-final exit requires an exact survivor. The pre-existing
`ThreadExecutionState` remains the sole scheduler lifecycle authority.

The source checker passes 14 negative and 14 positive fixtures and scans 162
production Rust leaves with zero findings. Focused executor, witness, quorum,
fork, core, thread-quiesce, and observability gates pass. Repository-wide
Clippy, docs, dependency policy, support-matrix, workspace-build, full unit, and
unrestricted integration gates pass. `just lint-domains` and `just ci` stop
only at the known compiler host-authority positional inventory drift with
`changed=[]`; no baseline was rewritten. The abort census has since been
reconciled to the exact 460-row table above; all three shards and the 54 checker
unit tests pass together at `bfdee9aac`.

The delegated fork consumer used Antigravity conversation
`353b580d-2a8a-4e8a-bb35-679894e54923` over three turns; Codex rejected and sent
back a lossy boolean telemetry projection before integrating worker commits
`4ccd570a2` and `d99f5c06f` as `eaf216c95` and `d23f37022`. The crash/core
consumer used conversation `a86ce8bd-f883-4e1a-a6b2-7d38522ef847` for one turn;
worker commit `d035366b2` became `c02fc50f3`. Codex re-ran the exact worker gates
and independent reviews approved both migrations.

## SysV paired-lock authority implementation receipt — 2026-08-29

The concrete lock-order edge from item 5 (per-process SysV attachment lock -> shared SysV namespace lock) is structurally sealed by this milestone.

- **Lock Authority Module**: Created private `crates/carrick-runtime/src/dispatch/sysv/lock_authority.rs` providing `SysvProcessGuard<'a>`, `SysvNamespacePermit<'process>`, and `SysvPairedNamespaceGuard<'process>`. A process guard must be acquired first and is the sole way to mint an exact-owner, borrow-bound permit required for paired namespace locking.
- **Enforcement & Non-leakage**: Permits and guards cannot be constructed freely, cloned, copied, leaked as raw mutex guards, or used across mismatched owner identities. Four compile-fail doctests compile against the actual authority API and reject multiple minting, cloning, lifetime escape, and a separately chosen namespace.
- **Call-Site Migration**: All five production paired sites in `dispatch/sysv.rs` (`note_sysv_remap_file_pages`, `commit_sysv_fork_inheritance`, `commit_remapped_shmat`, `validate_shmdt`/`commit_shmdt`, and `commit_host_alias_shmat`) have been migrated to the typed authority.
- **Ergonomic Standalone APIs**: Standalone namespace-only and process-only accessors remain clean via private scoped closures (`with_state`, `with_state_mut`, `with_sysv_process`, `with_sysv_process_mut`). `SysvIpcNamespace.state` and `SyscallDispatcher.sysv_process` are strictly private.
- **Fail-Closed Gate**: Added `scripts/migrate/check-dispatch-lock-authority.py` and `scripts/migrate/dispatch-lock-authority.json`, with self-tests (`--self-test`) and shrink-only enforcement wired into `just lint-domains`. The exact inventory includes one trusted raw process-lock minting boundary and three namespace-lock boundaries, plus the existing proc, PTY, and FileTable sites.
- **Concurrency Verification**: Added bounded subprocess regression testing with watchdog timeouts. The race enters the production `synthetic_proc_context` route while attachment cleanup and paired mutation run concurrently; an intentionally wedged child proves timeout kill and reap.
- **Deliberate Partial Boundary**: This milestone seals the structural process-then-exact-namespace order without changing SysV accounting semantics. The baseline flocked `nattch` update and RMID unlink remain synchronous under namespace authority. Extracting that host I/O is a separate generation-authenticated prepare/execute/finalize campaign; this receipt does not claim zero host I/O under Carrick locks.

This receipt does not close the whole audit. Item 4 now has the structural
`MmToken` / `CurrentMm` / `ForeignMm` / `CowBroken` seam plus accepted
`process_vm_readv` / `process_vm_writev` and ptrace PEEK/writable-POKE
consumers. RX `PTRACE_POKETEXT`, the retained `/proc/<pid>/mem` description,
and the fail-closed differential matrix remain open. Item 5 (mintable
structural lock ordering) is now structurally closed for both concrete edges
(MM `PtPause` -> `HostAlias` and SysV per-process -> shared namespace).

## The rule to carry forward

[`identity-and-scope-domains.md`](identity-and-scope-domains.md) ends with the
right rule, and this audit only widens its scope:

> When the execution model changes, the dangerous code is not the code that
> breaks. It is the code that keeps compiling, keeps passing, and keeps
> explaining itself in terms of a model that no longer exists.

An enum arm, a doc comment, a `static`, and an `abort()` are all ways of writing
an invariant the compiler will not check. Each survives a model change intact and
silent. The countermeasure is the same in every case: make the invariant a type,
and where it cannot be a type yet, make it a baseline that can only shrink.
