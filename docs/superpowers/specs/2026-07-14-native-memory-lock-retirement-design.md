# Native Memory-Lock Retirement — Design

**Goal:** Remove the dominant host-syscall cost of the Darwin-native backend —
contention on the single process-wide `Arc<parking_lot::Mutex<NativeMappedMemory>>`,
which is ~70% of all host syscalls under a multithreaded guest (Go) — by
making the read-mostly guest-memory metadata concurrently readable, shrinking
critical sections, and giving the one genuinely-shared cross-thread subsystem
(the exclusive monitor) its own fine-grained lock. Robust/correct/durable
foundation: backend wins compound up the stack.

## Measured basis (confirmed, not hypothesized)

- Tree-wide on the Go W1 reducer (go_types.test `TestImplicitsInfo`, 1M-trap
  ceiling): `psynch_cvwait` 1,228,606 + `psynch_cvsignal` 1,220,642 =
  ~70% of all host syscalls; 17,487 guest futex ops → ~70x amplification.
- Symbolicated (count-based, not snapshot): the condvar traffic is
  `parking_lot::RawMutex::lock_slow` / `unlock_slow` from
  `complete_dsr_syscall` and `run_native_dsr_thread_loop_profiled` — i.e.
  contention on the shared memory `Mutex`, NOT the guest-futex primitive (a
  backtrace snapshot mislabeled that; the count attribution is authoritative).
- Evidence: `.superpowers/sdd/{amplification-profile,condvar-pin-confirmed,
  memlock-classification}.md`.

## What the lock protects (from the classification map)

`NativeMappedMemory` (native_darwin.rs:6273) fields, grouped by access shape:

- **Immutable after init** (only `execve`'s `replace_image` @:2334 rewrites):
  `address_mode`, `host_page_size`, `linux_page_size`, `dsr_translator`
  (`Option<Arc<ProcessTranslator>>` — already an Arc handle).
- **Mapping/protection metadata** (read hot, written by mmap-family):
  `regions`, `protections`, `native_page_protections`,
  `native_write_exec_writable_pages`, `linux4k_page_protections`,
  `owned_host_ranges`.
- **Exclusive monitor** (cross-thread ABA state): `exclusive_reservation`
  (struct field — used only by the single-threaded-gated linux4k path),
  `exclusive_sequences` (BTreeMap — genuinely shared; bumped on CAS and on
  every overlapping `write_bytes` via `invalidate_exclusive_range`).
- **Interior-mutable already** (`&self`): `dsr_generations`
  (`PageGenerationTable` = AtomicU64 + internal RwLock).

Two facts the design leans on:
1. **Blocking is already lock-free.** `dispatch_native_syscall_inner` (:3427)
   scopes the lock to `dispatcher.dispatch_threaded(...)` only (guard dropped
   at :3449); every `wait_native_*` runs with no memory lock. `enter_dsr_prepared`
   runs guest code with no memory lock by design. So no blocking op holds the
   lock — the contention is purely short critical sections serializing.
2. **The hot path is a reader** except for two coupling points:
   - `NativeSignalTrap` (`complete_dsr_syscall` :2484, signal delivery :2453,
     sigreturn :2513) holds `&mut NativeMappedMemory` but `complete_syscall`/
     `set_pc` mutate only trap-local `regs`; guest-RAM writes go through region
     host pointers (needs `regions`/`protections` by-ref, not table mutation).
   - `write_bytes_raw` (:8856) — the single blocker — always calls
     `invalidate_exclusive_range` (mutates `exclusive_reservation`/
     `exclusive_sequences`), plus conditional `note_dsr_code_mutation`
     (interior-mutable, fine) and, only for writes to an executable page,
     `prepare_native16k_write_exec_host_write` (mutates metadata — the rare
     SMC/JIT case).

## Target lock architecture

1. **Immutable-after-init config → no lock.** Read `address_mode`, page sizes,
   and the `dsr_translator` Arc without locking (an `Arc<NativeMemoryConfig>`
   or equivalent). Only `replace_image` swaps them (whole-process quiesce).
2. **Mapping/protection metadata → `parking_lot::RwLock`.** Readers
   (translation, permission checks, guest-RAM byte copies, fault
   reverse-translation, the rejection predicates) take `.read()` and run
   concurrently. Writers (mmap/munmap/mprotect/madvise/brk via :3440,
   `replace_image`, fault-commit `protect_range` @:2577/:2626, W^X fault
   @:2586, linux4k guarded fault @:2604, `map_host_alias` @:2403) take
   `.write()`. The SMC write-to-exec-page case uses `upgradable_read()` and
   upgrades only when it reaches the W^X path.
3. **Exclusive monitor → out of the writer-exclusive struct.** Fold the struct
   `exclusive_reservation` into the already-per-thread
   `NativeThreadRuntime.exclusive_reservation`. Give `exclusive_sequences` its
   own small lock (or interior-mutable / sharded map). This is what lets
   `write_bytes_raw` — and therefore every read()/recv buffer copy, signal
   frame, clone/fork tid write, DC-ZVA — run under a read guard.
4. **`dsr_generations` → unchanged** (already `&self`).

## Correctness argument

- A writer (`.write()`) excludes all readers, so a mapping mutation
  (munmap/mprotect/exec) cannot race a reader translating or writing that page
  — the exact invariant the Mutex enforced today.
- Concurrent readers writing DIFFERENT guest addresses do not conflict;
  writing the SAME address concurrently is a guest-level data race, not
  carrick's to serialize (matches Linux semantics).
- The exclusive-sequence move preserves cross-thread ABA/monotonic semantics
  behind its own lock: a store or an overlapping write still bumps the shared
  sequence that invalidates another thread's stale reservation.
- No blocking operation holds any of these locks (already true; preserved).

## Phasing (each independently landable, red-first, measured)

### Phase 1 — Move the exclusive monitor out of `NativeMappedMemory`
Fold the struct `exclusive_reservation` into `NativeThreadRuntime`
(per-thread); put `exclusive_sequences` behind its own lock (or make it
interior-mutable). No lock-type change to the memory Mutex yet — this is the
prerequisite that makes the hot-path guest-RAM writes read-safe.
- Gate: full native probe gate + the CAS/futex/threading fusion gate
  (`fusion_gate.sh`, ≥10x each: futexpingpong, futexwake*, manythreads,
  forkexecpthread, execthreads, exitgroupthreads) all MATCH; `just ci` green.
- Correctness beats coverage: any atomic livelock/lost-wake stops the phase.

### Phase 2 — `Mutex<NativeMappedMemory>` → `RwLock<NativeMappedMemory>`
Apply the per-site read/write classification (already mapped). The `:3440`
dispatch site pre-classifies by syscall number: mapping-mutators
(mmap/munmap/mprotect/madvise/brk/exec) take `.write()`, all others `.read()`.
`write_bytes_raw` takes `upgradable_read` and upgrades on the W^X-exec-page
branch. Hot-path methods that were `&mut self` only to satisfy the trap become
`&self` where they touch only guest RAM + the (now externally-locked)
exclusive monitor + interior-mutable `dsr_generations`.
- Gate: native probe gate + fusion gate green; RE-MEASURE psynch amplification
  (`scripts/dtrace/syscall-amplification.d`) — require the psynch share to
  collapse; RE-MEASURE untraced wall/CPU on the same 1M-trap command (authority)
  — require improvement, no regression.

### Phase 3 — Extract module + lock-free immutable config
Extract `NativeMappedMemory` and its lock architecture into a focused module
out of the 15k-line `native_darwin.rs` (approved: file restructuring for
traversal). Factor the immutable config to truly lock-free reads. Cleanup and
durability; no behavior change beyond Phase 2.
- Gate: `just ci` green; no measurable regression vs Phase 2.

## Deferred alternative (documented, not chosen)

Fully lock-free hot path via seqlock/RCU immutable snapshots swapped on each
mmap. Deferred: parking_lot `RwLock` reads are cheap uncontended atomics that
do not block each other, and rebuilding an immutable snapshot on every mmap is
a real cost. Revisit only if Phase 2 measurement shows residual RwLock read
overhead worth removing.

## Risks and mitigations

- **Misclassifying a writer as a reader = guest memory corruption.** Mitigation:
  the classification map is complete and file:line-anchored; Phase 2 changes are
  driven by it, and the fusion/atomic stress gate + probe suite run ≥10x.
- **RwLock writer starvation** under heavy mmap churn. Mitigation: writers are a
  measured small minority; parking_lot RwLock is fair enough; measure Phase 2
  and shard further only if writer latency shows up.
- **`upgradable_read` deadlock** if two threads try to upgrade the same lock.
  parking_lot allows only one upgradable-read holder at a time, so this is
  safe; the SMC path is rare and the escalation is local.
- **Non-regression discipline:** untraced signed runs are the only wall/CPU
  authority; measure before/after each phase on the frozen command; never raise
  timeouts/max_traps or weaken AArch64 exclusive/signal semantics.
