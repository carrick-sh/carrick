# Design: Go bring-up follow-ups

Date: 2026-05-23
Status: approved (diagnosed this session), pending implementation plans

## Context

Branch `fix/epoll-kqueue-backed` brought a real multithreaded Go HTTP program up
on carrick: single-request demo is 100% reliable and concurrent (c≤10) runs at
~33k req/s, 10/10 clean. Shipped fixes: epoll instance = persistent kqueue
(snapshot-race wakeup loss), `carrick trace` outlives children, 32 GiB lazy mmap
arena + out-of-window-reservation relocation (Go heap arenas), `epoll_pwait`
sigmask applied during the wait, env forwarding for `GODEBUG`. See
`project_go_bringup` memory.

This spec captures the **remaining** follow-ups, each with the concrete
diagnostic evidence gathered, the proposed approach, scope/risk, and how to
verify. They are independent subsystems and get separate implementation plans.

Priority order (value × tractability): (1) ppoll/pselect6 sigmask, (2) mmap
arena reclaim, (3) guest-memory on-demand mapping redesign, (4) c≥20 vCPU EL0
fault, (5) epoll_wait03 EFAULT, (6) epoll_ctl05 ELOOP.

---

## 1. ppoll / pselect6 sigmask (ppoll DONE; pselect6 needs a refactor)

> UPDATE (executed): **ppoll DONE** (commit on branch) — read arg3/arg4 sigmask
> → `WaitOnFds.block_signals`; `ppollsig` probe MATCHES Docker. **pselect6 is
> NOT done and needs more than the plan assumed:** it does NOT emit `WaitOnFds`
> — it blocks DIRECTLY in `libc::poll(timeout_ms)` while holding the dispatcher
> lock, so its `libc::poll` gets host-signal EINTR and returns EINTR. The right
> fix routes pselect6's host-fd wait through `WaitOnFds` (so `block_signals`
> applies AND it stops starving siblings under the lock), or wraps the poll in a
> host `pthread_sigmask` of the host-translated mask. Its own follow-up.



**Problem.** `epoll_pwait` now applies its sigmask during the wait (a blocked
signal stays pending instead of EINTR-ing the wait — commit `0473901`), but
`ppoll(2)` and `pselect6(2)` carry the SAME sigmask argument and still ignore
it. Their `WaitOnFds` is emitted with `block_signals: 0`. LTP `ppoll01` fails 4
assertions (verified PRE-EXISTING by stashing — not caused by the epoll work).

**Approach.** The plumbing already exists: `DispatchOutcome::WaitOnFds` has a
`block_signals: u64` field, the runtime passes it to `ThreadWaiter::wait`, and
`host_signal::has_unblocked_pending_for(tid, block_mask)` honours it. So this is
the same one-shot move as `epoll_pwait`: in `ppoll` and `pselect6`, read the
sigmask pointer/size (validate like epoll_pwait: `sigsetsize ==
LINUX_RT_SIGSET_SIZE`, readable → else EINVAL/EFAULT), decode 8 LE bytes into a
`u64`, and pass it as `block_signals` on the emitted `WaitOnFds` instead of `0`.

**Scope/risk.** Low. `block_signals == 0` is byte-identical to today, so only the
sigmask-present path changes. Mirrors a landed, tested pattern.

**Verify.** New `ppollsig` conformance probe (mirror `epollpwait`'s
`sigmask_blocks`: child raises a masked signal while parent blocks in
`ppoll`/`pselect`, fd made ready later → must return 1, not EINTR). LTP
`ppoll01`, `pselect01`/`03` should improve/MATCH (mind the Docker-jitter
inversions on pselect01). `cargo test --lib`, conformance probes stay green.

Plan: `docs/superpowers/plans/2026-05-23-ppoll-pselect6-sigmask.md`.

---

## 2. mmap arena reclaim (PLAN-READY)

**Problem.** `next_mmap_address` (`src/dispatch/mem.rs`) is a pure bump allocator
(`mmap_next` only increases); `munmap` of a private/anonymous mapping is a no-op
that never reclaims arena address space. The 32 GiB arena absorbs the Go startup
burst, but a long-running process that churns mappings (repeated
mmap/munmap — thread stacks, transient buffers) will monotonically consume the
arena and eventually ENOMEM. This is the "durably" gap.

**Key enabler.** The arena is FLAT stage-2-mapped (one `hv_vm_map` over
`[LINUX_MMAP_BASE, +LINUX_MMAP_SIZE)`, lazily demand-zeroed by HVF). So reclaim
needs NO stage-2 teardown — a freed range is still mapped; reuse just needs the
bytes zeroed (anonymous-mmap contract) before handing them back.

**Approach.** Add a coalesced free-list to `MemState`:
`free_regions: Vec<(u64, u64)>` (addr, len), all within the arena.
- `munmap(addr, len)` (private/anon, in-arena): clamp to the arena, insert into
  `free_regions`, coalescing adjacent/overlapping ranges. If the freed range
  abuts the top (`addr + len == mmap_next`), lower `mmap_next` and absorb any
  free region now at the new top (cheap LIFO reclaim).
- `next_mmap_address` (non-FIXED, non-hint bump path): first-fit scan of
  `free_regions` for a region `>= length`; split it, ZERO the returned range
  (via a new `GuestMemory::zero_range` or `write_bytes` of zeros), and return it.
  Fall back to bumping `mmap_next` when no free region fits.

**Scope/risk.** Medium. Allocator-local (one file). Risks: (a) must zero reused
ranges or the guest sees stale data (correctness/security); (b) coalescing
correctness; (c) MAP_FIXED and shared-file maps must stay on their existing
paths (don't add their ranges to the free-list). The flat mapping means no HVF
calls, which removes the hardest class of bugs.

**Verify.** New `mmaprecl` probe: loop mmap(64 MiB anon)+touch+munmap many more
times than `LINUX_MMAP_SIZE/64MiB`; assert all succeed and a post-reuse mapping
reads back zero (proves reclaim + zeroing). MATCH Docker. `cargo test --lib`
(add unit tests for coalescing + top-reclaim), conformance, Go fixture stay
green; re-run `carrick run-elf … -benchmark -c 10` to confirm no perf
regression.

Plan: `docs/superpowers/plans/2026-05-23-mmap-arena-reclaim.md`.

---

## 3. Guest-memory on-demand mapping redesign (DESIGN — needs its own plan)

**Problem.** carrick pre-maps fixed VA windows (heap 256 GiB/128 MiB, mmap
384 GiB/32 GiB, shared-file 576 GiB/2 GiB) inside page-table/IPA coverage of
only 0–1 TiB. A real Linux process reserves address space anywhere in its
~128 TiB. Go's heap allocator probes PROT_NONE reservation hints at 256 GiB →
1.5+ TiB (observed: `addr=0x4000000000, 0x14000000000, … step 1 TiB`, len 64 MiB,
prot 0, flags MAP_PRIVATE|ANON). We currently RELOCATE the first such hint into
the arena (commit `548ce70`) which works for c≤10, but at c≥20 Go issues so many
hint probes that it stalls, and the fixed-window strategy is fundamentally a
mismatch (the `LINUX_MMAP_SIZE` magic number is the wrong axis).

**Target design (endorsed).** Stop pre-mapping fixed windows; map guest pages
**on demand** on an HVF stage-2 fault, anywhere in a much larger IPA space.
Research (QEMU `accel/hvf`, `hvf_set_map_granule` + configurable IPA; QEMU
`ipa-granule={auto,4k,16k}`): Apple Silicon HVF stage-2 supports a 4K granule
regardless of the 16K host page size, IPA size is enlargeable on macOS 15+, and
macOS 26 adds a public granule API. Default `auto` = host granule (16K).

Open design questions for the dedicated spec/plan:
- Fault-driven mapping: trap stage-2 data aborts (carrick already decodes ESR);
  on a fault in a guest-reserved region, `hv_vm_map` a fresh demand-zero 16K
  (or 4K) page at the faulting IPA. Bookkeeping of reserved-but-unmapped ranges.
- IPA sizing: how large can we make it on the target macOS, and how to detect
  the cap; widen page-table coverage (currently 1 TiB) to match.
- Granule choice: 16K (current, simplest) vs 4K (finer, matches guest 4K pages,
  needs the configurable-granule path / macOS-version gate).
- Interaction with the bump allocator + reclaim (§2): on-demand mapping may
  subsume the fixed arena entirely, or coexist (arena for small/hot allocs).
- fork coherence (the flat MAP_SHARED-anon path for cross-process futex must
  survive), and the `mprotect`/PROT_NONE-as-fault-arg model.

**Scope/risk.** High / multi-day. Touches `src/memory.rs`, `src/trap.rs`
(fault handling), `src/dispatch/mem.rs`. Needs its own design spec + plan; start
by prototyping IPA-size detection and a single on-demand page-fault map behind a
flag, measured against the Go benchmark at c≥20.

---

## 4. c≥20 intermittent vCPU EL0 fault (INVESTIGATION — needs root cause)

**Problem.** At very high concurrency (c≥20) a sibling vCPU occasionally dies:
`thread sibling vCPU loop failed … EL0 fault not handled by trap path:
esr=0x2000000 elr=0x614800bfd0 far=0x0`. Decoded: ESR EC=0 ("unknown reason"),
IL=1; the faulting PC `0x6148…` is INSIDE the mmap arena (≈389 GiB) — i.e. a
guest thread executed an instruction in a data/stack region and took an
undefined synchronous exception. Intermittent: a retry completes at ~22k req/s,
so c=20 is ~7/8 OK. Not the mmap-reservation issue (that's fixed).

**Code-level findings (this session's read).** A sibling vCPU is built by
`spawn_clone_thread` (runtime.rs) → `build_thread_spec` (trap.rs:541) →
`from_thread_spec` (trap.rs:1756). `build_thread_spec` captures, ON THE CLONING
THREAD: (a) a `snapshot_vcpu()` of the parent vCPU's registers, then
`seed_child_snapshot(parent, stack, tls)` to set the child's PC (=clone return,
in ELF text), SP (=clone stack), TLS, x0=0; (b) a COPY of `self.mappings`
(the cloning engine's HVF region list); (c) an `Arc::clone` of `protections`.
`from_thread_spec` then `vcpu_create`s and best-effort re-maps the snapshot
regions into the SHARED `hv_vm` (already-mapped → benign HV_ERROR/HV_BAD_ARG).
Since the fault PC is in the mmap ARENA (not ELF text), the sibling did NOT start
at a wrong entry PC — it ran from the correct entry and later transferred into
the arena (a goroutine stack/return-address corruption, or a stack mapped in a
region the sibling's snapshot/protections didn't cover).

**Hypotheses to test (investigation, not yet a fix).**
- The cloning thread's `self.mappings` copy is a per-engine list; under many
  concurrent clones + concurrent mmap (which grows the arena / adds regions on
  some engine), a sibling's snapshot mapping/protection set may be STALE relative
  to where Go then places that sibling's goroutine stack → a stack access or
  return lands in an arena page the sibling's `protections` marks no-access (or
  unmapped in its bookkeeping) → garbage fetch / EC=0. Check whether goroutine
  stacks for the new M live in arena regions added after the snapshot.
- Concurrency race in per-thread vCPU bring-up: a thread starts executing before
  its stack/TLS or shared stage-1 mapping is fully established → fetches garbage.
- The reservation-relocation (`548fce`/§3): confirm Go always uses the RETURNED
  mmap address for later MAP_FIXED commits (it should); a mismatch would leave a
  goroutine stack pointing at an uncommitted/relocated arena address.
- A corrupted return address / function pointer pointing into the arena (guest
  stack smash under load), possibly aggravated by the reservation-relocation if
  Go commits at an address it didn't expect (verify Go always uses the returned
  mmap address — it should).
- HVF vCPU count / resource pressure at ~20+ vCPUs.

**Approach.** Reduce to a probe that spawns N (≥20) threads each doing the Go
I/O shape, under `carrick trace` (now child-outliving) capturing the faulting
thread's setup syscalls + the `fork-post`/clone + the ESR/ELR. Compare the
faulting thread's stage-1/TLS/stack setup against a healthy sibling. Bisect the
relocation change (§3 / `548ce70`) by reverting just the relocation to see if
the fault rate changes. Only then design the fix.

**Scope/risk.** Unknown until root-caused. Heisenbug (tracing perturbs it — use
the lightest targeted script + many runs).

---

## 5. epoll_wait03: EFAULT on a read-only events buffer (DESIGN — niche)

**Problem.** LTP `epoll_wait03` maps the `events` output buffer `PROT_READ` and
expects `epoll_wait` to return EFAULT when it copies a ready event out. carrick
writes guest RAM directly (`write_kernel_struct_raw`), bypassing the guest's
mmap PROT, so the write "succeeds" → returns 1 instead of EFAULT. Pre-existing
(verified by stashing); fails identically with/without the epoll rewrite.

**Approach.** carrick models PROT_NONE for fault-on-syscall-arg via
`set_no_access` (read side). EFAULT-on-write needs a NEW dimension: track
write-protected (PROT_READ-only) guest ranges and have the copy-out path
(`write_kernel_struct_raw` / `GuestMemory::write_bytes`) reject writes to them
with an error the syscall maps to EFAULT. `mprotect`/`mmap` set/clear the
write-protect set.

**Scope/risk.** Medium-broad. Touches the guest-memory PROT model and EVERY
copy-out EFAULT path, not just epoll. Niche (read-only output buffers are rare
in real programs), not Go-relevant. Lower priority; do as part of, or after, the
§3 memory redesign which will revisit the PROT model anyway.

**Verify.** A probe mmapping a PROT_READ buffer and asserting epoll_wait (and a
couple of other copy-out syscalls) returns EFAULT; MATCH Docker. Re-run the full
LTP fs/mm/epoll sweep to catch over-enforcement regressions.

---

## 6. epoll_ctl05: ELOOP on nested-epoll loops (DESIGN — niche)

**Problem.** LTP `epoll_ctl05` builds a chain of epoll fds nested in each other
and expects `epoll_ctl(ADD)` to return ELOOP once the depth/cycle exceeds the
kernel limit (`EPOLL_MAX_DEPTH = 5`, plus self/cycle detection). carrick has no
nesting-loop detection — adding an epoll fd to another succeeds. Pre-existing.

**Approach.** In `epoll_ctl(ADD)`, when the target fd is itself an Epoll
description, walk the interest graph from the target to compute depth / detect a
cycle back to `epfd`; return ELOOP (or EINVAL for the self case, already handled)
when depth > 5 or a cycle is found. The interest map already records epoll→epoll
edges (in-memory interests).

**Scope/risk.** Low-medium, epoll-local. Niche (deeply nested epoll is rare; Go
doesn't do it). Low priority.

**Verify.** `epoll_ctl05` MATCH; `epoll_ctl0{1,2,3,4}` stay MATCH.

---

## Cross-cutting verification

Every plan re-runs, on a CLEAN system (kill stray `carrick`/test procs first —
contention produces phantom `context deadline exceeded` at c=10): `cargo test
--release --lib`, `cargo test --release --test conformance`, the relevant LTP
sweep via `.claude/skills/ltp-conformance/scripts/ltp-check.sh`, and the Go
fixture (`run-elf … carrick-linux-aarch64-go-hello` plain + `-benchmark -c 10`).
