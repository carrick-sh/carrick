# NativeLane Seam — Phase 3 (seam work) evidence

**Date:** 2026-07-24
**Branch:** `feat/native-lane-seam-phase3` (merge-base `7c3ea4af`)
**Scope of this doc:** the seam sub-deliverable (Tasks 0–4 + the futex-regression
deflake). NetBSD bring-up (Task 5) is deferred to Phase 4 — the host is ready, not
infra-blocked.

Read this alongside the design spec's **"Correction (2026-07-24): loop merge
SKIPPED"** block: the loop merge that this campaign was originally framed around did
not happen, and the metrics below are for the reshaped deliverable, not that merge.

## Metrics

### `native_freebsd.rs` shrink (the strangler target)

| point | file | lines |
|---|---|---|
| Phase-3 base | `crates/carrick-runtime/src/native_freebsd.rs` @ `7c3ea4af` | 16,595 |
| HEAD | `crates/carrick-runtime/src/native_freebsd.rs` @ `8c65d42d` | 15,784 |
| **delta** | | **−811 (−4.9%)** |

The moved orchestration/loader/futex bodies did not vanish — they relocated into
shared/lane crates (below). The −811 is net of the deflake test's re-wake loop
(`99e07d4b`, +30 lines of `#[cfg(test)]` code back into `native_freebsd.rs`), so the
gross extraction was larger; this is the honest at-HEAD line count.

### Where the code went

| crate / file | lines @ HEAD | what it is |
|---|---|---|
| `crates/carrick-dsr-x86/src/translator.rs` | 733 | the extracted x86 translate/cache/chain **engine** (`X86ThreadTranslator` + owned state + `translate()`) |
| `crates/carrick-native-freebsd/src/futex.rs` | 565 | FreeBSD cross-process futex ops (`shared_wait`/`shared_wake`/`shared_requeue` + waiter-count table), extracted for symmetry |
| `crates/carrick-dsr-aarch64/src/translator.rs` | 2,643 | the aarch64 engine the x86 extraction mirrors (unchanged reference point) |

## Honest key points

**(a) The loop merge was SKIPPED — Task 2 became the x86 ENGINE EXTRACTION.**
The Task-1 precision-map scout (`f902c26e`) found the two per-lane run loops share
only ~10% (100–180 of ~2,635 lines), and the divergence is danger-zone (fault
lowering, x86 XSAVE/XRSTOR vs aarch64 FP xstate), not thin-re-frontable — only 3
`GuestIsa` methods cleared the bar. The maintainer redirected Task 2 (`6a854b04`) to
extracting the x86 translate/cache/chain engine (`9dfcbc50` + `5d35725a`), which had
been inline in `native_freebsd.rs` while aarch64's equivalent already lived in
`carrick-dsr-aarch64::translator`. The result is a real `translate()` engine with
owned state mirroring aarch64's `ProcessTranslator` — **engine-level symmetry**.
Scope honesty: the symmetry is the translate/cache **engine** only. The cross-ISA
loop merge itself was NOT done; gateway-admission and xstate stay loop-resident and
lane-specific by design (the danger zones the scout flagged).

**(b) Task 3 was a category-error re-scope, and boot state is byte-identical.**
The planned "adopt exec-capsule + prepared_image" was a category error (verified:
`native_prepared_image`/`native_exec_capsule` are the Darwin execve self-reexec
transport, hard-gated `cfg(macos,aarch64)`; FreeBSD had 0 refs — no duplication to
remove). Re-scoped to adopting `carrick_mem::AddressSpace` for ELF parse/enumerate/
page-align, replacing FreeBSD's hand-rolled `map_one_elf` (`829617c3`, +92/−58). The
guest's initial stack/auxv/vDSO/vvar/PIE-base layout is **byte-identical** after
adoption (2 static fixtures matching SHA + empty formula-level diff; aarch64
untouched — only made an existing fn `pub`).

**(c) The futex work is an EXTRACTION for symmetry, NOT a shared abstraction.**
`3739c3f7` moved FreeBSD's `_umtx_op` + waiter-count table into
`carrick-native-freebsd::futex`, mirroring Darwin's already-extracted
`carrick-host::ulock` split. There is deliberately **no** shared cross-lane
`NativeHost` futex trait: with the loop merge skipped there is no shared caller to
name the operation, and Darwin is already factored behind `carrick_hal::PlatformFutex`
(which also backs the HVF runtime), so a unified static trait would regress it or add
a speculative arm only FreeBSD implements. The move is behavior-preserving (atomics,
orderings, `_umtx_op`, waiter table all verbatim; errno constants rebased
`crate::linux_abi` → `carrick_abi`).

**(d) The futex-heavy LTP "0 diffs" is NON-REGRESSION, not requeue correctness.**
The gate's futex-heavy set (15 cases incl. `FUTEX_CMP_REQUEUE`) showed zero per-case
diffs — meaning the extraction changed nothing, NOT that native futex requeue is
correct. `futex_cmp_requeue01` / `futex_wait02` / `futex_wake04` **pre-existing-fail
on the native lane both before and after** the extraction. That is a standing
futex-correctness worklist item (NetBSD-relevant), independent of this branch.

**(e) A real REGRESSION was caught by the empirical gate — and fixed test-side after
proof.** The Phase-3 gate (not the Task-4 review, nor the whole-branch review — both
of which MISSED it) caught
`native_freebsd::identity_raw_range_tests::unflagged_private_overlay_futex_does_not_cross_wake_but_shared_does`
regressing from 12/12 to ~10/12 on the futex-extraction commit. Root cause
(`99e07d4b`): the extraction turned `shared_wait`/`shared_wake`/`waiter_parked_count`
into non-inlined cross-crate calls in the non-LTO test build; that instruction-
scheduling shift widened the announce(`count.fetch_add` SeqCst)→enroll(`_umtx_op WAIT`)
window and exposed a **pre-existing test-only race**. It was fixed test-side (a
bounded `WNOHANG` re-wake loop; `futex.rs` production diff is EMPTY) only after
proving (i) the production futex body is byte-identical `282a0a9d`↔`3739c3f7`, and
(ii) real guests are immune — every `shared_wake` is guest-syscall-driven, the guest
advances the futex word before `FUTEX_WAKE`, so a late enroller re-checks
`*word != value` in-kernel, gets EAGAIN, and retries; the test wakes WITHOUT advancing
the word, a shape real guests never produce. **This is the evidence that an empirical
gate beats read-review for fork-shared-static relocation** — a process-global static
moved across a crate boundary behaves differently across fork, which neither review
pass could see.

**(f) What the Phase-3 seam work did NOT do (honest boundaries):**
- **Loop merge** — skipped (scout verdict; ~10% shared, danger-zone divergence). The
  cross-ISA thread-loop unification remains a follow-up.
- **NetBSD bring-up** — deferred to Phase 4. The host is READY (willow VM 201:
  NetBSD 10.1 amd64, rust 1.96.0 matching the pin, libclang present; host-crate build
  clean, zero netbsd cfg gaps), NOT infra-blocked.
- **`SharedFutexSyscall` unification** — deferred. The thin-seam justification in
  `3739c3f7` is partly wrong: `carrick_thread::platform_futex::SharedFutexSyscall`
  already serves bhyve (`BhyveSharedFutex`) and KVM (`KvmSharedFutex`) with requeue
  hooks, so the "speculative arm" claim is false. The landed code is fine; whether
  FreeBSD-native futex should unify onto `SharedFutexSyscall` is a Phase-4 evaluation
  (blocker: `carrick_host::umtx` has no requeue + a single mirror-word, not drop-in).

## Phase-4 carry-ins

From the seam whole-branch review (ledger, `.superpowers/sdd/progress.md`):

- **NetBSD/x86_64 native lane bring-up** — Phase 4's headline; host ready. NetBSD
  needs a `carrick-native-netbsd::futex` MIRROR of the FreeBSD module + lane dispatch
  for the 4 direct futex call sites (`native_freebsd.rs` 10767/10808/10843/10873) +
  the `FreebsdHost::` run-loop refs — there is NO `SYS___futex` trait slot (Task 4
  extracted FreeBSD-only). Study `carrick-vmm-nvmm/src/nvmm_futex.rs` (prior in-repo
  NetBSD futex art). Write the NetBSD plan against the LANDED shape, not spec §3/§4.
- **`SharedFutexSyscall` unification eval** (see (f) above).
- **`map_one_elf` class-validation** folded into `carrick-mem` (the `is_64` check
  restored on the direct-load path by `282a0a9d` belongs in the shared loader; guarded
  by the aarch64 pin).
- **PT_INTERP byte-exact fixture** before NetBSD reuses the shared loader (the dynamic/
  interp path is covered only by synthetic-ELF unit tests today, not the 2 byte-exact
  static fixtures).
- **`futex_cmp_requeue`-family pre-existing fails** — native-lane futex-correctness
  worklist; NetBSD inherits it.
- **`reset_after_fork_for_exec` cross-crate rename** (polish).

## Gate

- macOS: `just fmt-check` + `just clippy` clean; `cargo test -p carrick-dsr-x86 --lib`
  and `cargo test -p carrick-native-freebsd --lib` green. (The seam code is unchanged
  since the earlier full `just ci` green run; the docs commits cannot affect it.)
- FreeBSD box (`--no-default-features --features platform-freebsd`): full
  `native_freebsd_x86` suite green; the deflaked test 12/12; unfiltered `--lib` 777/5
  (the 5 are pre-existing environmental fails); LTP curated-25 == baseline.
