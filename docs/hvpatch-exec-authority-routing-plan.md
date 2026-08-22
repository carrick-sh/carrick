# Routing execve through the task inventory authority

## The defect, verified

A forked child that execs and exits abandons its frame-inventory rows. The
kernel object graph is then internally inconsistent and `carrick debug
hvpatch-kernel` refuses on any such guest:

    kernel snapshot invariant violated:
    mapping MappingId(78) names mm MmId(55), which is not in the snapshot

Reducer, deterministic:

    carrick run ubuntu:24.04 --raw --fs host /bin/sh -c '/bin/true; sleep 12'
    # while it sleeps, in another shell:
    carrick debug hvpatch-kernel --run-id <RID> --table mapping

Three variants isolate the trigger:

| reducer | result |
|---|---|
| `exec /bin/sleep 12` — exec, no fork | snapshot OK |
| `( : ) ; sleep 12` — fork+exit, no exec | a DIFFERENT clause (see "Out of scope") |
| `/bin/true; sleep 12` — fork+exec+exit | the dangling mm above |

## The chain

1. `sh` forks a child that shares its parent's kernel mm. At publication the
   child's `mm_key` matches the parent's, so
   `HvpatchCarrierTaskStateDirectory::publish` takes the `existing_task_mm`
   branch (`trap.rs:8241`): the child's freshly prepared authority is
   `abort()`ed and the child's registration adopts **the parent's
   `Arc<HvpatchTaskMmAuthority>`**, whose inventory phase is `SharedProcess`.
   Correct at that moment — the ledger really is the parent's.
2. The child calls `execve`. `HvfTaskState::begin_exec_inventory`
   (`trap.rs:5163`) sees `shared_process_mm` and installs a **brand-new empty
   ledger** so the child cannot remove the parent's mappings. The replacement
   commit publishes 18 mappings into it under the child's new `MmId`. Live
   evidence: `old_mm=MmId(1) replacement_mm=MmId(55) old_extent_count=0
   retires_old_mm=false`.
3. `execve_into` mutates the HVF state in place and sets
   `shared_process_mm = false` (`trap.rs:17328`). **Nothing re-publishes the
   task**, so its registration still points at the parent's `SharedProcess`
   authority under the OLD `mm_key`.
4. The child exits. `retire_detached_address_space_with` asks
   `shares_another_process_inventory()`, gets `true` from the stale authority,
   and skips the retirement — logged once as `detached retirement skipped: task
   shares another process's inventory`.
5. The child's kernel `Mm` drops. Its 18 rows remain in the ledger, naming an mm
   that no longer exists.

Exec also bypasses the authority's state machine entirely: it applies its
replacement commit straight to the kernel ledger via `apply_exec_inventory`
(`vcpu_loop/exec.rs:49`) using `.apply(mm, commit)`, which returns no receipt —
where the fork path uses `apply_process_inventory` and authenticates a receipt
against a challenge.

## This one change fixes THREE audited defects, not one

A directed read-only audit of the carrier/task state machines returned five
candidates; I verified each. Three are the same root cause — **execve mutates
the task's HVF state in place and never re-publishes it** — and all three fall
out of the fix below:

1. `HvpatchTaskInventoryAuthority::SharedProcess` survives exec (the defect
   above).
2. **`HvpatchTaskMmAuthority.kernel_mm` is SET-ONCE.** `bind_kernel_mm`
   (`trap.rs`) returns `Ok` only for `None` or the identical mm, and errors with
   "HVPatch MM binding changed across sibling registrations" otherwise. After
   exec the task has a NEW `MmId`, so the adopted authority can never be
   re-bound to it — and `apply_retirement` passes `*self.kernel_mm.lock()` as
   `expected_mm`, so a retirement would authenticate its receipt against the
   PRE-exec mm. **This is independent proof that transitioning the existing
   authority in place is not merely dangerous but impossible.**
3. The `HvpatchMmAuthorityKey` entry in the carrier directory still maps the
   pre-exec `mm_root_slot`. After exec assigns a replacement slot, a later
   `CLONE_THREAD` spawn looks the NEW key up, misses, and creates a second
   authority for one address space.

Two further candidates were checked and are NOT to be acted on here:

- "`Active { ledger }` holds the pre-exec ledger after exec" — **refuted**.
  `self.frame_inventory` is reassigned only at `trap.rs:5170`, inside the
  `if self.shared_process_mm` branch; a non-shared task keeps the same ledger
  `Arc` and the variant stays correct.
- "a `CLONE_THREAD` sibling adopts an already-`Active` authority" — that is the
  design: threads share the mm and therefore its authority. Needs a named
  guest-visible consequence before anyone touches it.

## THE HAZARD THAT RULES OUT THE OBVIOUS FIX

**Do not transition the existing authority in place.** For a vfork child,
`registration.task_mm` is the *same `Arc`* as the parent's
(`trap.rs:8241`, `HvpatchTaskRegistration.task_mm:
Option<Arc<HvpatchTaskMmAuthority>>`). Mutating it to `ProcessPrepared` over the
child's new ledger would silently redirect **the parent's** authority at the
child's ledger and destroy the parent's address space at its own teardown.

The child must end up owning a **new, separate** `HvpatchTaskMmAuthority`.

## The required end state

After a `shared_process_mm` task execs, its registration must hold its own
authority, driven through the same sequence the fork path uses
(`vcpu_loop/quiesce.rs:1229`):

    ProcessPrepared { ledger: <the fresh ledger>, staged, commit, challenge }
      -> apply_process_inventory(apply, expected_mm)  -> InventoryPublished
      -> activate(&[])                                -> Active

`apply_process_inventory` (`trap.rs`) requires an `apply` returning a
`FrameInventoryApplyReceipt` and authenticates it with the challenge against
`expected_mm`; the fork path's template for constructing `ProcessPrepared` with
`staged`/`commit`/`challenge` is the child materialization near `trap.rs:16565`.

Two consequences fall out and are wanted:

- `shares_another_process_inventory()` becomes false for the post-exec child, so
  its terminal retires its own ledger and the rows are unmapped.
- The exec replacement gains an authenticated receipt, matching fork.

The old `mm_key` association must not be left pointing at the child, and the
parent's authority must be observably untouched.

## Verification — all of it, in order

1. `just fmt && cargo check --workspace --all-targets` — exit 0.
2. `RUST_TEST_THREADS=1 cargo test -p carrick-runtime --lib` — `0 failed`
   (1605 today) and `cargo test -p carrick-vmm-hvf --lib` — `0 failed`
   (225 today).
3. `just build` (required: a bare `cargo build` strips the hypervisor
   entitlement and the guest dies with `HV_DENIED`).
4. **The reducer must go from refusing to succeeding.** Run the fork+exec+exit
   reducer above and query the snapshot while it sleeps; before the change it
   prints the invariant violation, after it must print JSON.
5. The parent must be unharmed: the reducer must still exit 0, ten times.
6. No regression on the fork probes. For each of `forkcow`, `cloneexitsig`,
   `waitidsiuid`, `xthreadsig`, `sigchld`:
   `CARRICK_RUN_ID=$RID timeout 25 ./target/release/carrick run-elf --raw
   --exec-backend hvpatch conformance-probes/target/aarch64-unknown-linux-musl/release/<p>`
   must exit 0, and reap each with `./scripts/sudo/kill.sh $RID`.

Red-first is required by `AGENTS.md`: capture the invariant violation on the
unmodified binary first, and quote both before and after.

## Out of scope — do not fix these here

- The `( : ) ; sleep 12` reducer exposes a **different** clause: `mapping
  MappingId(90) length FrameLength(8372224) disagrees with frame FrameId(22)
  length FrameLength(8388608)` — exactly one 16 KiB page. That is likely
  `stage_cow_inventory_split` reusing `old.frame` for partial-length fragments
  while the invariant demands equal lengths, and it may be the INVARIANT that is
  wrong rather than the data. Separate decision, separate change.
- Core dumps (`docs/hvpatch-core-dump-port-plan.md`) and job control
  (`docs/hvpatch-job-control-port-plan.md`).
