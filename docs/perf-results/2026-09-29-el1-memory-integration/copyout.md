# Prepared host copyout through EL1 descriptor publication

Development slice on base `cb285ae30`; not checkpoint acceptance.
Applicable contracts: `kernel.el1.stage1-publication` and
`kernel.el1.anonymous-first-touch`.

`Aarch64EngineCore::commit_prepared_host_write` now routes the guest-owned
lane through `KernelFrameCowAuthority::commit_guest_host_first_touch`.
The kernel retains exact-MM exclusion, plans without consuming first-touch
arming, and commits residency only after an authenticated Publish/Write
receipt names the exact MM and one-page span. The existing revision check
rejects changed arming. The host-owned venue remains available for lanes
whose writer conversion is unfinished.

Fork and copyout share the descriptor-drain implementation, moved unchanged
from runtime into carrick-aarch64. Copyout submits one page at a time through
that executor; permissions and expected backing are checked before mutation.
No new executor, tracing system, retry or larger wait budget was introduced.

## Verification

- Retained red: `prepared_copyout_publishes_only_its_page_through_the_guest_executor`
  failed on the unconnected publication stub, then passed with the real
  transaction planner/executor. This is model execution, not a signed VM.
- Runtime `guest_descriptor_lane_tests`: 11 passed, including wrong-root,
  wrong-backing, blocked-editor and read-only refusal with unchanged leaf and
  empty transaction slots, plus shared fork-drain regressions.
- Kernel `first_touch`: 15 passed, including exact receipt commit, rejection
  of wrong MM/page/read-only receipts, refusal preserving arming and no second
  publication after residency commits. Kernel receipt inputs are modeled;
  the runtime test independently exercises real descriptor mutation.
- Clippy for aarch64/kernel/runtime, all targets, `-D warnings`: passed.
- Formatting and source diff check passed. Raw logs retained beside this file.

## Acceptance limits and next production dependency

Guest descriptor admission remains disabled (`host_copyout=false`,
`backend_writers=false`). The copyout adapter is connected in source but not
observed in production execution. Keep admission closed until the complete
writer conversion and connected signed witness. This slice does not remove
host exclusion, activate anonymous reservation policy or accept checkpoint 2.
Full CI, inventories, signed migration and controlled costs remain open at the
connected integration boundary. Do not rerun ordinary boot to label this path
live.

The next implementation must connect the real backend writers, not extend
helper coverage. Source inspection identifies these remaining families:

- `HvfVmState::perform_frame_cow`: existing guest backing/continuation gates
  have no production caller; `CowCopyWindow` has no hardware implementation.
  Join allocation and retained old/new owners to guest copy, repoint receipt
  and final inventory commit.
- Private/shared repoints, replacement frame grants and retired reuse in
  `trap/cow_engine.rs` explicitly call `require_host_cow_lane`; their lifetime
  transactions must complete through the same descriptor authority.
- Engine protection, discard/unmap, alias/file mappings and exec publication
  still enter the host live-edit funnel. Preserve file/shared mappings while
  converting writers; merely flipping backend admission would break them.

This is an initial caller review, not the completed writer census. Anonymous
policy/lifecycle must also join SharedReservations before enabling the path.
