# EL1 shared stage-1 editor and live-image adoption

This VM-free checkpoint establishes the first production boundary of
`kernel.el1.stage1-publication`: guest EL1 and the host cannot edit the same
live stage-1 image concurrently, and a manager adopting live hardware backing
does not reissue an occupied table page.

The red-first source base was
`4161a8a58988619c0c1dbb6208ae5726799cda6a`. `guest-editor-red.log` records the
missing exact-editor and host-drain API. `live-cursor-red.log` records
`PageTableManager::new_live` resetting its cursor to 32 KiB even though the
live image's last occupied spare page required a 48 KiB cursor.

The corrected shared entry contains one exact nonzero editor token. Guest EL1
claims it and then rechecks the MM gate with SeqCst ordering. A host pause or
retirement raises/closes the gate first and waits for the token to clear.
Thus either the host sees the admitted editor or the guest sees the gate and
releases without mutation. The production `PtQuiesce` mirror and address-space
retirement path use this drain. Live manager construction scans the
hardware-visible primary arena and starts allocation after the last occupied
spare page.

Focused and broad VM-free evidence is retained here:

- `sched-core-green.log`: all 45 scheduler-core tests pass, including exclusive
  editor ownership and the deterministic gate-before-drain witness;
- `kernel-pause-green.log`: the production MM fence waits for the exact guest
  editor;
- `mmu-core-green.log`: all 94 MMU-core tests pass, including live cursor
  discovery;
- `contract-check-green.log`: 62 contracts, 15 claims and 140 surfaces validate;
- `clippy-green.log`: warning-denied Clippy passes for scheduler-core,
  MMU-core and kernel across all targets and features.

This checkpoint does not grant frames, expose a valid stage-1 leaf, service an
EL0 fault in guest EL1, or improve the signed first-touch slope. Stage-2 owner
and inventory readiness before leaf publication, rollback, frame return,
signed execution and the `<0.125` host-exit/page gate remain open in the same
contract.
