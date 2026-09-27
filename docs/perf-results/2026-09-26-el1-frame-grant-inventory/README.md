# EL1 frame-grant inventory authority and bulk range

This VM-free checkpoint gives the host side of a future EL1 frame grant two
kernel-owned properties: an exact inventory/owner receipt with rollback before
leaf publication, and a same-protection bulk semantic range clipped to one
2 MiB window.

The source base is `cc3647b4a`. `inventory-red.log` records the missing exact
apply and rollback endpoints. `grant-range-red.log` records the missing bulk
resident-plan and whole-span commit endpoints.

The production `KernelFrameCowAuthority` now retains the canonical host owner,
applies the inventory transaction, checks the exact MM/mapping/frame/GPA/span
at the returned revision, and returns that independently chosen owner
generation. An unpublished grant can be rolled back only through the opaque
kernel receipt. The dispatcher plans no more than one 2 MiB window inside one
armed same-protection extent and commits residency for exactly that span under
the existing host-alias/MM mutation exclusion.

Evidence retained here:

- `inventory-green.log`: the exact receipt is live at its returned revision,
  carries the independent owner generation, and removes the mapping on
  unpublished rollback;
- `grant-range-green.log`: the plan is clipped to the VMA/bulk boundary,
  commits the complete span and leaves any outside prefix/suffix armed.
- `abi-green.log`: all 23 shared-ABI tests pass after separating guest access
  from host-authoritative permissions;
- `kernel-fault-green.log`: all 11 focused fault/first-touch tests pass;
- `clippy-green.log`: warning-denied Clippy passes for the four changed crates
  on the active platform;
- `contract-green.log`: 62 contracts, 15 claims and 142 surfaces validate;
- `contract-change-green.log`: the exact `cc3647b4a..3b1a110d4` product diff
  has stage-1-publication evidence, with a revision-bound exemption for the
  unchanged contracts that share the ABI, HAL and runtime source files;
- `inventory-drift-green.log`: the generated syscall inventory remains current.

`clippy-all-features-invalid.log` preserves one rejected invocation that
enabled mutually exclusive macOS, Linux and BSD runtime platform features at
once. Its duplicate platform definitions are an invocation error; the valid
active-platform command is the retained green receipt above.

This does not prepare real stage-2 backing, publish mailbox Ready, edit a guest
leaf or change the signed first-touch slope. The next implementation must join
real VMM preparation to this authority, with all expected failures preceding
Ready, then let EL1 consume and publish the grant.
