# EL1 COW copy aliases and guest descriptor execution

Development continuation from `a5ca5ed03`; no production COW acceptance.
Contract: `kernel.el1.stage1-publication`, with anonymous first-touch and
fork-COW ownership obligations retained.

The existing guest descriptor handler now performs the physical page copy
before applying a CowRepoint. It authenticates MM/root and preflights the
existing descriptor operation, temporarily maps the exact source and replacement
pages, copies 4096 bytes in EL1, revokes both aliases, then runs the existing
repoint executor and returns its existing receipt. There is no separate copy
RPC or completion channel. Host submission/backing ownership is still unjoined.

Layout reserves `[0x1A0000,0x1A2000)` inside the existing EL1 region, after
transaction records and before stacks; included in the ABI hash. Process-root
construction preallocates invalid kernel page leaves at those VAs. The MM's
single editor owns both temporary aliases. Source is kernel read-only,
destination kernel writable; both are nG and execute-never. No frame pool or
extra backing authority is introduced. Maintenance roots cannot use this path.

Alias setup preflights both idle leaves, revokes a partially installed window
on refusal and invalidates before returning. Failed revocation is Indeterminate
and the existing hardware handler's fatal path stops the MM. Host code must
retain both exact stage-2 owner pins until the receipt settles.

Evidence:
- Boot-layout test failed against the prior valid coarse kernel block and
  passes with preallocated invalid leaves; adjacent mappings stay present.
- A deliberate missing-revocation control failed the alias lifetime assertion;
  restored cleanup passes. This is a mutation control, not an old production
  regression. An initial over-specific filter selected zero tests and is
  preserved separately, not counted as evidence.
- Four window tests pass: permissions/lifetime, partial setup/busy refusal,
  failed revocation, and overlapping VAs in two roots within one modeled table
  store. The copy callback cannot run before both aliases are installed.
- Combined EL1/ABI/memory/MMU run: 114/56/176/155 pass. The subsequently added
  two-root test passes in the final four-test window run.
- Affected all-target Clippy passes; final MMU Clippy passes after the two-root
  test. EL1 image build passes (including its hardware softfloat compilation
  and FP/SIMD instruction gate). No signed execution performed for this slice.

Next: connect `HvfVmState::perform_frame_cow` allocation and staged inventory
transaction to this descriptor service while retaining old/new exact owners.
Preserve its 16 KiB physical compound versus 4 KiB semantic fragment rules,
private-file lane reuse, protections, cancellation and rollback. Do not split
one compound commit into independent page commits with an unsafe partial-failure
path. Retire superseded host-copy/guest-copy-helper paths as the real transaction
is joined. No more window scaffolding or broad boot campaigns are the next step.

This is the second prerequisite interval since the impact reset. The dependency
review justifies the next bounded integration step: there was no production
copy transport; there is now a compiled guest descriptor transport. Continuing
requires the real backing transaction, not further helper coverage. Overall
admission, reservation policy/lifecycle, remaining writers, host-pause removal,
signed proof, full gates and all later ARM64 checkpoints remain open.
