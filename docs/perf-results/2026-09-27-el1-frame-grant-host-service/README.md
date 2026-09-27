# EL1 frame-grant host service

This VM-free checkpoint joins the existing forwarded-fault boundary to real
HVF stage-2 preparation and the authenticated kernel frame inventory. The
source base is `ce1c23b4e`.

The runtime claims only a request matching the current MM, fault address and
access class. It clips the request through the kernel's same-protection bulk
planner, then asks the active VMM to prepare the grant. HVF quiesces the exact
MM, creates zeroed anonymous stage-2 backing, stages its backend inventory row,
applies and authenticates the kernel receipt and owner generation, and retains
the live alias. The runtime publishes mailbox `Ready` only after those steps
and commits residency for the complete semantic span. A backend refusal is
published to the guest before the ordinary host fallback may resume.

Evidence retained here:

- `claim-red.log` and `claim-green.log`: the runtime did not have, then gained,
  an exact current-MM/fault/access request claim;
- `backend-request-red.log` and `backend-request-green.log`: the backend did
  not have, then gained, exact coherent-MM/span validation;
- `read-permission-red.log` and `read-permission-green.log`: a write-only Linux
  mapping initially rejected the read access that the current AArch64 lowering
  permits; the mailbox now matches the established first-touch rule;
- `abi-green.log`, `runtime-first-touch-green.log`, `hvf-sparse-green.log` and
  `aarch64-green.log`: focused ABI, runtime, HVF and AArch64 tests pass;
- `clippy.log`: warning-denied Clippy passes across the changed product crates;
- `contract-green.log`: 62 contracts, 15 claims and 143 registered surfaces
  validate after adding the production host-service paths;
- `inventory-drift-green.log`: the generated 338-syscall inventory remains
  current;
- `hvf-lib-first-run-red.log`: an invalid parallel validation run produced two
  process-global inventory lifecycle failures plus one unrelated GIC
  source-shape failure;
- `hvf-lib-green.log`: 571 HVF library tests pass serially, with three existing
  ignored tests and only the unchanged inherited GIC source-shape assertion
  filtered out. The two
  inventory failures from the parallel run pass in this isolated suite. The
  excluded assertion already fails on `ce1c23b4e`: its expected call omits the
  custody and VM-generation arguments present in unchanged `trap.rs` source.

This checkpoint does not install a guest stage-1 leaf or improve the signed
three-scale first-touch slope, which remains about 0.9954 host exits per page
against the `<0.125` target. Guest EL1 must publish a request, consume the exact
response, reauthenticate the live MM editor, install the existing invalid
leaves and acknowledge success or rollback. That is the next impact-bearing
step; this host service remains dormant until it exists.
