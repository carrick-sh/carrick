# EL1 authenticated frame-grant mailbox

This VM-free slice defines the carrier-wide single-flight transport needed
before a host can give guest EL1 anonymous backing. It does not prepare a host
mapping or install a guest stage-1 leaf.

The red-first source base was `0bb342858`. `mailbox-red.log` records that no
frame-grant request, ready receipt, exact-MM claim or authenticated authority
fields existed.

The shared ABI now binds every request and response to one nonzero MM key and
request generation. EL1 supplies only the read, write or execute access that
faulted; the host supplies authoritative VMA permissions. A successful
response must contain the fault within the requested span, permit the faulting
access, and name nonzero frame, mapping, stage-2 owner-generation and committed
inventory-revision identities. Wrong-MM and stale-generation participants
cannot claim the response; mismatched or unauthenticated host data cannot
become Ready. The 2 MiB target span permits one successful host boundary to
cover up to 512 Linux pages, subject to later host clamping at VMA, permission
and alignment boundaries.

Evidence in this directory:

- `mailbox-red.log`: expected compilation failure before the shared contract;
- `mailbox-green.log`: the two focused exact-identity and refusal tests pass;
- `abi-tests.log`: all 23 ABI tests pass;
- `el1-tests.log`: all 58 EL1 host tests pass;
- `abi-check.log` and `clippy.log`: the normal no_std compile and
  warning-denied ABI Clippy pass;
- `contract-check.log` and `inventory-check.log`: 62 contracts, 15 claims and
  140 surfaces validate, and the 338-syscall inventory has no drift.

Open work remains impact-bearing: the host must prepare and authenticate
stage-2 ownership and inventory before publishing Ready, roll both back on
refusal, and retain the grant until guest publication or cancellation. EL1
must reauthenticate the response, claim the exact MM editor, install the live
leaf with required visibility and TLB maintenance, and return unused frames.
The signed first-touch slope remains about 0.9954 host exits per page against
the `<0.125` target.
