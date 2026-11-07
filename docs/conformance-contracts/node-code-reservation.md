# Owner-admitted code reservations (#1791)

The anonymous reservation and permission contracts require MAP_NORESERVE to
preserve the admitted MM's ownership. Linux mmap(2) defines it as a swap
reservation hint; it does not change anonymous mapping or mprotect semantics.
The shared decoder previously forwarded that hint. V8 uses it for its
PROT_NONE code range, whose later protection change must stay with the owner
rather than entering legacy host sparse publication. The ownership guard and
stage-1/stage-2/frame-inventory transaction are unchanged.

`two_isa_noreserve_code_range_stays_owner_admitted` proves the shared decoder
and owner transaction through both call views, with one backing probe per
operation and zero allocation or descriptor edits for untouched pages.
`native_owner_noreserve_code_range_writes_and_executes` adds real native process
admission and the full Linux dispatch pipeline on a Linux x86_64 host. Its
physical venue uses live AArch64 descriptor transactions. It reserves 256 MiB,
grants RWX to an interior range, checks the exact three protection rows, and
then supplies one physical page through the descriptor executor. Resident RW
and RWX changes must also complete through the owner. It verifies output
identity and descriptor write/execute permissions before writing and executing
a small function in the host allocation representing that supplied frame.

The latter execution checks the fixture's physical backing and generated
bytes. It does not execute an AArch64 guest on an x86 host, emulate hardware
permission enforcement, or prove the VMM supply transaction. The signed Mac
must still run `node24 -e 'console.log(process.version)'` and print `v24…` on
the exact head. The VM-free witnesses cannot close that ecosystem acceptance.
