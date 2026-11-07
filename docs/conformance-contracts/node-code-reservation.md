# Owner-admitted code reservations (#1791)

The corrected signed classification is an outside-arena mmap hint, rather
than RWX or MAP_NORESERVE by itself. Unhinted reservations already work.
Linux mmap(2) requires a free usable hint to be honoured. A hinted reservation
must retain its MM owner through later R, RW and RWX protection changes,
without entering legacy host sparse publication. Untouched pages remain lazy.

The earlier MAP_NORESERVE decoder coverage remains a useful control: Linux
defines the flag as a swap reservation hint, without changing mapping ownership.

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

`delegated_outside_hint_keeps_owner_protection` drives production host
mmap/mprotect dispatch with a 256 MiB reservation at `0x7000000000` and an
unhinted control. It checks exact hint placement and owner publication for
protections 1, 3 and 7. Its backing is a test venue; it does not prove actual
guest stores, hardware permission enforcement or signed Node startup.

The host validates a free hint against user bounds, semantic and boot VMAs,
reserved apertures, the clock and Rosetta windows. Only then may it request
an external anonymous proposal from the exact MM owner. A carried provenance
bit distinguishes this placement from ordinary editable imports; generic
proposals cannot mint it. Subsequent protection, decommit and retirement
require complete coverage by owner-authorized nodes. Relocation into the
allocation arena drops the external placement bit. The node record layout
and the existing descriptor/backing completion transaction are unchanged.
