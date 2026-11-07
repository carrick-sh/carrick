# Owner-admitted code reservations (#1791)

The signed check on PR #1797 still fails on an **in-arena**, whole-range
256 MiB RWX transition at `0x6020000000`. The earlier outside-arena hint
correction does not establish the cause of that failure. Unhinted/subrange
controls alone cannot close this issue.

Linux mmap(2) treats the requested address as an advisory placement hint;
Carrick honours free usable hints outside its allocation arena. A hinted reservation
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

`serial_host_delegated_outside_hint_native_store_survives_protection` adds a
Linux native physical venue to production host mmap/mprotect dispatch. It
reserves actual host pages with MAP_FIXED_NOREPLACE at the free outside-arena
hint, with an unhinted arena control. Under the admitted MM root, it changes
an interior range to R, RW, RWX and back to RW. The owner publication callback
applies libc mprotect to those pages; legacy nonzero protection publication
fails the test.
Volatile stores and reads at both ends of each writable range then exercise
the actual returned address, rather than a byte-copy backend or a separately
allocated frame. Host VA equals guest VA only by explicit fixture placement;
this does not change production VA/IPA lookup or establish VMM supply.

## Whole-range continuation

`delegated_whole_code_range_keeps_owner_protection` calls production host
mmap then mprotect at `0x6020000000`, with a 256 MiB PROT_NONE reservation,
MAP_PRIVATE | MAP_ANONYMOUS | MAP_NORESERVE, and the entire range becoming
RWX without a preceding fault. It requires one owner publication, zero legacy
protection calls, and no backing allocation. It passes on the rebased #1797
implementation **before any continuation fix**. This is a control, not red
proof of the reported failure.

`serial_host_delegated_whole_code_range_writes_and_executes` applies the same
whole-range transition to actual Linux native pages through the production
host dispatcher. It verifies stores at both ends and, on x86_64, writes and
executes `mov eax, 42; ret` in the returned range. Host instruction execution
checks the test venue, not an ARM or x86 guest or VMM transaction.

V8 13.6.233's BSD-licensed `src/heap/code-range.cc` (InitReservation) changes
the allocatable range to RWX before discarding its pages; its
`src/base/platform/platform-posix.cc` uses MAP_NORESERVE for inaccessible
anonymous reservations. Sources:
https://github.com/v8/v8/blob/13.6.233/src/heap/code-range.cc
https://github.com/v8/v8/blob/13.6.233/src/base/platform/platform-posix.cc
The signed failure still needs its preceding syscall sequence and exact
artifact provenance to distinguish owner admission, opaque mapping history,
and the forwarding venue from this passing control. Do not remove the sparse
publication refusal or select owner publication without authenticated ownership.
