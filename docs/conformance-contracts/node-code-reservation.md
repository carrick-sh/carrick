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

`native_owner_whole_code_range_writes_and_executes` additionally repeats the
full native-process admission and Linux entry fixture with a whole-range
RWX commit, retaining the prior interior-range case. The native fixture uses
its own arena address; the host-dispatch controls above use the reported VA.
It checks one RWX reservation row before any first touch, then the existing
resident descriptor and generated host-code checks. This distinguishes the
native entry venue from production host dispatch without merging their
ownership or address domains.

## Continuation boundary

The Linux continuation reconfirmed that both whole-range host-dispatch
bindings above pass with the saved implementation. The native-pages venue
now returns `MemoryError::HostMap` with the reported sparse-publication
refusal if a nonzero protection edit enters its legacy callback. This lets
production `mprotect` handle the refusal instead of panicking inside the
fixture. Successful generated-code execution still requires the owner
callback to publish the actual native permissions.

The saved occupied-PIE-hint witness does reproduce the failure: after a
512 MiB cage reservation, an advisory hint into the occupied PIE image
relocates to `0x6020000000`, but the whole-range `mprotect` returns errno 12.
The native-pages venue returns the reported sparse-publication refusal.
The unhinted and free-arena-hint controls miss this placement history.

The root rejects an outside-layout hint with `ForeignMapping`. Previously
the host then relocated through an opaque host-served placeholder, losing
the anonymous owner's authority. A root-eligible anonymous mapping now
retries that rejected advisory hint as `Placement::Anywhere` through the
same owner. Free validated external hints keep their earlier path; fixed
placements and genuinely host-served mappings retain theirs. Protection
publication still requires an authenticated reservation proposal, and the
sparse refusal remains intact.
If the optional owner relocation cannot fit the allocation layout, its
original foreign-mapping result retains the existing high-alias gap search.
`x86_mmap_last_lower_half_gap_and_invalid_hint` guards that fallback; the
initial continuation fix returned errno 12 there before this correction.

`delegated_occupied_pie_hint_relocates_to_owner_code_range` checks both ISA
call views, zero backing allocation, exact owner publication, and the
overallocate/trim shape. Its native-pages companion checks actual stores
and generated x86 code execution. These VM-free checks do not prove VMM
publication or Node startup. The director's exact-head signed Node check
is still required.

## Outside-layout fixed sub-mappings and demotion (#1848)

Go's runtime reserves a 64 MiB `PROT_NONE` arena at an outside-layout hint
(`sysReserveOS`, e.g. `0x01400000000` on arm64 or `0x00c000000000` on amd64)
and commits sub-ranges with `mmap(MAP_FIXED | MAP_PRIVATE | MAP_ANONYMOUS)`
(`sysMapOS`), later calling `madvise(MADV_DONTNEED)`, `mprotect`, and `munmap`
on sub-ranges. A fixed private anonymous `Prepare` wholly covered by
`PLACED_OUTSIDE_LAYOUT` owner nodes stays on the MM owner, retains
`PLACED_OUTSIDE_LAYOUT` on the split sub-mapping, and uses lazy owner
publication rather than host alias installation. Fixed replacements over
imported ELF `IMAGE` spans still forward (`ForeignMapping`).

When a host-served operation (`MAP_FIXED` file, shared, or straddling mapping)
demotes or completes an opaque obstacle over a `PLACED_OUTSIDE_LAYOUT` or
`IMAGE` row, root-only outside-layout provenance is stripped from the opaque
obstacle while unclipped neighbour slices retain owner authority. Admitted
`insert_opaque` continues to reject `PLACED_OUTSIDE_LAYOUT` and `IMAGE` with
`Refusal::Invalid`. VM-free witnesses prove the shared reservation model and
production host/ISA dispatch; signed Go test rows still require a signed HVF
run on macOS.
