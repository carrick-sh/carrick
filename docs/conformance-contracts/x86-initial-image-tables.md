# Initial x86 image tables

Contract `x86.mm.initial-image` requires valid ELF layouts to boot regardless
of how many page-table pages the complete image needs. Linux ELF semantics
permit PT_LOAD memory sizes larger than file sizes (zero BSS).

The production KVM binding
`production_initial_image_spans_more_than_one_edit_table_budget` gives the
existing static exit ELF 16 MiB of memory. Together with the separate stack,
this exceeds the descriptor editor's eight-grant budget for one edit.
That budget bounds one transaction, not one address space.

The initial owner must acquire tables only for missing address prefixes as
it installs each page. Four-level x86 translation needs at most three new
tables per page, independent of total image size. Existing prefixes require
no additional table grants; the root and private copy window remain separate.
The VM-free tests retain exact table-count assertions for the small layout.
Runtime Go and KVM evidence are required separately; this fixture does not
claim Go syscall coverage or an ARM signed verdict.

The failing pool is the *transaction grant list*, not exhausted physical
RAM: `install_initial_image` used to count every distinct user table prefix,
acquire all those frames, and pass its entire unused tail to
`plan_descriptor_txn`. The latter refuses a list longer than
`MAX_TABLE_GRANTS` (8) before walking or consuming a frame. A sufficiently
large contiguous PT_LOAD crosses enough 2 MiB leaf-table boundaries to hit
this refusal; sparse layouts can hit it with very few data pages too.
ARM's initial mapping uses `PageTableManager` and its `alloc_table` path
on demand, rather than submitting the whole image as one edit's grants.

## Issue 1716 evidence

The new production KVM witness was red with `production initial MM refused:
status 2`, then green with exit status 7 after on-demand allocation and exact
host publication-grant reconstruction. The focused initial-MM suite passes
28 tests with one existing ignored test. The VM-free suite passes 119 tests;
its sparse rows add 3, 6 and 9 disjoint leaf-table prefixes and retain exact
frame and table counts. The separate serial-host partitions contain no tests.

The pulled `golang:1.23` amd64 executable has load regions spanning
`0x400000..0xff8600`. Six executable leaf tables plus one stack leaf table,
two directory tables and one PDPT table (including the independent 64 KiB
stack at `0x7fff0000`) make ten user tables, exceeding the old first edit's eight-grant limit.
The root and three private copy-window tables are separate allocations.

The release CLI now enters Go's runtime rather than refusing its initial MM.
It next exits 2 at `runtime.checkfds` with `errno=38` on descriptor 0 and
`fatal error: cannot open standard fds`. Thus the table-allocation witness
is green, but the issue's full `go version` output acceptance remains open.
No unrelated syscall routing is changed to conceal that next failure.
