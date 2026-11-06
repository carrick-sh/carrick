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
