# Anonymous reservations below the mmap arena (#1663)

The `kernel.el1.anonymous-retirement` contract includes a production-dispatch
witness for a private anonymous PROT_NONE hint at 256 GiB (64 MiB), and a
16 MiB freed buffer reused through PROT_NONE and mprotect RW. Every byte must
read zero after protection changes, including after writing 0x58 and unmapping.

Delegated placement compares the address against `mmap_writable_high`, whose
initial value is the arena base. Thus even a fresh hint below that base is
conservatively classified as reused. This is not proof of resident backing.

Private anonymous mappings on a lazy backend retire predecessor translations
and frames before publishing their new reservation. The shared dispatch path
uses that backing classification to omit eager scrubbing, regardless of VA.
Eager backends still scrub physical backing, bypassing guest permissions, so
PROT_NONE reuse cannot resurrect CPython's freed buffer. Shared and file
mappings retain their existing initialization authority.

The VM-free fixture models sparse frame retirement and fresh-zero supply and
refuses eager scrub requests, as the admitted HVPatch backend does. It requires
zero eager scrub calls and one backing retirement per mapping and unmapping.
It proves dispatch selection, not actual HVF page supply. Signed Go version,
the go-build ecosystem row, and guest reuse zero-fill remain director-owned.

A diagnostic extension also found that `munmap_served` rejects the 256 GiB
non-alias range with EINVAL at its outside-arena range check. That is an
adjacent pre-existing limitation, not covered or fixed by this slice. The
freed-range witness deliberately uses the semantic arena; gap-hint acceptance
ends after reserve/protect/touch. A follow-up needs Linux-valid unmap admission
for such recorded VMAs without losing backing retirement.
