//! Guest address-space construction — the memory image a Linux process runs in
//! when carrick maps it onto a Hypervisor.framework vCPU.
//!
//! # Theory of operation
//!
//! carrick runs an unmodified Linux ELF as a native macOS process under HVF,
//! with NO guest Linux kernel. Something must still do the kernel's job of
//! laying out a process's address space: load the ELF segments, place the
//! stack/heap/mmap arenas, install the auxiliary vector, and — because we run on
//! bare aarch64 EL0/EL1, not on top of a kernel — hand-build the things a kernel
//! would already have set up: page tables, exception vectors, the entry path
//! into EL0, and the vDSO. That is this crate. It produces an [`memory::AddressSpace`]
//! (a list of [`memory::MemoryRegion`]s plus an entry point and the EL1 control
//! registers to program); the trap engine in `carrick-hvf` `hv_vm_map`s those
//! regions and starts the vCPU.
//!
//! ## The four problems this crate solves
//!
//! * **VA layout** ([`memory`]). A fixed map of where everything lives in the
//!   guest's 1 TiB virtual address space — image, heap, mmap arena, stacks,
//!   trampolines, vDSO, the shared aperture, the Rosetta alias. M-series HVF
//!   caps the guest IPA at 40 bits (1 TiB), so every region (bar the Rosetta
//!   high-VA alias) is identity-mapped `IPA == VA` and must fit under that
//!   ceiling. The constants at the top of [`memory`] are the canonical layout;
//!   each carries the empirical reason it sits where it does.
//!
//! * **The stage-1 MMU + page tables** ([`memory::stage1_identity_page_tables`],
//!   [`page_table`]). The load-bearing trick of the whole crate. The vCPU starts
//!   MMU-off, where ARMv8 treats all memory as Device-nGnRnE and the
//!   load/store-exclusive instructions (`ldaxr`/`stlxr`) every libc lock relies
//!   on are architecturally prohibited. carrick installs a boot identity map and
//!   flips `SCTLR_EL1.M=1` so guest memory becomes Normal cacheable and
//!   exclusives work. The per-page access bits are shaped to dodge Apple
//!   Silicon's FEAT_PAN3 check (see [`memory::stage1_identity_page_tables`]).
//!   [`page_table`] then edits those tables at runtime to give guest
//!   `mprotect`/`munmap`/`PROT_NONE` real, guest-visible semantics.
//!
//! * **ELF loading** ([`elf`], plus the loaders in [`memory`]). Parse the
//!   program headers, compute a load plan, materialise PT_LOAD segments into
//!   regions, and synthesize the Linux initial stack (argv/envp/auxv) the
//!   guest's `_start` expects.
//!
//! * **The vDSO** ([`vdso`], plus the `vdso_getrandom_chacha` core). A hand-built Linux
//!   aarch64 vDSO so the guest reads the clock (and draws random bytes) in
//!   userspace instead of trapping out per call — without it, timer-heavy code
//!   drowns in HVF vmexits.
//!
//! ## Key invariant: regions are an *initialised prefix*, not full backing
//!
//! A [`memory::MemoryRegion`] stores only the bytes that have explicit initial
//! content (`Vec<u8>`); every byte past that prefix reads as zero. The heap and
//! the 32 GiB mmap arena carry an *empty* prefix — their pages are lazily
//! zero-filled by HVF on first touch. Materialising a real zero `Vec` for them
//! would pin gigabytes of RSS per guest process. The [`carrick_guest_mem::GuestMemory`]
//! read/write impl honours this: a read past the prefix returns zeroes. This is
//! the same zero-fill guarantee the dispatcher's mmap bump arena depends on (a
//! `mmap`'d anon page MUST read as zero); the guest-visible failure mode when it
//! is violated is stale-page reuse (a `0x78`-fill SEGV that only shows up under
//! accumulation — see the `mmap_dirty_high` watermark in the runtime).
//!
//! ## Crate boundary
//!
//! Lifted out of carrick-runtime as a cache/parallelism boundary (build-graph
//! A3): editing the VA layout or page tables must not recompile the ~40k-line
//! runtime. Depends only on the leaf crates `carrick-abi` (Linux constants) and
//! `carrick-guest-mem` (the `GuestMemory`/`MemoryError` hub types). The
//! `memory ↔ dispatch` cycle and the `memory → rootfs` edge were removed first
//! (A2/A2.5), so nothing here reaches back into the dispatcher or VFS.

// Moved files use `crate::linux_abi::…`; alias the leaf crate so they're unchanged.
pub use carrick_abi as linux_abi;

pub mod elf;
pub mod memory;
pub mod page_table;
pub mod vdso;
mod vdso_getrandom_chacha;
