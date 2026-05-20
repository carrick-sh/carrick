use std::fs;
use std::path::Path;

use crate::dispatch::{GuestMemory, MemoryError};
use crate::elf::{ElfInspectError, LoadPlan, SegmentPerms, plan_elf_load, plan_elf_load_bytes};
use crate::linux_abi::{
    LINUX_AT_BASE, LINUX_AT_CLKTCK, LINUX_AT_EGID, LINUX_AT_ENTRY, LINUX_AT_EUID, LINUX_AT_EXECFN,
    LINUX_AT_FLAGS, LINUX_AT_GID, LINUX_AT_HWCAP, LINUX_AT_HWCAP2, LINUX_AT_NULL, LINUX_AT_PAGESZ,
    LINUX_AT_PHDR, LINUX_AT_PHENT, LINUX_AT_PHNUM, LINUX_AT_PLATFORM, LINUX_AT_RANDOM,
    LINUX_AT_SECURE, LINUX_AT_UID, LINUX_PAGE_SIZE, LinuxAuxvEntry,
};
use crate::rootfs::{RootFs, RootFsError};
use serde::Serialize;
use thiserror::Error;
use zerocopy::IntoBytes;

// Guest layout for the bootstrap process. HVF on Apple Silicon limits the
// guest intermediate physical address (IPA) range; M-series machines we run
// on advertise a max IPA of 40 bits (1 TiB). Keep every region below that
// ceiling. The layout uses the high half of the 1 TiB window so PIE/static
// executables (loaded at 4–64 GiB) never collide with heap/mmap/stack.
// Guest physical address of the EL0 entry trampoline page. The HVF vCPU
// starts at EL1h; to deliver user code at EL0t we install a single-page
// region whose first instruction is `eret`. The base is well below the
// PIE/heap/mmap/stack window so it cannot collide with the user image.
pub const LINUX_EL0_TRAMPOLINE_BASE: u64 = 0x10000;
// Trampoline region size. Must be at least one HVF page (16 KiB) so the
// stage-2 mapping is aligned. The first 4 bytes carry the `eret` opcode;
// the rest is padded with `nop` so a runaway fetch is harmless.
pub const LINUX_EL0_TRAMPOLINE_SIZE: u64 = 0x4000;
// Guest physical address of the EL1 exception vector page. The AArch64
// vector table is 2 KiB (16 slots of 0x80 bytes); we round up to one HVF
// page (16 KiB) so the stage-2 mapping is aligned. VBAR_EL1 is set to this
// base so EL0 `svc #0` synchronous traps land in the slot at offset 0x400.
pub const LINUX_EL1_VECTORS_BASE: u64 = 0x20000;
pub const LINUX_EL1_VECTORS_SIZE: u64 = 0x4000;
// Stage-1 identity page table for EL0/EL1. Three 4 KiB pages:
//   - one L0 table (2 valid entries, 512 GiB each)
//   - two L1 tables (512 block descriptors × 1 GiB each)
// Identity-maps 0..1 TiB into the same VA range with "Normal Inner
// Shareable WB cacheable" memory (MAIR index 0). This is what
// `ldaxr`/`stlxr` need to work — without it ARMv8 treats every data
// access as Device-nGnRnE and exclusive ops are prohibited.
pub const LINUX_PAGE_TABLES_BASE: u64 = 0x30000;
pub const LINUX_PAGE_TABLES_SIZE: u64 = 0x4000; // 16 KiB allocated, three pages used
// AArch64 `eret` opcode, little-endian.
const AARCH64_ERET_OPCODE: u32 = 0xd69f_03e0;
// AArch64 `clrex` opcode (clears the local Exclusives monitor).
const AARCH64_CLREX_OPCODE: u32 = 0xd5033f5f;
// AArch64 `hvc #0` opcode, used to re-trap from EL1 to HVF.
const AARCH64_HVC0_OPCODE: u32 = 0xd400_0002;
// AArch64 `nop` opcode, used as trampoline page padding.
const AARCH64_NOP_OPCODE: u32 = 0xd503_201f;
// AArch64 `tlbi vmalle1` — invalidate all stage-1 TLB entries for the
// current EL & inner-shareable domain. Required after the host flips
// SCTLR_EL1.M from 0 to 1 via `set_sys_reg` because the guest never
// executed the MSR itself, so the TLB may contain stale identity
// translations from the pre-MMU bootstrap.
const AARCH64_TLBI_VMALLE1_OPCODE: u32 = 0xd508_871f;
// AArch64 `ic ialluis` — invalidate instruction cache, all entries,
// inner-shareable. Same reason: instruction fetches after enabling
// stage-1 must see fresh translations, not pre-MMU cached lines.
const AARCH64_IC_IALLUIS_OPCODE: u32 = 0xd508_711f;
// AArch64 `dsb sy` — data synchronization barrier, full system domain.
const AARCH64_DSB_SY_OPCODE: u32 = 0xd503_3f9f;
// AArch64 `isb` — instruction synchronization barrier.
const AARCH64_ISB_OPCODE: u32 = 0xd503_3fdf;
// Size of one AArch64 exception vector slot (16 slots in the 2 KiB table).
const AARCH64_VECTOR_SLOT_SIZE: usize = 0x80;
// Offset of the "Lower EL using AArch64, synchronous" slot in the vector
// table. EL0 `svc #0` from AArch64 lands here.
const AARCH64_VECTOR_LOWER_EL_SYNC_OFFSET: usize = 0x400;

pub const LINUX_HEAP_BASE: u64 = 0x40_0000_0000; // 256 GiB
pub const LINUX_HEAP_SIZE: u64 = 128 * 1024 * 1024; // 128 MiB
pub const LINUX_MMAP_BASE: u64 = 0x60_0000_0000; // 384 GiB
pub const LINUX_MMAP_SIZE: u64 = 512 * 1024 * 1024; // 512 MiB — apt's pkgcache alone wants 24 MiB
pub const LINUX_INTERPRETER_BASE: u64 = 0x80_0000_0000; // 512 GiB
pub const LINUX_STACK_TOP: u64 = 0xff_ffff_0000; // just under 1 TiB
pub const LINUX_STACK_SIZE: u64 = 2 * 1024 * 1024; // 2 MiB

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AddressSpace {
    entry: u64,
    regions: Vec<MemoryRegion>,
    initial_stack_pointer: Option<u64>,
    /// When set, the HVF trap engine should start the vCPU at this guest
    /// physical address (the EL0 entry trampoline) and use `entry` as the
    /// user-mode ELR_EL1 target after the trampoline's `eret`.
    el0_trampoline_entry: Option<u64>,
    /// When set, the HVF trap engine should program VBAR_EL1 with this guest
    /// physical address. The matching memory region carries the AArch64
    /// vector page whose lower-EL synchronous slot re-traps to HVF via HVC.
    el1_vectors_base: Option<u64>,
    /// When set, the HVF trap engine should program TTBR0_EL1 with this
    /// guest physical address and turn on the stage-1 MMU. The matching
    /// region carries the identity-mapping page tables.
    stage1_page_tables_base: Option<u64>,
    #[serde(skip)]
    linux_auxv: Vec<LinuxAuxvEntry>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct MemoryRegion {
    pub start: u64,
    pub end: u64,
    pub perms: SegmentPerms,
    #[serde(skip)]
    bytes: Vec<u8>,
}

impl MemoryRegion {
    pub fn len(&self) -> u64 {
        self.end - self.start
    }

    pub fn is_empty(&self) -> bool {
        self.start == self.end
    }

    pub fn contains_range(&self, address: u64, length: usize) -> bool {
        let Ok(length) = u64::try_from(length) else {
            return false;
        };
        let Some(end) = address.checked_add(length) else {
            return false;
        };
        address >= self.start && end <= self.end
    }

    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }
}

#[derive(Debug, Error)]
pub enum AddressSpaceError {
    #[error("failed to inspect ELF load plan: {0}")]
    Elf(#[from] ElfInspectError),
    #[error("failed to read ELF bytes: {0}")]
    Io(#[from] std::io::Error),
    #[error("failed to read rootfs-backed ELF dependency: {0}")]
    RootFs(#[from] RootFsError),
    #[error(
        "ELF segment at 0x{virtual_address:x} has file size {file_size} greater than memory size {memory_size}"
    )]
    FileLargerThanMemory {
        virtual_address: u64,
        file_size: u64,
        memory_size: u64,
    },
    #[error("ELF segment at 0x{virtual_address:x} extends beyond the file")]
    SegmentBeyondFile { virtual_address: u64 },
    #[error(
        "memory region 0x{start:x}..0x{end:x} overlaps existing region 0x{other_start:x}..0x{other_end:x}"
    )]
    OverlappingRegion {
        start: u64,
        end: u64,
        other_start: u64,
        other_end: u64,
    },
    #[error("memory region at 0x{start:x} with size {size} overflows")]
    RegionOverflow { start: u64, size: u64 },
    #[error("memory region size {0} does not fit this host")]
    RegionTooLarge(u64),
    #[error("initial stack at 0x{stack_top:x} with size {stack_size} overflows")]
    InitialStackOverflow { stack_top: u64, stack_size: u64 },
    #[error("initial stack string contains a nul byte: {0}")]
    InitialStackStringContainsNul(String),
    #[error("initial Linux stack does not fit in {stack_size} bytes")]
    InitialStackTooLarge { stack_size: u64 },
}

impl AddressSpace {
    pub fn load_elf(path: impl AsRef<Path>) -> Result<Self, AddressSpaceError> {
        let path = path.as_ref();
        let plan = plan_elf_load(path)?;
        let file = fs::read(path)?;
        Self::load_elf_segments(&file, plan)
    }

    pub fn load_elf_bytes(bytes: &[u8]) -> Result<Self, AddressSpaceError> {
        let plan = plan_elf_load_bytes(bytes)?;
        Self::load_elf_segments(bytes, plan)
    }

    pub fn load_elf_from_rootfs(
        path: impl AsRef<Path>,
        rootfs: &RootFs,
    ) -> Result<Self, AddressSpaceError> {
        let file = rootfs.read(path)?;
        let plan = plan_elf_load_bytes(&file)?;
        Self::load_elf_segments_with_interpreter(&file, plan, rootfs)
    }

    fn load_elf_segments(file: &[u8], plan: LoadPlan) -> Result<Self, AddressSpaceError> {
        let linux_auxv = linux_auxv_from_load_plan(&plan, None);
        let mut regions = regions_from_load_plan(file, &plan)?;
        regions.extend(linux_runtime_regions()?);

        let mut image = Self::from_regions(plan.entry, regions)?;
        image.linux_auxv = linux_auxv;
        Ok(image)
    }

    fn load_elf_segments_with_interpreter(
        file: &[u8],
        plan: LoadPlan,
        rootfs: &RootFs,
    ) -> Result<Self, AddressSpaceError> {
        let mut regions = regions_from_load_plan(file, &plan)?;
        let mut entry = plan.entry;
        let mut interpreter_base = None;

        if let Some(interpreter_path) = plan.interpreter.as_deref() {
            let interpreter = rootfs.read(interpreter_path)?;
            let interpreter_plan =
                plan_elf_load_bytes(&interpreter)?.with_load_bias(LINUX_INTERPRETER_BASE);
            regions.extend(regions_from_load_plan(&interpreter, &interpreter_plan)?);
            entry = interpreter_plan.entry;
            interpreter_base = Some(LINUX_INTERPRETER_BASE);
        }
        regions.extend(linux_runtime_regions()?);

        let linux_auxv = linux_auxv_from_load_plan(&plan, interpreter_base);
        let mut image = Self::from_regions(entry, regions)?;
        image.linux_auxv = linux_auxv;
        Ok(image)
    }

    pub fn from_segments<I>(entry: u64, segments: I) -> Result<Self, AddressSpaceError>
    where
        I: IntoIterator<Item = (u64, SegmentPerms, Vec<u8>, u64)>,
    {
        let mut regions = Vec::new();
        for (start, perms, file_bytes, memory_size) in segments {
            if u64::try_from(file_bytes.len()).unwrap_or(u64::MAX) > memory_size {
                return Err(AddressSpaceError::FileLargerThanMemory {
                    virtual_address: start,
                    file_size: file_bytes.len() as u64,
                    memory_size,
                });
            }
            let memory_len = usize::try_from(memory_size)
                .map_err(|_| AddressSpaceError::RegionTooLarge(memory_size))?;
            let mut bytes = vec![0; memory_len];
            bytes[..file_bytes.len()].copy_from_slice(&file_bytes);
            let end = start
                .checked_add(memory_size)
                .ok_or(AddressSpaceError::RegionOverflow {
                    start,
                    size: memory_size,
                })?;
            regions.push(MemoryRegion {
                start,
                end,
                perms,
                bytes,
            });
        }
        Self::from_regions(entry, regions)
    }

    pub fn from_regions(
        entry: u64,
        mut regions: Vec<MemoryRegion>,
    ) -> Result<Self, AddressSpaceError> {
        regions.sort_by_key(|region| region.start);
        for pair in regions.windows(2) {
            let left = &pair[0];
            let right = &pair[1];
            if left.end > right.start {
                return Err(AddressSpaceError::OverlappingRegion {
                    start: right.start,
                    end: right.end,
                    other_start: left.start,
                    other_end: left.end,
                });
            }
        }
        Ok(Self {
            entry,
            regions,
            initial_stack_pointer: None,
            el0_trampoline_entry: None,
            el1_vectors_base: None,
            stage1_page_tables_base: None,
            linux_auxv: Vec::new(),
        })
    }

    pub fn entry(&self) -> u64 {
        self.entry
    }

    pub fn regions(&self) -> &[MemoryRegion] {
        &self.regions
    }

    pub fn initial_stack_pointer(&self) -> Option<u64> {
        self.initial_stack_pointer
    }

    /// When set, the trap engine should boot the vCPU at this guest physical
    /// address (the EL0 entry trampoline) instead of `entry()`. The real user
    /// entry remains in `entry()` and is wired into ELR_EL1 so the trampoline
    /// `eret` lands the vCPU at user code in EL0t.
    pub fn el0_trampoline_entry(&self) -> Option<u64> {
        self.el0_trampoline_entry
    }

    /// When set, the trap engine should program VBAR_EL1 with this guest
    /// physical address so EL0 SVC traps are routed through our vector page.
    pub fn el1_vectors_base(&self) -> Option<u64> {
        self.el1_vectors_base
    }

    /// When set, the trap engine should program TTBR0_EL1 with this guest
    /// physical address and turn on the stage-1 MMU (SCTLR_EL1.M=1) so EL0
    /// data accesses are tagged Normal cacheable (required for `ldaxr`).
    pub fn stage1_page_tables_base(&self) -> Option<u64> {
        self.stage1_page_tables_base
    }

    /// Append the EL0 entry trampoline region. The trampoline is a single
    /// page containing one `eret` instruction at offset 0. The vCPU starts
    /// here at EL1h with SPSR_EL1 staged for EL0t, so the first instruction
    /// drops the guest to EL0 with PC = user entry.
    pub fn with_el0_trampoline(self) -> Result<Self, AddressSpaceError> {
        let bytes = el0_trampoline_bytes();
        let start = LINUX_EL0_TRAMPOLINE_BASE;
        let end =
            start
                .checked_add(LINUX_EL0_TRAMPOLINE_SIZE)
                .ok_or(AddressSpaceError::RegionOverflow {
                    start,
                    size: LINUX_EL0_TRAMPOLINE_SIZE,
                })?;
        let region = MemoryRegion {
            start,
            end,
            perms: SegmentPerms {
                read: true,
                write: false,
                execute: true,
            },
            bytes,
        };

        // Reconstruct via `from_regions` so the overlap check still runs.
        let AddressSpace {
            entry,
            regions,
            initial_stack_pointer,
            linux_auxv,
            el1_vectors_base,
            stage1_page_tables_base,
            ..
        } = self;
        let mut image =
            Self::from_regions(entry, regions.into_iter().chain([region]).collect())?;
        image.initial_stack_pointer = initial_stack_pointer;
        image.linux_auxv = linux_auxv;
        image.el0_trampoline_entry = Some(LINUX_EL0_TRAMPOLINE_BASE);
        image.el1_vectors_base = el1_vectors_base;
        image.stage1_page_tables_base = stage1_page_tables_base;
        Ok(image)
    }

    /// Append the EL1 exception vector page. Each 0x80-byte slot is either:
    /// * the "Lower EL using AArch64, synchronous" slot at offset 0x400,
    ///   which executes `hvc #0; eret` so the EL0 `svc #0` is forwarded to
    ///   HVF as an HVC trap (`EC = 0x16`) that the host dispatches like a
    ///   normal syscall; or
    /// * any other slot, which executes a bare `eret` so a spurious
    ///   exception just returns to wherever it came from instead of
    ///   crashing on an unmapped vector fetch.
    pub fn with_el1_vectors(self) -> Result<Self, AddressSpaceError> {
        let bytes = el1_vectors_bytes();
        let start = LINUX_EL1_VECTORS_BASE;
        let end =
            start
                .checked_add(LINUX_EL1_VECTORS_SIZE)
                .ok_or(AddressSpaceError::RegionOverflow {
                    start,
                    size: LINUX_EL1_VECTORS_SIZE,
                })?;
        let region = MemoryRegion {
            start,
            end,
            perms: SegmentPerms {
                read: true,
                write: false,
                execute: true,
            },
            bytes,
        };

        let AddressSpace {
            entry,
            regions,
            initial_stack_pointer,
            linux_auxv,
            el0_trampoline_entry,
            stage1_page_tables_base,
            ..
        } = self;
        let mut image =
            Self::from_regions(entry, regions.into_iter().chain([region]).collect())?;
        image.initial_stack_pointer = initial_stack_pointer;
        image.linux_auxv = linux_auxv;
        image.el0_trampoline_entry = el0_trampoline_entry;
        image.el1_vectors_base = Some(LINUX_EL1_VECTORS_BASE);
        image.stage1_page_tables_base = stage1_page_tables_base;
        Ok(image)
    }

    /// Append the stage-1 identity-mapping page tables region. The vCPU
    /// uses these so EL0/EL1 data accesses are tagged as Normal cacheable
    /// memory (required for `ldaxr`/`stlxr`).
    pub fn with_stage1_page_tables(self) -> Result<Self, AddressSpaceError> {
        let bytes = stage1_identity_page_tables();
        let start = LINUX_PAGE_TABLES_BASE;
        let end =
            start
                .checked_add(LINUX_PAGE_TABLES_SIZE)
                .ok_or(AddressSpaceError::RegionOverflow {
                    start,
                    size: LINUX_PAGE_TABLES_SIZE,
                })?;
        let region = MemoryRegion {
            start,
            end,
            perms: SegmentPerms {
                read: true,
                write: false,
                execute: false,
            },
            bytes,
        };

        let AddressSpace {
            entry,
            regions,
            initial_stack_pointer,
            linux_auxv,
            el0_trampoline_entry,
            el1_vectors_base,
            ..
        } = self;
        let mut image =
            Self::from_regions(entry, regions.into_iter().chain([region]).collect())?;
        image.initial_stack_pointer = initial_stack_pointer;
        image.linux_auxv = linux_auxv;
        image.el0_trampoline_entry = el0_trampoline_entry;
        image.el1_vectors_base = el1_vectors_base;
        image.stage1_page_tables_base = Some(LINUX_PAGE_TABLES_BASE);
        Ok(image)
    }

    pub fn with_linux_initial_stack<A, E>(self, argv: A, env: E) -> Result<Self, AddressSpaceError>
    where
        A: IntoIterator<Item = String>,
        E: IntoIterator<Item = String>,
    {
        self.with_linux_initial_stack_at(argv, env, LINUX_STACK_TOP, LINUX_STACK_SIZE)
    }

    pub fn with_linux_initial_stack_at<A, E>(
        self,
        argv: A,
        env: E,
        stack_top: u64,
        stack_size: u64,
    ) -> Result<Self, AddressSpaceError>
    where
        A: IntoIterator<Item = String>,
        E: IntoIterator<Item = String>,
    {
        let AddressSpace {
            entry,
            regions,
            linux_auxv,
            el0_trampoline_entry,
            el1_vectors_base,
            stage1_page_tables_base,
            ..
        } = self;
        let argv = argv.into_iter().collect::<Vec<_>>();
        let env = env.into_iter().collect::<Vec<_>>();
        let (region, stack_pointer) =
            build_linux_initial_stack(argv, env, &linux_auxv, stack_top, stack_size)?;
        let mut image = Self::from_regions(entry, regions.into_iter().chain([region]).collect())?;
        image.initial_stack_pointer = Some(stack_pointer);
        image.linux_auxv = linux_auxv;
        image.el0_trampoline_entry = el0_trampoline_entry;
        image.el1_vectors_base = el1_vectors_base;
        image.stage1_page_tables_base = stage1_page_tables_base;
        Ok(image)
    }

    pub fn find_bytes(&self, needle: &[u8]) -> Option<u64> {
        if needle.is_empty() {
            return Some(self.regions.first()?.start);
        }

        self.regions.iter().find_map(|region| {
            region
                .bytes
                .windows(needle.len())
                .position(|window| window == needle)
                .map(|offset| region.start + offset as u64)
        })
    }
}

fn build_linux_initial_stack(
    argv: Vec<String>,
    env: Vec<String>,
    auxv: &[LinuxAuxvEntry],
    stack_top: u64,
    stack_size: u64,
) -> Result<(MemoryRegion, u64), AddressSpaceError> {
    let stack_start =
        stack_top
            .checked_sub(stack_size)
            .ok_or(AddressSpaceError::InitialStackOverflow {
                stack_top,
                stack_size,
            })?;
    let stack_len =
        usize::try_from(stack_size).map_err(|_| AddressSpaceError::RegionTooLarge(stack_size))?;
    let mut bytes = vec![0; stack_len];
    let mut cursor = stack_len;

    let argv_addrs = write_stack_strings(&mut bytes, stack_start, &mut cursor, &argv, stack_size)?;
    let env_addrs = write_stack_strings(&mut bytes, stack_start, &mut cursor, &env, stack_size)?;

    // AT_EXECFN, AT_PLATFORM bytes (NUL-terminated strings on the stack).
    let execfn_addr = if let Some(first) = argv.first() {
        let s = first.as_bytes();
        if cursor < s.len() + 1 {
            return Err(AddressSpaceError::InitialStackTooLarge { stack_size });
        }
        cursor -= s.len() + 1;
        bytes[cursor..cursor + s.len()].copy_from_slice(s);
        bytes[cursor + s.len()] = 0;
        Some(stack_start + cursor as u64)
    } else {
        None
    };
    let platform = b"aarch64";
    if cursor < platform.len() + 1 {
        return Err(AddressSpaceError::InitialStackTooLarge { stack_size });
    }
    cursor -= platform.len() + 1;
    bytes[cursor..cursor + platform.len()].copy_from_slice(platform);
    bytes[cursor + platform.len()] = 0;
    let platform_addr = stack_start + cursor as u64;

    // AT_RANDOM — 16 bytes glibc copies into __stack_chk_guard, pointer_guard,
    // and dl_random. Source from the host's CSPRNG via libc::getentropy so
    // each process gets fresh canaries; ZSTC/OpenSSL boot also checks it
    // before deciding it can use vectorized routines.
    cursor = align_down_usize(cursor, 16);
    if cursor < 16 {
        return Err(AddressSpaceError::InitialStackTooLarge { stack_size });
    }
    cursor -= 16;
    let mut random_bytes = [0u8; 16];
    unsafe {
        let _ = libc::getentropy(
            random_bytes.as_mut_ptr() as *mut _,
            random_bytes.len(),
        );
    }
    bytes[cursor..cursor + 16].copy_from_slice(&random_bytes);
    let random_addr = stack_start + cursor as u64;

    cursor = align_down_usize(cursor, 16);

    let mut entries = Vec::with_capacity(1 + argv_addrs.len() + 1 + env_addrs.len() + 1);
    entries.push(argv_addrs.len() as u64);
    entries.extend(argv_addrs);
    entries.push(0);
    entries.extend(env_addrs);
    entries.push(0);

    let auxv_len = auxv
        .len()
        .checked_add(1)
        .and_then(|len| len.checked_mul(core::mem::size_of::<LinuxAuxvEntry>()))
        .ok_or(AddressSpaceError::InitialStackTooLarge { stack_size })?;
    let entries_len = entries
        .len()
        .checked_mul(8)
        .and_then(|len| len.checked_add(auxv_len))
        .ok_or(AddressSpaceError::InitialStackTooLarge { stack_size })?;
    if cursor < entries_len {
        return Err(AddressSpaceError::InitialStackTooLarge { stack_size });
    }
    let stack_pointer_offset = align_down_usize(cursor - entries_len, 16);
    let entries_words = entries.len();
    for (index, entry) in entries.into_iter().enumerate() {
        let offset = stack_pointer_offset + index * 8;
        bytes[offset..offset + 8].copy_from_slice(&entry.to_le_bytes());
    }
    let mut auxv_offset = stack_pointer_offset + entries_words * 8;
    for entry in auxv.iter().copied() {
        let patched = match entry.a_type {
            LINUX_AT_RANDOM => LinuxAuxvEntry::new(LINUX_AT_RANDOM, random_addr),
            LINUX_AT_PLATFORM => LinuxAuxvEntry::new(LINUX_AT_PLATFORM, platform_addr),
            LINUX_AT_EXECFN => match execfn_addr {
                Some(addr) => LinuxAuxvEntry::new(LINUX_AT_EXECFN, addr),
                None => continue,
            },
            _ => entry,
        };
        bytes[auxv_offset..auxv_offset + core::mem::size_of::<LinuxAuxvEntry>()]
            .copy_from_slice(patched.as_bytes());
        auxv_offset += core::mem::size_of::<LinuxAuxvEntry>();
    }
    bytes[auxv_offset..auxv_offset + core::mem::size_of::<LinuxAuxvEntry>()]
        .copy_from_slice(LinuxAuxvEntry::new(LINUX_AT_NULL, 0).as_bytes());

    Ok((
        MemoryRegion {
            start: stack_start,
            end: stack_top,
            perms: SegmentPerms {
                read: true,
                write: true,
                execute: false,
            },
            bytes,
        },
        stack_start + stack_pointer_offset as u64,
    ))
}

fn write_stack_strings(
    stack: &mut [u8],
    stack_start: u64,
    cursor: &mut usize,
    strings: &[String],
    stack_size: u64,
) -> Result<Vec<u64>, AddressSpaceError> {
    let mut addrs = Vec::with_capacity(strings.len());
    for value in strings.iter().rev() {
        let string = value.as_bytes();
        if string.contains(&0) {
            return Err(AddressSpaceError::InitialStackStringContainsNul(
                value.clone(),
            ));
        }
        let len = string
            .len()
            .checked_add(1)
            .ok_or(AddressSpaceError::InitialStackTooLarge { stack_size })?;
        if *cursor < len {
            return Err(AddressSpaceError::InitialStackTooLarge { stack_size });
        }
        *cursor -= len;
        stack[*cursor..*cursor + string.len()].copy_from_slice(string);
        stack[*cursor + string.len()] = 0;
        addrs.push(stack_start + *cursor as u64);
    }
    addrs.reverse();
    Ok(addrs)
}

fn align_down_usize(value: usize, alignment: usize) -> usize {
    value / alignment * alignment
}

fn regions_from_load_plan(
    file: &[u8],
    plan: &LoadPlan,
) -> Result<Vec<MemoryRegion>, AddressSpaceError> {
    // Apple HVF on macOS 26 mis-translates stage-2 page tables when an ELF
    // image is split into multiple non-contiguous mappings within the same
    // ~1 MiB block (Alpine's `ld-musl-aarch64.so.1` r-x text at 0x0 and r-w
    // data at 0xbfb00 reproduces this — second segment's pages report
    // DFSC=0x35, "external abort on TT walk, level 1"). Collapse a plan's
    // PT_LOAD segments into one contiguous region per image whenever they
    // sit within a small window of each other. Permissions widen to the
    // union of the segments' perms (we then escalate to RWX in
    // `hvf_perms` anyway), and gaps are zero-padded in the host buffer.
    const MERGE_WINDOW: u64 = 16 * 1024 * 1024;

    if plan.segments.is_empty() {
        return Ok(Vec::new());
    }

    let min_start = plan
        .segments
        .iter()
        .map(|seg| seg.virtual_address)
        .min()
        .expect("non-empty segments");
    let max_end = plan
        .segments
        .iter()
        .map(|seg| seg.virtual_address.wrapping_add(seg.memory_size))
        .max()
        .expect("non-empty segments");
    if max_end.saturating_sub(min_start) <= MERGE_WINDOW {
        let total_size_u64 = max_end
            .checked_sub(min_start)
            .ok_or(AddressSpaceError::RegionOverflow {
                start: min_start,
                size: 0,
            })?;
        let total_size = usize::try_from(total_size_u64)
            .map_err(|_| AddressSpaceError::RegionTooLarge(total_size_u64))?;
        let mut bytes = vec![0_u8; total_size];
        let mut merged_perms = SegmentPerms::default();
        for segment in &plan.segments {
            merged_perms.read |= segment.perms.read;
            merged_perms.write |= segment.perms.write;
            merged_perms.execute |= segment.perms.execute;
            let file_offset = usize::try_from(segment.file_offset).map_err(|_| {
                AddressSpaceError::SegmentBeyondFile {
                    virtual_address: segment.virtual_address,
                }
            })?;
            let file_size = usize::try_from(segment.file_size).map_err(|_| {
                AddressSpaceError::SegmentBeyondFile {
                    virtual_address: segment.virtual_address,
                }
            })?;
            let file_end = file_offset.checked_add(file_size).ok_or(
                AddressSpaceError::SegmentBeyondFile {
                    virtual_address: segment.virtual_address,
                },
            )?;
            if file_end > file.len() {
                return Err(AddressSpaceError::SegmentBeyondFile {
                    virtual_address: segment.virtual_address,
                });
            }
            let offset_in_region = usize::try_from(
                segment.virtual_address.wrapping_sub(min_start),
            )
            .map_err(|_| AddressSpaceError::RegionTooLarge(total_size_u64))?;
            bytes[offset_in_region..offset_in_region + file_size]
                .copy_from_slice(&file[file_offset..file_end]);
        }
        return Ok(vec![MemoryRegion {
            start: min_start,
            end: max_end,
            perms: merged_perms,
            bytes,
        }]);
    }

    let mut regions = Vec::with_capacity(plan.segments.len());

    for segment in &plan.segments {
        // `virtual_address` is already rebased by the load plan (including
        // the PIE bias for ET_DYN binaries). Treat it as the final guest
        // address without further adjustment.
        let start = segment.virtual_address;

        if segment.file_size > segment.memory_size {
            return Err(AddressSpaceError::FileLargerThanMemory {
                virtual_address: start,
                file_size: segment.file_size,
                memory_size: segment.memory_size,
            });
        }

        let file_offset = usize::try_from(segment.file_offset).map_err(|_| {
            AddressSpaceError::SegmentBeyondFile {
                virtual_address: start,
            }
        })?;
        let file_size = usize::try_from(segment.file_size).map_err(|_| {
            AddressSpaceError::SegmentBeyondFile {
                virtual_address: start,
            }
        })?;
        let file_end =
            file_offset
                .checked_add(file_size)
                .ok_or(AddressSpaceError::SegmentBeyondFile {
                    virtual_address: start,
                })?;
        if file_end > file.len() {
            return Err(AddressSpaceError::SegmentBeyondFile {
                virtual_address: start,
            });
        }

        let memory_size = usize::try_from(segment.memory_size)
            .map_err(|_| AddressSpaceError::RegionTooLarge(segment.memory_size))?;
        let mut bytes = vec![0; memory_size];
        bytes[..file_size].copy_from_slice(&file[file_offset..file_end]);

        regions.push(MemoryRegion {
            start,
            end: start.checked_add(segment.memory_size).ok_or(
                AddressSpaceError::RegionOverflow {
                    start,
                    size: segment.memory_size,
                },
            )?,
            perms: segment.perms,
            bytes,
        });
    }

    Ok(regions)
}

/// Build the byte image of the EL0 entry trampoline page. Offset 0 is a
/// single `eret`; the rest of the page is filled with `nop` so a stray fetch
/// beyond the entry instruction doesn't immediately fault.
/// Build a stage-1 identity-mapping page table for the EL0/EL1 guest with
/// per-region AP so it survives Apple Silicon's FEAT_PAN3 check.
///
/// On Apple Silicon HVF the vCPU starts with PSTATE.PAN=1 regardless of
/// what the host writes to CPSR via `set_reg`. With FEAT_PAN3 (mandatory
/// on ARMv8.3+), any EL1 instruction fetch from a page whose descriptor
/// has AP[1]=1 (i.e. AP=01, user-accessible) raises a permission fault.
/// To work around that we split the identity map so:
///
/// * Pages EL1 fetches from (trampoline 0x10000, vectors 0x20000, this
///   page-table region at 0x30000) live in the first 2 MiB block of
///   L1A[0] and use AP=00 (RW at EL1 only, no EL0 access). UXN=1 so
///   user code can never accidentally jump into kernel pages.
/// * Pages EL0 fetches from (user PIE/static text, interpreter, heap,
///   mmap arena, stack) live in every other block at any level and use
///   AP=01 + PXN=1 + UXN=0 (RW at both ELs, no EL1 instruction fetch).
///   PXN=1 is what bypasses FEAT_PAN3 — EL1 isn't allowed to fetch from
///   these pages, so the PAN check never fires.
///
/// Buffer layout (16 KiB total, four 4 KiB pages):
///
/// * Page 0 (0x000–0xFFF): L0 table — two table descriptors.
/// * Page 1 (0x1000–0x1FFF): L1A — L1A[0] is a table descriptor pointing
///   at the L2 sub-table; L1A[1..511] are user 1 GiB block descriptors.
/// * Page 2 (0x2000–0x2FFF): L1B — all 512 entries are user 1 GiB block
///   descriptors covering 512 GiB..1 TiB.
/// * Page 3 (0x3000–0x3FFF): L2 sub-table for the first 1 GiB — L2[0] is
///   the kernel-only 2 MiB block covering 0..2 MiB; L2[1..511] are user
///   2 MiB block descriptors covering 2 MiB..1 GiB.
pub fn stage1_identity_page_tables() -> Vec<u8> {
    let size = LINUX_PAGE_TABLES_SIZE as usize;
    let mut bytes = vec![0_u8; size];

    let l1_a_pa = LINUX_PAGE_TABLES_BASE + 0x1000;
    let l1_b_pa = LINUX_PAGE_TABLES_BASE + 0x2000;
    let l2_a_pa = LINUX_PAGE_TABLES_BASE + 0x3000;

    // Table descriptors point at the next-level table. Bits 47:12 hold the
    // PA of the next-level table; bits 1:0 = 11 (valid table). AP/PXN/UXN
    // restrictions could go in the upper attributes (bits 59..63) but we
    // leave them clear and rely on the leaf block descriptors.
    let table_descriptor =
        |next_pa: u64| -> u64 { (next_pa & 0x0000_FFFF_FFFF_F000) | 0b11 };

    // Kernel-only leaf flags (used by L2[0] — covers trampoline/vectors/PT):
    //   bit  0 = 1   (valid)
    //   bit  1 = 0   (block)
    //   bits 4..2 = 0   (AttrIndex — MAIR slot 0, Normal WB)
    //   bit  5 = 0   (NS)
    //   bits 7..6 = 0b00  (AP[2:1] = RW EL1, no EL0 — avoids FEAT_PAN3)
    //   bits 9..8 = 0b11  (SH = Inner Shareable)
    //   bit 10 = 1   (AF)
    //   bit 11 = 0   (nG)
    //   bit 53 = 0   (PXN — EL1 must be able to fetch trampoline/vectors)
    //   bit 54 = 1   (UXN — EL0 must NOT be able to fetch kernel pages)
    const KERNEL_BLOCK_FLAGS: u64 =
        (1u64 << 54) | (1 << 10) | (0b11 << 8) | (0b00 << 6) | 0b01;

    // User leaf flags (everywhere else):
    //   AP[2:1] = 0b01 (RW EL1 + EL0)
    //   PXN = 1  (no EL1 fetch — required because AP[1]=1 would otherwise
    //             trip FEAT_PAN3 on PSTATE.PAN=1)
    //   UXN = 0  (EL0 can fetch user code)
    //   AF, SH, AttrIndex same as kernel block.
    const USER_BLOCK_FLAGS: u64 =
        (1u64 << 53) | (1 << 10) | (0b11 << 8) | (0b01 << 6) | 0b01;

    // PA masks for block descriptors at each level.
    const PA_MASK_1GIB: u64 = 0x0000_FFFF_C000_0000; // bits 47..30
    const PA_MASK_2MIB: u64 = 0x0000_FFFF_FFE0_0000; // bits 47..21

    // ----- L0 -----
    bytes[0..8].copy_from_slice(&table_descriptor(l1_a_pa).to_le_bytes());
    bytes[8..16].copy_from_slice(&table_descriptor(l1_b_pa).to_le_bytes());

    // ----- L1A: covers 0..512 GiB -----
    // L1A[0] is a table descriptor pointing at L2_A so the first 1 GiB gets
    // fine-grained AP via 2 MiB blocks.
    bytes[0x1000..0x1008].copy_from_slice(&table_descriptor(l2_a_pa).to_le_bytes());
    // L1A[1..511] are 1 GiB user blocks.
    for index in 1..512_u64 {
        let pa = index << 30;
        let descriptor = (pa & PA_MASK_1GIB) | USER_BLOCK_FLAGS;
        let off = 0x1000 + (index as usize) * 8;
        bytes[off..off + 8].copy_from_slice(&descriptor.to_le_bytes());
    }

    // ----- L1B: covers 512 GiB..1 TiB -----
    for index in 0..512_u64 {
        let pa = (index + 512) << 30;
        let descriptor = (pa & PA_MASK_1GIB) | USER_BLOCK_FLAGS;
        let off = 0x2000 + (index as usize) * 8;
        bytes[off..off + 8].copy_from_slice(&descriptor.to_le_bytes());
    }

    // ----- L2_A: covers the first 1 GiB in 2 MiB blocks -----
    // L2[0] covers VA 0..2 MiB — kernel-only.
    let l2_0 = (0u64 & PA_MASK_2MIB) | KERNEL_BLOCK_FLAGS;
    bytes[0x3000..0x3008].copy_from_slice(&l2_0.to_le_bytes());
    // L2[1..511] are 2 MiB user blocks.
    for index in 1..512_u64 {
        let pa = index << 21;
        let descriptor = (pa & PA_MASK_2MIB) | USER_BLOCK_FLAGS;
        let off = 0x3000 + (index as usize) * 8;
        bytes[off..off + 8].copy_from_slice(&descriptor.to_le_bytes());
    }

    bytes
}

pub fn el0_trampoline_bytes() -> Vec<u8> {
    let size = LINUX_EL0_TRAMPOLINE_SIZE as usize;
    let mut bytes = vec![0_u8; size];
    // The host flips SCTLR_EL1.M from 0 to 1 via `set_sys_reg` before the
    // vCPU runs. ARMv8-A requires the guest to issue cache + TLB
    // maintenance after such a transition or fetches/data accesses may
    // hit stale pre-MMU translations and abort. The trampoline therefore
    // executes (in order):
    //   tlbi vmalle1is  — drop stage-1 TLB entries inner-shareable
    //   dsb sy          — make the invalidation observable
    //   ic ialluis      — drop instruction cache entries inner-shareable
    //   dsb sy          — make the I-cache invalidation observable
    //   isb             — synchronise instruction fetch with the new mapping
    //   clrex           — clear the local Exclusives monitor (musl LDAXR)
    //   eret            — drop to EL0 at the user entry
    let mut offset = 0;
    for opcode in [
        AARCH64_TLBI_VMALLE1_OPCODE,
        AARCH64_DSB_SY_OPCODE,
        AARCH64_IC_IALLUIS_OPCODE,
        AARCH64_DSB_SY_OPCODE,
        AARCH64_ISB_OPCODE,
        AARCH64_CLREX_OPCODE,
        AARCH64_ERET_OPCODE,
    ] {
        let bytes_le = opcode.to_le_bytes();
        bytes[offset..offset + bytes_le.len()].copy_from_slice(&bytes_le);
        offset += bytes_le.len();
    }
    let nop = AARCH64_NOP_OPCODE.to_le_bytes();
    while offset + nop.len() <= size {
        bytes[offset..offset + nop.len()].copy_from_slice(&nop);
        offset += nop.len();
    }
    bytes
}

/// Build the byte image of the EL1 exception vector page. The first 2 KiB
/// is the AArch64 vector table (16 slots of 0x80 bytes each); the rest of
/// the page is filled with `nop`. Slot 0x400 ("Lower EL using AArch64,
/// synchronous") catches EL0 `svc #0` and re-traps to HVF via `hvc #0`;
/// every other slot is a bare `eret` so spurious exceptions just return.
pub fn el1_vectors_bytes() -> Vec<u8> {
    let size = LINUX_EL1_VECTORS_SIZE as usize;
    let mut bytes = vec![0_u8; size];
    let hvc = AARCH64_HVC0_OPCODE.to_le_bytes();
    let eret = AARCH64_ERET_OPCODE.to_le_bytes();
    let nop = AARCH64_NOP_OPCODE.to_le_bytes();

    // Fill the 16 vector slots covering the first 2 KiB of the page.
    let mut slot_offset = 0;
    while slot_offset + AARCH64_VECTOR_SLOT_SIZE <= 16 * AARCH64_VECTOR_SLOT_SIZE
        && slot_offset + AARCH64_VECTOR_SLOT_SIZE <= size
    {
        let mut cursor = slot_offset;
        if slot_offset == AARCH64_VECTOR_LOWER_EL_SYNC_OFFSET {
            bytes[cursor..cursor + hvc.len()].copy_from_slice(&hvc);
            cursor += hvc.len();
            bytes[cursor..cursor + eret.len()].copy_from_slice(&eret);
            cursor += eret.len();
        } else {
            bytes[cursor..cursor + eret.len()].copy_from_slice(&eret);
            cursor += eret.len();
        }
        // Pad the rest of the slot with `nop` so an over-run on the
        // `eret`/`hvc;eret` body lands on harmless filler.
        while cursor + nop.len() <= slot_offset + AARCH64_VECTOR_SLOT_SIZE {
            bytes[cursor..cursor + nop.len()].copy_from_slice(&nop);
            cursor += nop.len();
        }
        slot_offset += AARCH64_VECTOR_SLOT_SIZE;
    }

    // Fill the rest of the page (past the 2 KiB vector table) with `nop`.
    let mut offset = 16 * AARCH64_VECTOR_SLOT_SIZE;
    while offset + nop.len() <= size {
        bytes[offset..offset + nop.len()].copy_from_slice(&nop);
        offset += nop.len();
    }
    bytes
}

fn linux_runtime_regions() -> Result<Vec<MemoryRegion>, AddressSpaceError> {
    Ok(vec![
        zeroed_region(
            LINUX_HEAP_BASE,
            LINUX_HEAP_SIZE,
            SegmentPerms {
                read: true,
                write: true,
                execute: false,
            },
        )?,
        zeroed_region(
            LINUX_MMAP_BASE,
            LINUX_MMAP_SIZE,
            SegmentPerms {
                read: true,
                write: true,
                execute: true,
            },
        )?,
    ])
}

fn zeroed_region(
    start: u64,
    size: u64,
    perms: SegmentPerms,
) -> Result<MemoryRegion, AddressSpaceError> {
    let end = start
        .checked_add(size)
        .ok_or(AddressSpaceError::RegionOverflow { start, size })?;
    // A zeroed region (heap, mmap arena) carries NO payload bytes: the extent
    // is end-start, but the initial contents are entirely zero. We let HVF's
    // lazily zero-filled guest memory provide that, instead of materialising a
    // 512 MiB zero Vec (which, copied into the HVF buffer, pinned ~2 GiB
    // resident per guest process). `MemoryRegion::bytes` is only the
    // initialised prefix; everything past it reads as zero.
    Ok(MemoryRegion {
        start,
        end,
        perms,
        bytes: Vec::new(),
    })
}

fn linux_auxv_from_load_plan(
    plan: &LoadPlan,
    interpreter_base: Option<u64>,
) -> Vec<LinuxAuxvEntry> {
    let mut auxv = Vec::new();
    if let Some(phdr) = plan.program_header_address {
        auxv.push(LinuxAuxvEntry::new(LINUX_AT_PHDR, phdr));
        auxv.push(LinuxAuxvEntry::new(
            LINUX_AT_PHENT,
            u64::from(plan.program_header_entry_size),
        ));
        auxv.push(LinuxAuxvEntry::new(
            LINUX_AT_PHNUM,
            u64::from(plan.program_header_count),
        ));
    }
    auxv.push(LinuxAuxvEntry::new(LINUX_AT_PAGESZ, LINUX_PAGE_SIZE));
    if let Some(base) = interpreter_base {
        auxv.push(LinuxAuxvEntry::new(LINUX_AT_BASE, base));
    }
    auxv.push(LinuxAuxvEntry::new(LINUX_AT_FLAGS, 0));
    auxv.push(LinuxAuxvEntry::new(LINUX_AT_ENTRY, plan.entry));
    // Identity ids — bootstrap runs as the host user, not real Linux
    // root semantics. Returning 0/0 keeps glibc's __nss_database_lookup
    // and friends from deciding the process is "secure" (AT_SECURE=1)
    // and dropping LD_LIBRARY_PATH lookups.
    auxv.push(LinuxAuxvEntry::new(LINUX_AT_UID, 0));
    auxv.push(LinuxAuxvEntry::new(LINUX_AT_EUID, 0));
    auxv.push(LinuxAuxvEntry::new(LINUX_AT_GID, 0));
    auxv.push(LinuxAuxvEntry::new(LINUX_AT_EGID, 0));
    auxv.push(LinuxAuxvEntry::new(LINUX_AT_SECURE, 0));
    auxv.push(LinuxAuxvEntry::new(LINUX_AT_CLKTCK, 100));
    // Minimal AArch64 HWCAP — enough for glibc to decide it can use the
    // "modern" optimized routines. Bits picked from /usr/include/asm/hwcap.h
    // (FP, ASIMD, AES, PMULL, SHA1, SHA2, CRC32, ATOMICS).
    auxv.push(LinuxAuxvEntry::new(LINUX_AT_HWCAP, 0x1fb));
    auxv.push(LinuxAuxvEntry::new(LINUX_AT_HWCAP2, 0));
    // Sentinel addresses for AT_RANDOM, AT_PLATFORM, AT_EXECFN — the
    // actual stack offsets get patched in by `build_linux_initial_stack`
    // once it has placed the backing bytes on the stack. Using 0 here
    // would be visible to glibc as "no random / no platform" and break
    // stack canary init.
    auxv.push(LinuxAuxvEntry::new(LINUX_AT_RANDOM, 0));
    auxv.push(LinuxAuxvEntry::new(LINUX_AT_PLATFORM, 0));
    auxv.push(LinuxAuxvEntry::new(LINUX_AT_EXECFN, 0));
    auxv
}

impl GuestMemory for AddressSpace {
    fn read_bytes(&self, address: u64, length: usize) -> Result<Vec<u8>, MemoryError> {
        let region = self
            .regions
            .iter()
            .find(|region| region.contains_range(address, length))
            .ok_or(MemoryError::OutOfBounds { address, length })?;
        let offset = usize::try_from(address - region.start)
            .map_err(|_| MemoryError::OutOfBounds { address, length })?;
        Ok(region.bytes[offset..offset + length].to_vec())
    }

    fn write_bytes(&mut self, address: u64, bytes: &[u8]) -> Result<(), MemoryError> {
        let length = bytes.len();
        let region = self
            .regions
            .iter_mut()
            .find(|region| region.contains_range(address, length))
            .ok_or(MemoryError::OutOfBounds { address, length })?;
        let offset = usize::try_from(address - region.start)
            .map_err(|_| MemoryError::OutOfBounds { address, length })?;
        region.bytes[offset..offset + length].copy_from_slice(bytes);
        Ok(())
    }
}

#[cfg(test)]
mod stage1_tests {
    use super::*;

    fn read_u64_le(buf: &[u8], offset: usize) -> u64 {
        let mut arr = [0u8; 8];
        arr.copy_from_slice(&buf[offset..offset + 8]);
        u64::from_le_bytes(arr)
    }

    fn ap(desc: u64) -> u64 {
        (desc >> 6) & 0x3
    }
    fn pxn(desc: u64) -> u64 {
        (desc >> 53) & 0x1
    }
    fn uxn(desc: u64) -> u64 {
        (desc >> 54) & 0x1
    }
    fn valid_block(desc: u64) -> bool {
        (desc & 0x1) == 1 && ((desc >> 1) & 0x1) == 0
    }
    fn valid_table(desc: u64) -> bool {
        (desc & 0x3) == 0b11
    }

    #[test]
    fn stage1_identity_tables_layout() {
        let bytes = stage1_identity_page_tables();
        assert_eq!(bytes.len(), LINUX_PAGE_TABLES_SIZE as usize);

        // L0[0] -> L1A table descriptor at base+0x1000
        let l0_0 = read_u64_le(&bytes, 0);
        assert!(valid_table(l0_0), "L0[0] must be a table descriptor");
        assert_eq!(
            l0_0 & 0x0000_FFFF_FFFF_F000,
            LINUX_PAGE_TABLES_BASE + 0x1000
        );
        // L0[1] -> L1B table descriptor at base+0x2000
        let l0_1 = read_u64_le(&bytes, 8);
        assert!(valid_table(l0_1));
        assert_eq!(
            l0_1 & 0x0000_FFFF_FFFF_F000,
            LINUX_PAGE_TABLES_BASE + 0x2000
        );

        // L1A[0] must be a TABLE descriptor pointing at the L2 sub-table.
        let l1a_0 = read_u64_le(&bytes, 0x1000);
        assert!(valid_table(l1a_0), "L1A[0] must be a table descriptor");
        assert_eq!(
            l1a_0 & 0x0000_FFFF_FFFF_F000,
            LINUX_PAGE_TABLES_BASE + 0x3000,
            "L1A[0] must point at the L2 sub-table"
        );

        // L1A[1..511] must be USER 1 GiB BLOCK descriptors:
        //   AP=01, PXN=1, UXN=0 (FEAT_PAN3-safe user mapping).
        for index in 1..512usize {
            let d = read_u64_le(&bytes, 0x1000 + index * 8);
            assert!(valid_block(d), "L1A[{}] must be a block", index);
            assert_eq!(ap(d), 0b01, "L1A[{}] AP must be 01", index);
            assert_eq!(pxn(d), 1, "L1A[{}] PXN must be 1", index);
            assert_eq!(uxn(d), 0, "L1A[{}] UXN must be 0", index);
            let expected_pa = (index as u64) << 30;
            assert_eq!(
                d & 0x0000_FFFF_C000_0000,
                expected_pa & 0x0000_FFFF_C000_0000,
                "L1A[{}] PA mismatch",
                index
            );
        }

        // L1B[0..511] all user 1 GiB blocks.
        for index in 0..512usize {
            let d = read_u64_le(&bytes, 0x2000 + index * 8);
            assert!(valid_block(d), "L1B[{}] must be a block", index);
            assert_eq!(ap(d), 0b01);
            assert_eq!(pxn(d), 1);
            assert_eq!(uxn(d), 0);
            let expected_pa = ((index as u64) + 512) << 30;
            assert_eq!(d & 0x0000_FFFF_C000_0000, expected_pa & 0x0000_FFFF_C000_0000);
        }

        // L2[0] is the KERNEL 2 MiB block (AP=00, PXN=0, UXN=1) covering 0..2 MiB.
        let l2_0 = read_u64_le(&bytes, 0x3000);
        assert!(valid_block(l2_0), "L2[0] must be a block");
        assert_eq!(ap(l2_0), 0b00, "L2[0] kernel block must use AP=00");
        assert_eq!(pxn(l2_0), 0, "L2[0] PXN must be 0 (EL1 fetches trampoline)");
        assert_eq!(uxn(l2_0), 1, "L2[0] UXN must be 1 (EL0 cannot fetch kernel)");
        assert_eq!(l2_0 & 0x0000_FFFF_FFE0_0000, 0);

        // L2[1..511] user 2 MiB blocks covering 2 MiB..1 GiB.
        for index in 1..512usize {
            let d = read_u64_le(&bytes, 0x3000 + index * 8);
            assert!(valid_block(d), "L2[{}] must be a block", index);
            assert_eq!(ap(d), 0b01);
            assert_eq!(pxn(d), 1);
            assert_eq!(uxn(d), 0);
            let expected_pa = (index as u64) << 21;
            assert_eq!(d & 0x0000_FFFF_FFE0_0000, expected_pa & 0x0000_FFFF_FFE0_0000);
        }

        // No block descriptor may have RES0 bits set in the block's PA gap.
        for (offset_base, shift) in
            [(0x1000usize, 30u64), (0x2000usize, 30u64), (0x3000usize, 21u64)]
        {
            for index in 0..512usize {
                let d = read_u64_le(&bytes, offset_base + index * 8);
                if !valid_block(d) {
                    continue;
                }
                let res0_mask = ((1u64 << shift) - 1) & !0xFFFu64;
                assert_eq!(
                    d & res0_mask,
                    0,
                    "block @ {:#x} has RES0 bits set: {:#x}",
                    offset_base + index * 8,
                    d
                );
            }
        }
    }
}

