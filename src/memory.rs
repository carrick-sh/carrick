use std::fs;
use std::path::Path;

use crate::dispatch::{GuestMemory, MemoryError};
use crate::elf::{ElfInspectError, LoadPlan, SegmentPerms, plan_elf_load, plan_elf_load_bytes};
use crate::linux_abi::{
    LINUX_AT_BASE, LINUX_AT_ENTRY, LINUX_AT_NULL, LINUX_AT_PAGESZ, LINUX_AT_PHDR, LINUX_AT_PHENT,
    LINUX_AT_PHNUM, LINUX_PAGE_SIZE, LinuxAuxvEntry,
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
pub const LINUX_HEAP_BASE: u64 = 0x40_0000_0000; // 256 GiB
pub const LINUX_HEAP_SIZE: u64 = 4 * 1024 * 1024;
pub const LINUX_MMAP_BASE: u64 = 0x60_0000_0000; // 384 GiB
pub const LINUX_MMAP_SIZE: u64 = 16 * 1024 * 1024;
pub const LINUX_INTERPRETER_BASE: u64 = 0x80_0000_0000; // 512 GiB
pub const LINUX_STACK_TOP: u64 = 0xff_ffff_0000; // just under 1 TiB
pub const LINUX_STACK_SIZE: u64 = 1024 * 1024;

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AddressSpace {
    entry: u64,
    regions: Vec<MemoryRegion>,
    initial_stack_pointer: Option<u64>,
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
            ..
        } = self;
        let argv = argv.into_iter().collect::<Vec<_>>();
        let env = env.into_iter().collect::<Vec<_>>();
        let (region, stack_pointer) =
            build_linux_initial_stack(argv, env, &linux_auxv, stack_top, stack_size)?;
        let mut image = Self::from_regions(entry, regions.into_iter().chain([region]).collect())?;
        image.initial_stack_pointer = Some(stack_pointer);
        image.linux_auxv = linux_auxv;
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
        bytes[auxv_offset..auxv_offset + core::mem::size_of::<LinuxAuxvEntry>()]
            .copy_from_slice(entry.as_bytes());
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
    let bytes_len = usize::try_from(size).map_err(|_| AddressSpaceError::RegionTooLarge(size))?;
    let end = start
        .checked_add(size)
        .ok_or(AddressSpaceError::RegionOverflow { start, size })?;
    Ok(MemoryRegion {
        start,
        end,
        perms,
        bytes: vec![0; bytes_len],
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
    auxv.push(LinuxAuxvEntry::new(LINUX_AT_ENTRY, plan.entry));
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
