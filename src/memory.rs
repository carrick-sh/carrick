use std::fs;
use std::path::Path;

use crate::dispatch::{GuestMemory, MemoryError};
use crate::elf::{ElfInspectError, SegmentPerms, plan_elf_load, plan_elf_load_bytes};
use serde::Serialize;
use thiserror::Error;

pub const LINUX_STACK_TOP: u64 = 0x7fff_ffff_0000;
pub const LINUX_STACK_SIZE: u64 = 1024 * 1024;

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AddressSpace {
    entry: u64,
    regions: Vec<MemoryRegion>,
    initial_stack_pointer: Option<u64>,
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

    fn load_elf_segments(
        file: &[u8],
        plan: crate::elf::LoadPlan,
    ) -> Result<Self, AddressSpaceError> {
        let mut regions = Vec::with_capacity(plan.segments.len());

        for segment in plan.segments {
            if segment.file_size > segment.memory_size {
                return Err(AddressSpaceError::FileLargerThanMemory {
                    virtual_address: segment.virtual_address,
                    file_size: segment.file_size,
                    memory_size: segment.memory_size,
                });
            }

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
            let file_end =
                file_offset
                    .checked_add(file_size)
                    .ok_or(AddressSpaceError::SegmentBeyondFile {
                        virtual_address: segment.virtual_address,
                    })?;
            if file_end > file.len() {
                return Err(AddressSpaceError::SegmentBeyondFile {
                    virtual_address: segment.virtual_address,
                });
            }

            let memory_size = usize::try_from(segment.memory_size)
                .map_err(|_| AddressSpaceError::RegionTooLarge(segment.memory_size))?;
            let mut bytes = vec![0; memory_size];
            bytes[..file_size].copy_from_slice(&file[file_offset..file_end]);

            regions.push(MemoryRegion {
                start: segment.virtual_address,
                end: segment
                    .virtual_address
                    .checked_add(segment.memory_size)
                    .ok_or(AddressSpaceError::RegionOverflow {
                        start: segment.virtual_address,
                        size: segment.memory_size,
                    })?,
                perms: segment.perms,
                bytes,
            });
        }

        Self::from_regions(plan.entry, regions)
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
        let argv = argv.into_iter().collect::<Vec<_>>();
        let env = env.into_iter().collect::<Vec<_>>();
        let (region, stack_pointer) = build_linux_initial_stack(argv, env, stack_top, stack_size)?;
        let mut image = Self::from_regions(
            self.entry,
            self.regions.into_iter().chain([region]).collect(),
        )?;
        image.initial_stack_pointer = Some(stack_pointer);
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

    let mut entries = Vec::with_capacity(1 + argv_addrs.len() + 1 + env_addrs.len() + 1 + 2);
    entries.push(argv_addrs.len() as u64);
    entries.extend(argv_addrs);
    entries.push(0);
    entries.extend(env_addrs);
    entries.push(0);
    entries.push(0);
    entries.push(0);

    let entries_len = entries
        .len()
        .checked_mul(8)
        .ok_or(AddressSpaceError::InitialStackTooLarge { stack_size })?;
    if cursor < entries_len {
        return Err(AddressSpaceError::InitialStackTooLarge { stack_size });
    }
    let stack_pointer_offset = align_down_usize(cursor - entries_len, 16);
    for (index, entry) in entries.into_iter().enumerate() {
        let offset = stack_pointer_offset + index * 8;
        bytes[offset..offset + 8].copy_from_slice(&entry.to_le_bytes());
    }

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
