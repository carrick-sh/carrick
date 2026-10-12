//! Host-side ELF description for the guest-owned x86 initial MM editor.
//! The parser and stack serializer are the same ones used by the ARM image
//! path. This module supplies no page-table or physical-frame authority.

use crate::elf::{ElfProgram, ElfType, LoadPlan, Machine, SegmentPerms};

#[derive(::core::fmt::Debug, ::thiserror::Error)]
pub enum X86InitialImageError {
    #[error("x86 ELF load plan has wrong machine: {0:?}")]
    InvalidMachine(Machine),
    #[error("x86 ELF program headers are not mapped in a PT_LOAD segment")]
    MissingProgramHeaders,
    #[error("x86 ELF entry is outside executable PT_LOAD memory")]
    InvalidEntry,
    #[error("x86 image has an overlapping or non-user page range")]
    InvalidRegion,
}

/// An ELF load description. The guest MM owner builds the stack, allocates
/// frames, writes descriptors and publishes its exact edit receipts.
#[derive(::core::fmt::Debug)]
pub struct X86InitialImage<'a> {
    /// Initial RIP, at the interpreter when PT_INTERP is present.
    pub entry: u64,
    /// Executable entry for AT_ENTRY, independent of initial RIP.
    pub executable_entry: u64,
    pub interpreter_base: u64,
    pub phdr: u64,
    pub phent: u16,
    pub phnum: u16,
    pub regions: Vec<X86InitialRegion<'a>>,
    /// Executable regions precede interpreter regions; only these set brk.
    pub executable_region_count: usize,
}

/// A page-rounded PT_LOAD description borrowing only initialized file bytes.
/// The guest's zeroed frame grants supply every BSS and padding byte.
#[derive(::core::fmt::Debug)]
pub struct X86InitialRegion<'a> {
    pub start: u64,
    pub end: u64,
    pub initialized_offset: u64,
    pub file_bytes: &'a [u8],
    pub perms: SegmentPerms,
}

/// Describe the executable and interpreter from the shared ELF loader.
/// The host may read the ELF file, but no host code creates the task stack or
/// writes a guest page-table descriptor.
pub fn prepare_x86_elf<'a>(
    program: &'a ElfProgram<'_>,
) -> Result<X86InitialImage<'a>, X86InitialImageError> {
    let plan = &program.executable;
    let Some(phdr) = plan.program_header_address else {
        return Err(X86InitialImageError::MissingProgramHeaders);
    };
    if plan.program_header_count == 0 {
        return Err(X86InitialImageError::MissingProgramHeaders);
    }
    let phdr_end = phdr
        .checked_add(
            u64::from(plan.program_header_entry_size) * u64::from(plan.program_header_count),
        )
        .ok_or(X86InitialImageError::MissingProgramHeaders)?;
    if !plan.segments.iter().any(|segment| {
        segment.virtual_address <= phdr
            && segment
                .virtual_address
                .checked_add(segment.file_size)
                .is_some_and(|end| phdr_end <= end)
    }) {
        return Err(X86InitialImageError::MissingProgramHeaders);
    }
    let mut regions = image_regions(program.executable_bytes, plan)?;
    let executable_region_count = regions.len();
    if let Some(interpreter) = &program.interpreter {
        regions.extend(image_regions(&interpreter.bytes, &interpreter.plan)?);
    }
    // Check the union without losing executable/interpreter identity.
    let mut ordered: Vec<_> = regions.iter().collect();
    ordered.sort_by_key(|region| region.start);
    if ordered.windows(2).any(|pair| pair[0].end > pair[1].start) {
        return Err(X86InitialImageError::InvalidRegion);
    }
    Ok(X86InitialImage {
        entry: program.entry(),
        executable_entry: plan.entry,
        interpreter_base: program.interpreter_base().unwrap_or(0),
        phdr,
        phent: plan.program_header_entry_size,
        phnum: plan.program_header_count,
        regions,
        executable_region_count,
    })
}

fn image_regions<'a>(
    elf: &'a [u8],
    plan: &LoadPlan,
) -> Result<Vec<X86InitialRegion<'a>>, X86InitialImageError> {
    const X86_USER_END: u64 = 0x0000_8000_0000_0000;
    if plan.machine != Machine::X86_64 {
        return Err(X86InitialImageError::InvalidMachine(plan.machine));
    }
    if !matches!(plan.e_type, ElfType::Exec | ElfType::Dyn)
        || !plan.segments.iter().any(|segment| {
            segment.perms.execute
                && segment.virtual_address <= plan.entry
                && segment
                    .virtual_address
                    .checked_add(segment.memory_size)
                    .is_some_and(|end| plan.entry < end)
        })
    {
        return Err(X86InitialImageError::InvalidEntry);
    }
    let mut regions = Vec::with_capacity(plan.segments.len());
    for segment in &plan.segments {
        let start = segment.virtual_address & !4095;
        let end = segment
            .virtual_address
            .checked_add(segment.memory_size)
            .and_then(|end| end.checked_add(4095))
            .map(|end| end & !4095)
            .ok_or(X86InitialImageError::InvalidRegion)?;
        let file_start = usize::try_from(segment.file_offset)
            .map_err(|_| X86InitialImageError::InvalidRegion)?;
        let file_len =
            usize::try_from(segment.file_size).map_err(|_| X86InitialImageError::InvalidRegion)?;
        let file_end = file_start
            .checked_add(file_len)
            .ok_or(X86InitialImageError::InvalidRegion)?;
        let file_bytes = elf
            .get(file_start..file_end)
            .ok_or(X86InitialImageError::InvalidRegion)?;
        if segment.file_size > segment.memory_size {
            return Err(X86InitialImageError::InvalidRegion);
        }
        regions.push(X86InitialRegion {
            start,
            end,
            initialized_offset: segment.virtual_address - start,
            file_bytes,
            perms: segment.perms,
        });
    }
    regions.sort_by_key(|region| region.start);
    let mut previous_end = 0;
    for region in &regions {
        if region.start < 4096
            || region.start & 4095 != 0
            || region.end & 4095 != 0
            || region.end > X86_USER_END
            || region.start < previous_end
            || region.start >= region.end
        {
            return Err(X86InitialImageError::InvalidRegion);
        }
        previous_end = region.end;
    }
    Ok(regions)
}
