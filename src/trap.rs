use crate::elf::SegmentPerms;
use crate::memory::AddressSpace;
use serde::Serialize;
use thiserror::Error;

pub const HVF_PAGE_SIZE: u64 = 0x4000;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TrapBackend {
    HypervisorFramework,
}

#[derive(Debug, Error)]
pub enum TrapError {
    #[error("Hypervisor.framework syscall trapping is only available on macOS/aarch64")]
    UnsupportedPlatform,
    #[error("Hypervisor.framework operation failed: {0}")]
    Hypervisor(String),
    #[error("guest mapping size {0} does not fit this host")]
    MappingTooLarge(u64),
    #[error("guest mapping at 0x{guest_start:x} with size {mapped_size} overflows")]
    MappingOverflow { guest_start: u64, mapped_size: u64 },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct TrapCapabilities {
    pub backend: TrapBackend,
    pub available_on_this_host: bool,
    pub implemented: bool,
}

pub fn hvf_capabilities() -> TrapCapabilities {
    TrapCapabilities {
        backend: TrapBackend::HypervisorFramework,
        available_on_this_host: cfg!(all(target_os = "macos", target_arch = "aarch64")),
        implemented: cfg!(all(target_os = "macos", target_arch = "aarch64")),
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct GuestMappingPlan {
    pub entry: u64,
    pub mappings: Vec<GuestMapping>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct GuestMapping {
    pub guest_start: u64,
    pub mapped_size: u64,
    pub offset_in_mapping: u64,
    pub payload_size: u64,
    pub perms: SegmentPerms,
    #[serde(skip)]
    image: Vec<u8>,
}

impl GuestMappingPlan {
    pub fn from_address_space(address_space: &AddressSpace) -> Result<Self, TrapError> {
        let mut mappings = Vec::with_capacity(address_space.regions().len());
        for region in address_space.regions() {
            let guest_start = align_down(region.start, HVF_PAGE_SIZE);
            let guest_end = align_up(region.end, HVF_PAGE_SIZE)?;
            let mapped_size =
                guest_end
                    .checked_sub(guest_start)
                    .ok_or(TrapError::MappingOverflow {
                        guest_start,
                        mapped_size: 0,
                    })?;
            let mapped_len = usize::try_from(mapped_size)
                .map_err(|_| TrapError::MappingTooLarge(mapped_size))?;
            let offset_in_mapping = region.start - guest_start;
            let payload_offset = usize::try_from(offset_in_mapping)
                .map_err(|_| TrapError::MappingTooLarge(offset_in_mapping))?;

            let mut image = vec![0; mapped_len];
            image[payload_offset..payload_offset + region.bytes().len()]
                .copy_from_slice(region.bytes());

            mappings.push(GuestMapping {
                guest_start,
                mapped_size,
                offset_in_mapping,
                payload_size: region.bytes().len() as u64,
                perms: region.perms,
                image,
            });
        }

        Ok(Self {
            entry: address_space.entry(),
            mappings,
        })
    }
}

pub struct HvfTrapEngine {
    inner: HvfInner,
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
struct HvfInner {
    _vm: applevisor::vm::VirtualMachineInstance<applevisor::vm::GicDisabled>,
    vcpu: applevisor::vcpu::Vcpu,
    mappings: Vec<applevisor::memory::Memory>,
}

#[cfg(not(all(target_os = "macos", target_arch = "aarch64")))]
struct HvfInner;

impl HvfTrapEngine {
    pub fn new() -> Result<Self, TrapError> {
        if !cfg!(all(target_os = "macos", target_arch = "aarch64")) {
            return Err(TrapError::UnsupportedPlatform);
        }
        Self::new_platform()
    }

    pub fn backend(&self) -> TrapBackend {
        TrapBackend::HypervisorFramework
    }

    pub fn mapped_region_count(&self) -> usize {
        self.inner.mapped_region_count()
    }

    pub fn program_counter(&self) -> Result<u64, TrapError> {
        self.inner.program_counter()
    }

    pub fn map_address_space(
        &mut self,
        address_space: &AddressSpace,
    ) -> Result<GuestMappingPlan, TrapError> {
        let plan = GuestMappingPlan::from_address_space(address_space)?;
        self.map_plan(&plan)?;
        Ok(plan)
    }

    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    fn new_platform() -> Result<Self, TrapError> {
        use applevisor::prelude::*;

        let vm = VirtualMachine::new().map_err(hvf_error)?;
        let vcpu = vm.vcpu_create().map_err(hvf_error)?;
        Ok(Self {
            inner: HvfInner {
                _vm: vm,
                vcpu,
                mappings: Vec::new(),
            },
        })
    }

    #[cfg(not(all(target_os = "macos", target_arch = "aarch64")))]
    fn new_platform() -> Result<Self, TrapError> {
        Err(TrapError::UnsupportedPlatform)
    }

    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    fn map_plan(&mut self, plan: &GuestMappingPlan) -> Result<(), TrapError> {
        use applevisor::prelude::*;

        for mapping in &plan.mappings {
            let mut memory = self
                .inner
                ._vm
                .memory_create(
                    usize::try_from(mapping.mapped_size)
                        .map_err(|_| TrapError::MappingTooLarge(mapping.mapped_size))?,
                )
                .map_err(hvf_error)?;
            memory
                .map(mapping.guest_start, hvf_perms(mapping.perms))
                .map_err(hvf_error)?;
            memory
                .write(mapping.guest_start, &mapping.image)
                .map_err(hvf_error)?;
            self.inner.mappings.push(memory);
        }

        self.inner
            .vcpu
            .set_reg(Reg::PC, plan.entry)
            .map_err(hvf_error)?;
        Ok(())
    }

    #[cfg(not(all(target_os = "macos", target_arch = "aarch64")))]
    fn map_plan(&mut self, _: &GuestMappingPlan) -> Result<(), TrapError> {
        Err(TrapError::UnsupportedPlatform)
    }
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
impl HvfInner {
    fn mapped_region_count(&self) -> usize {
        self.mappings.len()
    }

    fn program_counter(&self) -> Result<u64, TrapError> {
        use applevisor::prelude::*;

        self.vcpu.get_reg(Reg::PC).map_err(hvf_error)
    }
}

#[cfg(not(all(target_os = "macos", target_arch = "aarch64")))]
impl HvfInner {
    fn mapped_region_count(&self) -> usize {
        0
    }

    fn program_counter(&self) -> Result<u64, TrapError> {
        Err(TrapError::UnsupportedPlatform)
    }
}

fn align_down(value: u64, alignment: u64) -> u64 {
    value / alignment * alignment
}

fn align_up(value: u64, alignment: u64) -> Result<u64, TrapError> {
    let remainder = value % alignment;
    if remainder == 0 {
        Ok(value)
    } else {
        value
            .checked_add(alignment - remainder)
            .ok_or(TrapError::MappingOverflow {
                guest_start: value,
                mapped_size: alignment,
            })
    }
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
fn hvf_perms(perms: SegmentPerms) -> applevisor::memory::MemPerms {
    use applevisor::memory::MemPerms;

    match (perms.read, perms.write, perms.execute) {
        (false, false, false) => MemPerms::None,
        (true, false, false) => MemPerms::Read,
        (false, true, false) => MemPerms::Write,
        (false, false, true) => MemPerms::Exec,
        (true, true, false) => MemPerms::ReadWrite,
        (true, false, true) => MemPerms::ReadExec,
        (false, true, true) => MemPerms::WriteExec,
        (true, true, true) => MemPerms::ReadWriteExec,
    }
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
fn hvf_error(error: applevisor::error::HypervisorError) -> TrapError {
    TrapError::Hypervisor(error.to_string())
}
