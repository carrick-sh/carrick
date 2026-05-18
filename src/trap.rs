use crate::dispatch::{Aarch64SyscallFrame, GuestMemory, MemoryError};
use crate::elf::SegmentPerms;
use crate::memory::AddressSpace;
use serde::Serialize;
use thiserror::Error;

pub const HVF_PAGE_SIZE: u64 = 0x4000;
pub const AARCH64_SVC_EXCEPTION_CLASS: u64 = 0x15;
const AARCH64_EXCEPTION_CLASS_SHIFT: u64 = 26;
const AARCH64_EXCEPTION_CLASS_MASK: u64 = 0x3f;

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
    #[error("Hypervisor.framework exited for an unexpected reason: {reason}")]
    UnexpectedExit { reason: String },
    #[error(
        "guest exception is not an AArch64 SVC trap: syndrome=0x{syndrome:x}, virtual_address=0x{virtual_address:x}, physical_address=0x{physical_address:x}"
    )]
    UnexpectedException {
        syndrome: u64,
        virtual_address: u64,
        physical_address: u64,
    },
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
    mappings: Vec<HvfMappedRegion>,
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
#[derive(Debug)]
struct HvfMappedRegion {
    start: u64,
    end: u64,
    memory: applevisor::memory::Memory,
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

    pub fn run_until_syscall(&mut self) -> Result<Aarch64SyscallFrame, TrapError> {
        self.inner.run_until_syscall()
    }

    pub fn complete_syscall(&mut self, return_value: i64) -> Result<(), TrapError> {
        self.inner.complete_syscall(return_value)
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
            self.inner.mappings.push(HvfMappedRegion {
                start: mapping.guest_start,
                end: mapping.guest_start.checked_add(mapping.mapped_size).ok_or(
                    TrapError::MappingOverflow {
                        guest_start: mapping.guest_start,
                        mapped_size: mapping.mapped_size,
                    },
                )?,
                memory,
            });
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

    fn run_until_syscall(&mut self) -> Result<Aarch64SyscallFrame, TrapError> {
        use applevisor::prelude::*;

        self.vcpu.run().map_err(hvf_error)?;
        let exit = self.vcpu.get_exit_info();
        if exit.reason != ExitReason::EXCEPTION {
            return Err(TrapError::UnexpectedExit {
                reason: format!("{:?}", exit.reason),
            });
        }

        let exception = exit.exception;
        if !is_aarch64_svc_exception(exception.syndrome) {
            return Err(TrapError::UnexpectedException {
                syndrome: exception.syndrome,
                virtual_address: exception.virtual_address,
                physical_address: exception.physical_address,
            });
        }

        Ok(Aarch64SyscallFrame {
            x0: self.vcpu.get_reg(Reg::X0).map_err(hvf_error)?,
            x1: self.vcpu.get_reg(Reg::X1).map_err(hvf_error)?,
            x2: self.vcpu.get_reg(Reg::X2).map_err(hvf_error)?,
            x3: self.vcpu.get_reg(Reg::X3).map_err(hvf_error)?,
            x4: self.vcpu.get_reg(Reg::X4).map_err(hvf_error)?,
            x5: self.vcpu.get_reg(Reg::X5).map_err(hvf_error)?,
            x8: self.vcpu.get_reg(Reg::X8).map_err(hvf_error)?,
        })
    }

    fn complete_syscall(&mut self, return_value: i64) -> Result<(), TrapError> {
        use applevisor::prelude::*;

        self.vcpu
            .set_reg(Reg::X0, return_value as u64)
            .map_err(hvf_error)
    }

    fn read_guest_bytes(&self, address: u64, length: usize) -> Result<Vec<u8>, MemoryError> {
        let Some(mapping) = self.mapping_for_range(address, length) else {
            return Err(MemoryError::OutOfBounds { address, length });
        };
        let mut bytes = vec![0; length];
        mapping
            .memory
            .read(address, &mut bytes)
            .map_err(|_| MemoryError::OutOfBounds { address, length })?;
        Ok(bytes)
    }

    fn write_guest_bytes(&mut self, address: u64, bytes: &[u8]) -> Result<(), MemoryError> {
        let length = bytes.len();
        let Some(mapping) = self.mapping_for_range_mut(address, length) else {
            return Err(MemoryError::OutOfBounds { address, length });
        };
        mapping
            .memory
            .write(address, bytes)
            .map_err(|_| MemoryError::OutOfBounds { address, length })
    }

    fn mapping_for_range(&self, address: u64, length: usize) -> Option<&HvfMappedRegion> {
        self.mappings
            .iter()
            .find(|mapping| mapping.contains_range(address, length))
    }

    fn mapping_for_range_mut(
        &mut self,
        address: u64,
        length: usize,
    ) -> Option<&mut HvfMappedRegion> {
        self.mappings
            .iter_mut()
            .find(|mapping| mapping.contains_range(address, length))
    }
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
impl HvfMappedRegion {
    fn contains_range(&self, address: u64, length: usize) -> bool {
        let Ok(length) = u64::try_from(length) else {
            return false;
        };
        let Some(end) = address.checked_add(length) else {
            return false;
        };
        address >= self.start && end <= self.end
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

    fn run_until_syscall(&mut self) -> Result<Aarch64SyscallFrame, TrapError> {
        Err(TrapError::UnsupportedPlatform)
    }

    fn complete_syscall(&mut self, _: i64) -> Result<(), TrapError> {
        Err(TrapError::UnsupportedPlatform)
    }

    fn read_guest_bytes(&self, address: u64, length: usize) -> Result<Vec<u8>, MemoryError> {
        Err(MemoryError::OutOfBounds { address, length })
    }

    fn write_guest_bytes(&mut self, address: u64, bytes: &[u8]) -> Result<(), MemoryError> {
        Err(MemoryError::OutOfBounds {
            address,
            length: bytes.len(),
        })
    }
}

impl GuestMemory for HvfTrapEngine {
    fn read_bytes(&self, address: u64, length: usize) -> Result<Vec<u8>, MemoryError> {
        self.inner.read_guest_bytes(address, length)
    }

    fn write_bytes(&mut self, address: u64, bytes: &[u8]) -> Result<(), MemoryError> {
        self.inner.write_guest_bytes(address, bytes)
    }
}

pub fn aarch64_exception_class(syndrome: u64) -> u64 {
    (syndrome >> AARCH64_EXCEPTION_CLASS_SHIFT) & AARCH64_EXCEPTION_CLASS_MASK
}

pub fn is_aarch64_svc_exception(syndrome: u64) -> bool {
    aarch64_exception_class(syndrome) == AARCH64_SVC_EXCEPTION_CLASS
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
