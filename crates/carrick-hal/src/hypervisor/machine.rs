//! #1236 R1 spike: one stopped machine, one vCPU, and exact-extent stage-2
//! edits. The production carriers still use the existing HAL traits and HVF
//! inventory transactions.

use std::collections::BTreeMap;
use std::ptr::NonNull;

use carrick_guest_arch::FrameGpa;
use carrick_softcpu_aarch64::dispatch::{self, ExecuteBlock, Report, Stop};
use carrick_softcpu_aarch64::handler::{
    CodeGeneration, Event, ExclusiveMonitor, GuestMemory, MemoryFault,
};
use carrick_softcpu_aarch64::state::{CpuState, VirtualAddress};
use carrick_softcpu_aarch64::translate::BlockLimits;
use carrick_softmmu::{ExtentRecord, ExtentTable, OwnerGeneration, PAGE_SIZE_4K};

use crate::error::OsError;
pub use crate::error::{MemPerms, Reg, SysReg};
pub use crate::hypervisor::VcpuExit;

pub enum HvVm {
    #[cfg(target_os = "macos")]
    Hvf(applevisor::vm::VirtualMachineInstance<applevisor::vm::GicDisabled>),
    Soft(SoftStage2),
}

pub enum HvVcpu<'a, X: ExecuteBlock> {
    #[cfg(target_os = "macos")]
    Hvf(applevisor::vcpu::Vcpu),
    Soft {
        cpu: &'a mut CpuState,
        executor: &'a mut X,
        monitor: &'a mut ExclusiveMonitor,
        report: &'a mut Option<Report<X::Error>>,
    },
}

impl HvVm {
    pub fn soft() -> Result<Self, OsError> {
        Ok(Self::Soft(SoftStage2 {
            extents: ExtentTable::new().map_err(|e| refusal(format!("{e:?}")))?,
            backing: BTreeMap::new(),
            dirty_code: BTreeMap::new(),
        }))
    }

    /// Publish a caller-owned mapping.
    ///
    /// # Safety
    /// The backing must stay initialized, stable, live and accessible until
    /// unmap or machine destruction. The caller excludes concurrent accesses
    /// while the machine runs. Soft mappings must have disjoint host backing
    /// so that every in-run store invalidates the correct code generation.
    pub unsafe fn map_memory(
        &mut self,
        base: FrameGpa,
        host: NonNull<u8>,
        len: usize,
        perms: MemPerms,
    ) -> Result<(), OsError> {
        match self {
            #[cfg(target_os = "macos")]
            Self::Hvf(_) => {
                use applevisor_sys as ffi;
                let flags = u64::from(perms.read) * ffi::HV_MEMORY_READ
                    | u64::from(perms.write) * ffi::HV_MEMORY_WRITE
                    | u64::from(perms.exec) * ffi::HV_MEMORY_EXEC;
                // SAFETY: the caller retains the original backing.
                let result =
                    unsafe { ffi::hv_vm_map(host.as_ptr().cast(), base.raw(), len, flags) };
                hvf_result(result)
            }
            Self::Soft(memory) => {
                if !memory.extents.install(ExtentRecord::new(
                    base,
                    len as u64,
                    OwnerGeneration::FIRST,
                )) {
                    return Err(refusal("soft stage-2 extent refused"));
                }
                memory.backing.insert(base, Backing { host, perms });
                Ok(())
            }
        }
    }

    /// Retire a previously mapped exact extent while the vCPU is stopped.
    pub fn unmap_memory(&mut self, base: FrameGpa, len: usize) -> Result<(), OsError> {
        match self {
            #[cfg(target_os = "macos")]
            Self::Hvf(_) => {
                // SAFETY: this VM owns the stage-2 mapping.
                hvf_result(unsafe { applevisor_sys::hv_vm_unmap(base.raw(), len) })
            }
            Self::Soft(memory) => {
                let Some(record) = memory.extents.lookup_span(base.raw(), len as u64) else {
                    return Err(refusal("soft stage-2 unmap found no extent"));
                };
                if record.base != base || record.len_bytes != len as u64 {
                    return Err(refusal("soft stage-2 unmap requires an exact extent"));
                }
                let retirement = memory
                    .extents
                    .remove(base, None)
                    .map_err(|e| refusal(format!("{e:?}")))?
                    .ok_or_else(|| refusal("soft stage-2 extent disappeared"))?;
                // No TLB is registered. The dispatcher's block cache is scoped
                // to a run and already dropped before any edit can enter.
                let completion = retirement
                    .pending
                    .try_complete()
                    .map_err(|_| refusal("unexpected soft stage-2 retirement wait"))?;
                memory.extents.reclaim(&completion);
                memory.backing.remove(&base);
                memory
                    .dirty_code
                    .retain(|frame, _| frame.raw() < base.raw() || frame.raw() >= record.end_gpa());
                Ok(())
            }
        }
    }
}

impl<X: ExecuteBlock> HvVcpu<'_, X>
where
    X::Error: std::fmt::Debug,
{
    pub fn run(&mut self, machine: &mut HvVm, budget: u64) -> Result<VcpuExit, OsError> {
        match (self, machine) {
            #[cfg(target_os = "macos")]
            (Self::Hvf(cpu), HvVm::Hvf(_)) => {
                use applevisor::vcpu::ExitReason;
                cpu.run().map_err(|e| refusal(e.to_string()))?;
                let exit = cpu.get_exit_info();
                match exit.reason {
                    ExitReason::CANCELED => Ok(VcpuExit::Kicked),
                    ExitReason::EXCEPTION => Ok(VcpuExit::Exception {
                        syndrome: exit.exception.syndrome,
                        far: exit.exception.virtual_address,
                    }),
                    reason => Err(refusal(format!("HVF spike exit: {reason:?}"))),
                }
            }
            (
                Self::Soft {
                    cpu,
                    executor,
                    monitor,
                    report,
                },
                HvVm::Soft(memory),
            ) => {
                let run = dispatch::run(
                    cpu,
                    monitor,
                    memory,
                    *executor,
                    BlockLimits::default(),
                    budget,
                );
                let exit = match &run.stop {
                    Stop::Event {
                        event: Event::ProviderExit(exit),
                        ..
                    } => Ok(VcpuExit::Exception {
                        syndrome: (crate::aarch64::AARCH64_HVC_EXCEPTION_CLASS << 26)
                            | (1 << 25)
                            | u64::from(exit.immediate.value()),
                        far: 0,
                    }),
                    _ => Err(refusal(run.to_string())),
                };
                **report = Some(run);
                exit
            }
            #[cfg(target_os = "macos")]
            _ => Err(refusal("VM and vCPU machine variants differ")),
        }
    }
}

#[cfg(target_os = "macos")]
fn hvf_result(result: applevisor_sys::hv_return_t) -> Result<(), OsError> {
    if result == applevisor_sys::hv_error_t::HV_SUCCESS as i32 {
        Ok(())
    } else {
        Err(refusal(format!(
            "HVF stage-2 operation failed: {result:#x}"
        )))
    }
}

fn refusal(context: impl Into<String>) -> OsError {
    OsError {
        errno: 0,
        context: context.into(),
    }
}

struct Backing {
    host: NonNull<u8>,
    perms: MemPerms,
}

pub struct SoftStage2 {
    extents: ExtentTable,
    backing: BTreeMap<FrameGpa, Backing>,
    dirty_code: BTreeMap<FrameGpa, u64>,
}

impl SoftStage2 {
    fn resolve(
        &self,
        address: VirtualAddress,
        len: usize,
        permits: impl FnOnce(MemPerms) -> bool,
    ) -> Result<*mut u8, MemoryFault> {
        let fault = MemoryFault { address };
        let record = self
            .extents
            .lookup_span(address.0, len as u64)
            .ok_or(fault)?;
        let backing = self
            .backing
            .get(&record.base)
            .filter(|b| permits(b.perms))
            .ok_or(fault)?;
        Ok(backing
            .host
            .as_ptr()
            .wrapping_add((address.0 - record.base.raw()) as usize))
    }

    fn copy_out(
        &self,
        address: VirtualAddress,
        bytes: &mut [u8],
        permits: impl FnOnce(MemPerms) -> bool,
    ) -> Result<(), MemoryFault> {
        let src = self.resolve(address, bytes.len(), permits)?;
        // SAFETY: resolve authenticated the full span under the caller's
        // stopped-machine backing contract. The dispatcher supplies a local buffer.
        unsafe { src.copy_to_nonoverlapping(bytes.as_mut_ptr(), bytes.len()) };
        Ok(())
    }
}

impl GuestMemory for SoftStage2 {
    fn read(&mut self, address: VirtualAddress, bytes: &mut [u8]) -> Result<(), MemoryFault> {
        self.copy_out(address, bytes, |p| p.read)
    }

    fn fetch(&mut self, address: VirtualAddress, bytes: &mut [u8]) -> Result<(), MemoryFault> {
        self.copy_out(address, bytes, |p| p.exec)
    }

    fn write(&mut self, address: VirtualAddress, bytes: &[u8]) -> Result<(), MemoryFault> {
        let dst = self.resolve(address, bytes.len(), |p| p.write)?;
        if !bytes.is_empty() {
            let mask = !(PAGE_SIZE_4K - 1);
            let last = address.0 + bytes.len() as u64 - 1;
            for frame in ((address.0 & mask)..=(last & mask)).step_by(PAGE_SIZE_4K as usize) {
                let revision = self.dirty_code.entry(FrameGpa::new(frame)).or_default();
                *revision = revision.checked_add(1).ok_or(MemoryFault { address })?;
            }
        }
        // SAFETY: as in copy_out, the dispatcher buffer and authenticated
        // backing are disjoint. No peer accesses the backing during the copy.
        unsafe { dst.copy_from_nonoverlapping(bytes.as_ptr(), bytes.len()) };
        Ok(())
    }

    fn code_generation(&self, frame: FrameGpa) -> Option<CodeGeneration> {
        self.resolve(VirtualAddress(frame.raw()), PAGE_SIZE_4K as usize, |p| {
            p.exec
        })
        .ok()?;
        Some(CodeGeneration(*self.dirty_code.get(&frame).unwrap_or(&0)))
    }
}
