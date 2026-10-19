//! KVM realization of carrier physical custody and the multi-vCPU machine.
use crate::{KvmVcpu, KvmVm};
use carrick_hal::OsError;

pub use carrick_el1_abi::GuestMmuPublication;
pub use carrick_guest_arch::{AddressContext, FrameGpa, RootGpa};
pub use carrick_mmu_core::x86::descriptor_txn::{
    Access, DescriptorOp, DescriptorTxn, DescriptorTxnId, InlineJournal, LeafSize, PAGE, PageSpan,
    Permissions, execute_descriptor_txn,
};
pub use carrick_x86_cpl0_host::carrier_memory::{
    BackingExtent, BackingHandle, BackingIdentity, CarrierMemoryIo, CarrierMemoryRegion,
    InheritedFrameSelectionError, Invalidation, InventoryRetirement, InventoryTransaction,
    MemoryError, PreparedBacking, ShootdownPlan, TranslationDrain,
};
pub use std::num::NonZeroU64;
pub use std::sync::Arc;

pub type CarrierMemory = carrick_x86_cpl0_host::carrier_memory::CarrierMemory<KvmVm>;

fn error(msg: impl Into<String>) -> MemoryError {
    MemoryError(msg.into())
}

impl CarrierMemoryIo for KvmVm {
    fn carrier_slot_limit(&self) -> Result<u32, OsError> {
        self.carrier_slot_limit()
    }

    unsafe fn set_user_memory_region(&self, region: CarrierMemoryRegion) -> Result<(), OsError> {
        let kvm_region = kvm_bindings::kvm_userspace_memory_region {
            slot: region.slot,
            flags: region.flags,
            guest_phys_addr: region.guest_phys_addr,
            memory_size: region.memory_size,
            userspace_addr: region.userspace_addr,
        };
        unsafe { self.carrier_set_region(kvm_region) }
    }

    fn signal_msi(&self, address_lo: u32, data: u32) -> Result<(), OsError> {
        let sent = self
            .vm
            .signal_msi(kvm_bindings::kvm_msi {
                address_lo,
                data,
                ..Default::default()
            })
            .map_err(|e| OsError::new(e.to_string()))?;
        if sent > 0 {
            Ok(())
        } else {
            Err(OsError::new("KVM MSI delivery was blocked"))
        }
    }
}

/// One KVM VM and its retained physical backing for a bounded set of vCPUs.
/// vCPU handles drop before the memory owner and its VM. All CPUs issued by
/// this owner see the same slot namespace; no standalone CPU can be attached.
pub struct CarrierMachine {
    cpus: Vec<KvmVcpu>,
    memory: CarrierMemory,
}

impl CarrierMachine {
    pub fn create_stopped(vcpu_count: usize) -> Result<Self, MemoryError> {
        let vm = KvmVm::create_empty().map_err(|e| MemoryError(e.to_string()))?;
        let memory = CarrierMemory::new(vm)?;
        Self::from_memory(memory, vcpu_count)
    }

    pub(crate) fn from_memory(
        memory: CarrierMemory,
        vcpu_count: usize,
    ) -> Result<Self, MemoryError> {
        if vcpu_count == 0 {
            return Err(MemoryError("carrier requires at least one vCPU".into()));
        }
        let mut cpus = Vec::new();
        for _ in 0..vcpu_count {
            let mut vcpu = memory
                .vm()
                .create_vcpu_on_shared_vm()
                .map_err(|e| MemoryError(e.to_string()))?;
            vcpu.enroll_carrier_census();
            cpus.push(vcpu);
        }
        Ok(Self { cpus, memory })
    }

    pub fn vcpu_count(&self) -> usize {
        self.cpus.len()
    }

    pub fn memory_mut(&mut self) -> &mut CarrierMemory {
        &mut self.memory
    }

    pub fn cpu_mut(&mut self, index: usize) -> Option<&mut KvmVcpu> {
        self.cpus.get_mut(index)
    }

    pub(crate) fn into_parts(self) -> (Vec<KvmVcpu>, CarrierMemory) {
        (self.cpus, self.memory)
    }
}

pub mod fixture;

#[cfg(test)]
#[path = "carrier_memory/tests.rs"]
mod memslot_tests;

#[cfg(test)]
mod tests {
    use super::*;
    use carrick_hal::{HvVcpu, VcpuExit};

    fn nz(n: u64) -> NonZeroU64 {
        NonZeroU64::new(n).unwrap()
    }

    #[test]
    fn three_vcpus_observe_one_carrier_backing_in_order() {
        let mut machine = CarrierMachine::create_stopped(3).unwrap();
        let mut extent = BackingExtent::private(FrameGpa::new(0), PAGE as usize).unwrap();
        // Real-mode MOV AL, [0x100]; OUT 0xe9, AL; HLT. Each KVM_RUN must
        // observe the same retained host page through its own vCPU in this VM.
        extent
            .initialize(0, &[0xa0, 0x00, 0x01, 0xe6, 0xe9, 0xf4])
            .unwrap();
        extent.initialize(0x100, b"A").unwrap();
        let backing = PreparedBacking {
            extent: Arc::new(extent),
            identity: BackingIdentity {
                frame_id: nz(1),
                mapping_id: nz(1),
                owner_generation: nz(1),
                inventory_revision: nz(1),
            },
        };
        machine.memory_mut().install(&[backing]).unwrap();
        assert_eq!(machine.memory_mut().slot_count(), 1);
        for index in 0..machine.vcpu_count() {
            let cpu = machine.cpu_mut(index).unwrap();
            let mut sregs = cpu.fd().get_sregs().unwrap();
            sregs.cs.base = 0;
            sregs.cs.selector = 0;
            sregs.ds.base = 0;
            sregs.ds.selector = 0;
            cpu.fd().set_sregs(&sregs).unwrap();
            let mut regs = cpu.fd().get_regs().unwrap();
            regs.rip = 0;
            regs.rflags = 2;
            cpu.fd().set_regs(&regs).unwrap();
            let exit = HvVcpu::run(cpu).unwrap();
            assert!(
                matches!(&exit, VcpuExit::IoOut { port: 0xe9, data } if data == &[b'A' + index as u8]),
                "vCPU {index} did not read the current shared GPA byte"
            );
            machine
                .memory_mut()
                .write(FrameGpa::new(0x100), &[b'B' + index as u8])
                .unwrap();
        }
        assert_eq!(machine.memory_mut().retained_bytes(), PAGE as usize);
    }
}
