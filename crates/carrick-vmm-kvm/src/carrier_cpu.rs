//! KVM hardware operations consumed by the sealed carrier CPU custody.

use carrick_hal::{HvVcpu, HvVm, TrapError, VcpuExit};
use carrick_x86::{BringupLayout, X86Reg, X86Vcpu, X86VcpuSnapshot};
pub use carrick_x86_cpl0_host::carrier_cpu::{
    CarrierChildBindings, CarrierCpu, CarrierCpuBackend, CarrierCpuIo, CarrierRunExit, OwnedCpuIo,
    StoppedTaskExit, claim_carrier_cpu_io,
};

struct ProductionCpuStatic {
    sregs: kvm_bindings::kvm_sregs,
    lstar: u64,
    star: u64,
    sfmask: u64,
}

pub type KvmCpuIo = OwnedCpuIo<KvmCpuBackend>;

pub struct KvmCpuBackend {
    vcpu: crate::KvmVcpu,
    _vm: crate::KvmVm,
    layout: BringupLayout,
    production_run: Option<crate::cpl0_boot::ProductionRunContext>,
    production_static: Option<ProductionCpuStatic>,
}

impl CarrierCpuBackend for KvmCpuBackend {
    type KickHandle = crate::KvmKickHandle;
    type Watchdog = crate::cpl0_boot::Watchdog;

    fn for_current_thread_kick() -> Self::KickHandle {
        crate::KvmKickHandle::for_current_thread()
    }

    fn read_image(&self) -> Result<X86VcpuSnapshot, TrapError> {
        carrick_x86::snapshot(&self.vcpu)
    }

    fn write_image(&mut self, image: &X86VcpuSnapshot) -> Result<(), TrapError> {
        crate::kvm_x86_engine::restore_kvm_vcpu(
            &mut self.vcpu,
            self.layout,
            image,
            [0; 4],
            [0; 4],
            [0; 4],
            [0; 4],
        )?;
        if let Some(static_state) = &self.production_static {
            let mut sregs = self
                .vcpu
                .fd()
                .get_sregs()
                .map_err(|error| TrapError::Hypervisor(format!("KVM sregs: {error}")))?;
            sregs.gdt = static_state.sregs.gdt;
            sregs.idt = static_state.sregs.idt;
            sregs.tr = crate::kvm_x86_engine::KvmSegment::from(
                carrick_x86::SegmentDescriptor::tss64_busy(static_state.sregs.tr.base)
                    .with_selector(static_state.sregs.tr.selector),
            )
            .0;
            sregs.ldt = static_state.sregs.ldt;
            sregs.apic_base = static_state.sregs.apic_base;
            self.vcpu
                .fd()
                .set_sregs(&sregs)
                .map_err(|error| TrapError::Hypervisor(format!("KVM sregs: {error}")))?;
            self.vcpu
                .set_syscall_msrs(static_state.lstar, static_state.star, static_state.sfmask)
                .map_err(|error| TrapError::Hypervisor(format!("KVM msrs: {error}")))?;
        }
        Ok(())
    }

    fn run(&mut self) -> Result<VcpuExit, TrapError> {
        if let Some(context) = &self.production_run {
            context.run(&mut self.vcpu)
        } else {
            Ok(HvVcpu::run(&mut self.vcpu)?)
        }
    }

    fn complete_pending_io(&mut self) -> Result<(), TrapError> {
        self.vcpu
            .complete_pending_io_exit()
            .map_err(|error| TrapError::Hypervisor(format!("KVM pending IO: {error}")))
    }

    fn arm_run_kick(&mut self, kick: &Self::KickHandle) -> Result<(), TrapError> {
        self.vcpu.arm_run_kick(kick);
        Ok(())
    }

    fn disarm_run_kick(kick: &Self::KickHandle) {
        kick.disarm_run();
    }

    fn physical_slot(&self) -> Option<carrick_guest_arch::CpuId> {
        self.production_run
            .as_ref()
            .map(crate::cpl0_boot::ProductionRunContext::physical_slot)
    }

    fn get_gpr(&self, reg: X86Reg) -> Result<u64, TrapError> {
        self.vcpu.get_gpr(reg)
    }

    fn read_msr(&self, msr: u32) -> Result<u64, TrapError> {
        self.vcpu.read_msr(msr)
    }

    fn get_fs_base(&self) -> Result<u64, TrapError> {
        Ok(self
            .vcpu
            .fd()
            .get_sregs()
            .map_err(|e| TrapError::Hypervisor(e.to_string()))?
            .fs
            .base)
    }
    fn set_fs_base(&mut self, address: u64) -> Result<(), TrapError> {
        let mut sregs = self
            .vcpu
            .fd()
            .get_sregs()
            .map_err(|e| TrapError::Hypervisor(e.to_string()))?;
        sregs.fs.base = address;
        self.vcpu
            .fd()
            .set_sregs(&sregs)
            .map_err(|e| TrapError::Hypervisor(e.to_string()))
    }

    fn write_msr(&mut self, msr: u32, value: u64) -> Result<(), TrapError> {
        let msrs = kvm_bindings::Msrs::from_entries(&[kvm_bindings::kvm_msr_entry {
            index: msr,
            data: value,
            ..Default::default()
        }])
        .map_err(|error| TrapError::Hypervisor(format!("write_msr entry: {error}")))?;
        let written = self
            .vcpu
            .fd()
            .set_msrs(&msrs)
            .map_err(|error| TrapError::Hypervisor(format!("KVM_SET_MSRS: {error}")))?;
        if written != 1 {
            return Err(TrapError::Hypervisor("KVM_SET_MSRS refused entry".into()));
        }
        Ok(())
    }
}

pub struct KvmCarrierCpu;

impl KvmCarrierCpu {
    pub fn create_stopped(layout: BringupLayout) -> Result<CarrierCpu<KvmCpuIo>, TrapError> {
        let mut vm =
            crate::KvmVm::create_empty().map_err(|e| TrapError::Hypervisor(e.to_string()))?;
        let mut vcpu = vm
            .add_vcpu()
            .map_err(|e| TrapError::Hypervisor(e.to_string()))?;
        carrick_x86::program_longmode_entry(&mut vcpu, layout, 0x1000, 0x2000)?;
        CarrierCpu::new(claim_carrier_cpu_io(KvmCpuBackend {
            vcpu,
            _vm: vm,
            layout,
            production_run: None,
            production_static: None,
        }))
    }

    pub(crate) fn from_production(
        vcpu: crate::KvmVcpu,
        vm: crate::KvmVm,
        layout: BringupLayout,
        production_run: crate::cpl0_boot::ProductionRunContext,
        child_bindings: CarrierChildBindings,
    ) -> Result<CarrierCpu<KvmCpuIo>, TrapError> {
        let static_state = ProductionCpuStatic {
            sregs: vcpu
                .fd()
                .get_sregs()
                .map_err(|error| TrapError::Hypervisor(format!("KVM sregs: {error}")))?,
            lstar: vcpu
                .read_msr(0xc000_0082)
                .map_err(|error| TrapError::Hypervisor(format!("KVM lstar: {error}")))?,
            star: vcpu
                .read_msr(0xc000_0081)
                .map_err(|error| TrapError::Hypervisor(format!("KVM star: {error}")))?,
            sfmask: vcpu
                .read_msr(0xc000_0084)
                .map_err(|error| TrapError::Hypervisor(format!("KVM sfmask: {error}")))?,
        };
        let maintenance_root = production_run.maintenance_root.ok_or_else(|| {
            TrapError::Hypervisor("worker production run has no maintenance root".into())
        })?;
        CarrierCpu::new_with_maintenance(
            claim_carrier_cpu_io(KvmCpuBackend {
                vcpu,
                _vm: vm,
                layout,
                production_run: Some(production_run),
                production_static: Some(static_state),
            }),
            child_bindings,
            Some(maintenance_root),
        )
    }
}
