//! Stopped CPU custody for the carrier, independent of runtime and MM owners.
//! This M1 boundary stages/saves two task contexts; it exposes no guest-run
//! method. M2 supplies entry/run/exit retirement before that surface is added.
use carrick_hal::TrapError;
use carrick_hal::guest_arch_binding::{GuestArchBinding, core_arch::TaskIdentity};
use carrick_hal::threaded::X86_TASK_RESUME_PAYLOAD_LEN;
use carrick_x86::{X86VcpuSnapshot, arch_context::X86ArchContext};

/// Physical I/O only. A driver must own a fresh stopped CPU with no pending
/// exit completion. It must never run it behind this custody boundary.
pub trait CarrierCpuIo {
    fn read_image(&self) -> Result<X86VcpuSnapshot, TrapError>;
    fn write_image(&mut self, image: &X86VcpuSnapshot) -> Result<(), TrapError>;
}

pub struct KvmCarrierCpu<I: CarrierCpuIo> {
    io: I,
    neutral: X86VcpuSnapshot,
}
impl<I: CarrierCpuIo> KvmCarrierCpu<I> {
    pub fn new(io: I) -> Result<Self, TrapError> {
        let neutral = io.read_image()?;
        if neutral.xsave.is_none() {
            return Err(TrapError::Hypervisor(
                "carrier CPU requires full XSAVE".into(),
            ));
        }
        Ok(Self { io, neutral })
    }
    pub fn load(&mut self, _context: X86ArchContext) -> Result<(), TrapError> {
        Err(TrapError::Hypervisor(
            "x86 carrier CPU boundary is not implemented".into(),
        ))
    }
    pub fn save_and_detach(&mut self, _task: TaskIdentity) -> Result<X86ArchContext, TrapError> {
        Err(TrapError::Hypervisor(
            "x86 carrier CPU boundary is not implemented".into(),
        ))
    }
    pub fn audit_idle(&self) -> Result<(), TrapError> {
        let _ = (&self.neutral, &self.io);
        Err(TrapError::Hypervisor(
            "x86 carrier CPU boundary is not implemented".into(),
        ))
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;
    use carrick_hal::guest_arch_binding::core_arch::*;
    use carrick_hal::threaded::{X86_TASK_RESUME_MAGIC, X86TaskCpuStateV1};
    use std::num::NonZeroU64;

    struct TestIo {
        image: X86VcpuSnapshot,
    }
    impl CarrierCpuIo for TestIo {
        fn read_image(&self) -> Result<X86VcpuSnapshot, TrapError> {
            Ok(self.image.clone())
        }
        fn write_image(&mut self, image: &X86VcpuSnapshot) -> Result<(), TrapError> {
            self.image = image.clone();
            Ok(())
        }
    }
    fn context(tag: u64) -> X86ArchContext {
        let nz = |v| NonZeroU64::new(v).unwrap();
        let root = RootGpa::page_aligned(FrameGpa::new(tag << 12)).unwrap();
        let binding = GuestArchBinding::x86(
            TaskIdentity {
                carrier: CarrierGeneration::new(nz(1)),
                task: TaskSerial::new(nz(tag)),
                execution: ExecutionGeneration::new(nz(tag + 10)),
            },
            AddressContext {
                root,
                mm: MmGeneration::new(nz(tag + 20)),
                generation: ContextGeneration::new(nz(tag + 30)),
            },
        );
        let mut resume = [0u8; X86_TASK_RESUME_PAYLOAD_LEN];
        // All pending-PC/syscall/SYSRET/fork flags are exercised, not just GPRs.
        for (slot, value) in [
            15,
            tag << 16,
            39,
            172,
            tag << 20,
            0x202,
            0,
            X86_TASK_RESUME_MAGIC,
        ]
        .into_iter()
        .enumerate()
        {
            resume[slot * 8..slot * 8 + 8].copy_from_slice(&value.to_le_bytes());
        }
        let mut gprs = [tag; 16];
        gprs[7] = tag << 24;
        let state = X86TaskCpuStateV1::new(
            gprs,
            tag << 16,
            0x202,
            gprs[7],
            0x8000_0031,
            root.address().raw(),
            0x40620,
            0xd01,
            tag << 28,
            tag << 32,
            binding.context().mm.raw().get(),
            binding.context().generation.raw().get(),
            vec![tag as u8; carrick_x86::XSAVE_LEN],
            resume.to_vec(),
        )
        .unwrap();
        X86ArchContext::new(binding, state).unwrap()
    }

    #[test]
    fn two_task_contexts_preserve_registers_tls_xsave_and_resume() {
        let a = context(2);
        let b = context(3);
        let mut cpu = KvmCarrierCpu::new(TestIo {
            image: context(1).hardware_image(),
        })
        .unwrap();
        cpu.load(a.clone()).unwrap();
        let saved_a = cpu.save_and_detach(a.binding().task()).unwrap();
        assert_eq!(saved_a.state(), a.state());
        cpu.audit_idle().unwrap();
        cpu.load(b.clone()).unwrap();
        let saved_b = cpu.save_and_detach(b.binding().task()).unwrap();
        assert_eq!(saved_b.state(), b.state());
        assert_ne!(saved_a.state().cr3(), saved_b.state().cr3());
        assert_ne!(saved_a.state().fs_base(), saved_b.state().fs_base());
        assert_ne!(saved_a.state().gs_base(), saved_b.state().gs_base());
        assert_ne!(saved_a.state().xsave(), saved_b.state().xsave());
        cpu.load(saved_a).unwrap();
        assert_eq!(
            cpu.save_and_detach(a.binding().task()).unwrap().state(),
            a.state()
        );
        cpu.audit_idle().unwrap();
    }
}
