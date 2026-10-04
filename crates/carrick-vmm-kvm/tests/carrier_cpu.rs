//! Required KVM readback gate, separate from VM-free library tests.
//! Missing /dev/kvm is a failure. No guest instruction or KVM_RUN is issued.
#![cfg(all(target_os = "linux", target_arch = "x86_64"))]
#![allow(clippy::unwrap_used)]
use carrick_hal::guest_arch_binding::{GuestArchBinding, core_arch::*};
use carrick_hal::threaded::{X86_TASK_RESUME_MAGIC, X86_TASK_RESUME_PAYLOAD_LEN};
use carrick_vmm_kvm::carrier_cpu::KvmCarrierCpu;
use carrick_vmm_kvm::kvm_x86_engine::KVM_X86_LAYOUT;
use carrick_x86::{X86VcpuSnapshot, arch_context::X86ArchContext};
use std::num::NonZeroU64;

fn context(mut image: X86VcpuSnapshot, tag: u8) -> X86ArchContext {
    let nz = |n| NonZeroU64::new(n).unwrap();
    let value = u64::from(tag);
    let root = RootGpa::page_aligned(FrameGpa::new(value << 12)).unwrap();
    let binding = GuestArchBinding::x86(
        TaskIdentity {
            carrier: CarrierGeneration::new(nz(1)),
            task: TaskSerial::new(nz(value)),
            execution: ExecutionGeneration::new(nz(value + 10)),
        },
        AddressContext {
            root,
            mm: MmGeneration::new(nz(value + 20)),
            generation: ContextGeneration::new(nz(value + 30)),
        },
    );
    image.gprs = [value; 16];
    image.rsp = value << 24;
    image.gprs[7] = image.rsp;
    image.rip = KVM_X86_LAYOUT.trampoline_base + 2; // pending SYSRET
    image.cr3 = root.address().raw();
    image.fs_base = value << 28;
    image.gs_base = value << 32;
    let xs = image.xsave.as_mut().unwrap();
    // Legal standard-format XSAVE: preserve control/reserved bytes, mark x87,
    // SSE and AVX present, tag both XMM and YMM upper state.
    xs[512..520].copy_from_slice(&7u64.to_le_bytes());
    xs[160..416].fill(tag);
    xs[carrick_x86::XSAVE_AVX_OFFSET..].fill(tag);
    let mut resume = [0; X86_TASK_RESUME_PAYLOAD_LEN];
    for (slot, word) in [
        15,
        image.rip,
        39,
        172,
        value << 16,
        0x202,
        0,
        X86_TASK_RESUME_MAGIC,
    ]
    .into_iter()
    .enumerate()
    {
        resume[slot * 8..slot * 8 + 8].copy_from_slice(&word.to_le_bytes());
    }
    X86ArchContext::capture(binding, &image, resume).unwrap()
}

#[test]
fn stopped_kvm_cpu_roundtrips_two_complete_task_images() {
    let mut cpu = KvmCarrierCpu::create_stopped(KVM_X86_LAYOUT).unwrap();
    cpu.audit_idle().unwrap();
    let a = context(cpu.neutral_image().clone(), 2);
    let b = context(cpu.neutral_image().clone(), 3);
    for expected in [&a, &b, &a] {
        cpu.load(expected.clone()).unwrap();
        let actual = cpu.save_and_detach(expected.binding().task()).unwrap();
        assert_eq!(actual.binding(), expected.binding());
        assert_eq!(actual.state(), expected.state());
        cpu.audit_idle().unwrap();
    }
}
