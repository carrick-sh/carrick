//! `SoftBootVcpu` programs a stopped soft CPU as `KvmVcpu` programs a KVM
//! vCPU: every setter leaves the soft CPU's derived state (the TLB mode tag,
//! `EFER.LMA`, the FS/GS base) as the hardware would hold it (#671 M1-3
//! review P1s).

#![cfg(all(target_arch = "x86_64", target_os = "linux"))]
#![allow(clippy::expect_used, clippy::panic)]

use carrick_softcpu_x86::{ExtentTable, SoftCpu, SoftCpuContext};
use carrick_softmmu::SoftTlb;
use carrick_vmm_soft::{SoftBootVcpu, soft_cpuid};
use carrick_x86::{SegmentDescriptor, SegmentDpl, X86Reg, X86Seg, X86Vcpu};

const RFLAGS_AC: u64 = 1 << 18;
const CR0_PE: u64 = 1;
const CR0_ET: u64 = 1 << 4;
const CR0_PG: u64 = 1 << 31;
const CR4_PAE: u64 = 1 << 5;
const CR4_SMAP: u64 = 1 << 21;
const EFER_LME: u64 = 1 << 8;
const EFER_LMA: u64 = 1 << 10;

fn stopped_cpu() -> SoftCpu {
    SoftCpu::new(&ExtentTable::new().expect("extent table")).expect("soft CPU")
}

fn program(cpu: &mut SoftCpu, f: impl FnOnce(&mut SoftBootVcpu<'_>)) {
    let cpuid = soft_cpuid();
    f(&mut SoftBootVcpu::new(cpu.context_mut(), &cpuid));
}

fn tag_is_current(ctx: &SoftCpuContext) -> bool {
    ctx.tlb_tag_bits == SoftTlb::mode_tag_bits(ctx.access_mode())
}

#[test]
fn setting_rflags_ac_refreshes_the_tlb_mode_tag() {
    let mut cpu = stopped_cpu();
    program(&mut cpu, |vcpu| {
        // SMAP makes RFLAGS.AC part of a supervisor access's mode.
        vcpu.set_segment(X86Seg::Cs, SegmentDescriptor::code64(SegmentDpl::Kernel))
            .expect("CS");
        vcpu.set_gpr(X86Reg::Rflags, 2).expect("RFLAGS");
        vcpu.set_gpr(X86Reg::Cr4, CR4_PAE | CR4_SMAP).expect("CR4");
        vcpu.set_gpr(X86Reg::Rflags, 2 | RFLAGS_AC).expect("RFLAGS");
    });
    let ctx = cpu.context();
    assert!(ctx.access_mode().ac);
    assert!(tag_is_current(ctx), "stale tag {:#x}", ctx.tlb_tag_bits);
}

#[test]
fn setting_cr0_paging_with_lme_activates_long_mode() {
    let mut cpu = stopped_cpu();
    program(&mut cpu, |vcpu| {
        // Paging off, then LME, then paging on: only the CR0 write can
        // activate long mode.
        vcpu.set_gpr(X86Reg::Cr0, CR0_PE | CR0_ET)
            .expect("CR0 without PG");
        vcpu.set_gpr(X86Reg::Cr4, CR4_PAE).expect("CR4");
        vcpu.set_gpr(X86Reg::Efer, EFER_LME).expect("EFER");
        assert_eq!(vcpu.get_gpr(X86Reg::Efer).expect("EFER") & EFER_LMA, 0);
        vcpu.set_gpr(X86Reg::Cr0, CR0_PE | CR0_ET | CR0_PG)
            .expect("CR0");
    });
    let ctx = cpu.context();
    assert_ne!(ctx.efer() & EFER_LMA, 0, "EFER {:#x}", ctx.efer());
    assert!(tag_is_current(ctx));
}

#[test]
fn fs_and_gs_descriptors_install_their_base() {
    let mut cpu = stopped_cpu();
    let (fs, gs) = (0x7f00_1000_u64, 0x7f00_2000_u64);
    program(&mut cpu, |vcpu| {
        vcpu.set_fs_base(0x1111_0000).expect("FS base");
        vcpu.set_gs_base(0x2222_0000).expect("GS base");
        vcpu.set_segment(
            X86Seg::Fs,
            SegmentDescriptor::flat_data(SegmentDpl::User, fs),
        )
        .expect("FS");
        vcpu.set_segment(
            X86Seg::Gs,
            SegmentDescriptor::flat_data(SegmentDpl::User, gs),
        )
        .expect("GS");
    });
    let ctx = cpu.context();
    assert_eq!((ctx.fs_base(), ctx.fs.base), (fs, fs));
    assert_eq!((ctx.gs_base(), ctx.gs.base), (gs, gs));
}
