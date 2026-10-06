//! KVM x86 register marshalling for shared-kernel carrier CPUs.
//! This module owns no guest RAM, page tables, per-process VM or service loop.
//! KVM groups control registers and segments in SREGS, and general registers
//! in REGS; restores preserve that grouped ioctl boundary.

use crate::kvm::KvmVcpu;
use carrick_hal::TrapError;
use carrick_x86::{
    BringupLayout, FAULT_DOORBELL_PORT, FaultDoorbellRecord, MsrInstall,
    X86_FAULT_RECORD_U32_WORDS, X86Exit, X86Reg, X86Seg, X86Vcpu, X86VcpuSnapshot,
    fault_exit_from_record,
};
use kvm_bindings::{Msrs, kvm_dtable, kvm_msr_entry, kvm_segment};

/// Low physical layout for the stopped CPU readback witness. Production CPL0
/// boot owns its separate shared-kernel layout in `cpl0_boot`.
pub const KVM_X86_LAYOUT: BringupLayout = BringupLayout {
    trampoline_base: 0x1000_0000,
    gdt_base: 0x1000_1000,
    pml4_base: 0x1000_2000,
};

/// Map an `X86Seg` to the KVM bring-up selector (KVM uses the hidden `kvm_segment`
/// directly and does not re-load from the GDT, but a consistent selector keeps
/// the descriptor self-describing). CS=0x23, SS/DS/ES=0x1B, others 0.
fn seg_selector(seg: X86Seg) -> u16 {
    match seg {
        X86Seg::Cs => 0x23,
        X86Seg::Ss | X86Seg::Ds | X86Seg::Es => 0x1B,
        _ => 0,
    }
}

/// Unpack a packed long-mode access-rights word (see `carrick_x86`'s `seg_ar`)
/// into the `kvm_segment` bit-fields.
fn ar_to_kvm_segment(base: u64, limit: u32, ar: u32, selector: u16) -> kvm_segment {
    kvm_segment {
        base,
        limit,
        selector,
        type_: (ar & 0xF) as u8,
        s: ((ar >> 4) & 1) as u8,
        dpl: ((ar >> 5) & 3) as u8,
        present: ((ar >> 7) & 1) as u8,
        avl: ((ar >> 12) & 1) as u8,
        l: ((ar >> 13) & 1) as u8,
        db: ((ar >> 14) & 1) as u8,
        g: ((ar >> 15) & 1) as u8,
        unusable: ((ar >> 16) & 1) as u8,
        ..Default::default()
    }
}

pub(crate) fn restore_kvm_vcpu(
    vcpu: &mut KvmVcpu,
    layout: BringupLayout,
    s: &X86VcpuSnapshot,
    rcx_walk: [u64; 4],
    rdx_walk: [u64; 4],
    rsp_walk: [u64; 4],
    fs_walk: [u64; 4],
) -> Result<(), TrapError> {
    use carrick_hal::guest_arch::GuestArch as _;
    use carrick_hal::x8664_arch::X8664GuestArch;

    let boot = X8664GuestArch::bootstrap_sysregs();
    let segs = carrick_x86::long_mode_segment_state();
    let kernel_cs = ((boot.star >> 32) & 0xFFFF) as u16;
    let kernel_ss = kernel_cs.wrapping_add(8);
    let user_base = ((boot.star >> 48) & 0xFFFF) as u16;
    let user_ss = user_base.wrapping_add(8);
    let user_cs = user_base.wrapping_add(16);
    let at_sysret = s.rip == layout.trampoline_base + 2;
    let (cs_ar, cs_selector, ss_ar, ss_selector) = if at_sysret {
        (segs.kernel_cs_ar, kernel_cs, segs.kernel_data_ar, kernel_ss)
    } else {
        (segs.cs_ar, user_cs, segs.data_ar, user_ss)
    };
    let mut sregs = vcpu
        .fd()
        .get_sregs()
        .map_err(|e| TrapError::Hypervisor(format!("KVM_GET_SREGS(restore): {e}")))?;
    sregs.cr0 = s.cr0;
    sregs.cr2 = 0;
    sregs.cr3 = s.cr3;
    sregs.cr4 = s.cr4;
    sregs.efer = s.efer;
    sregs.cs = ar_to_kvm_segment(0, 0xFFFF_FFFF, cs_ar, cs_selector);
    let data = |base| ar_to_kvm_segment(base, 0xFFFF_FFFF, segs.data_ar, 0);
    sregs.ss = ar_to_kvm_segment(0, 0xFFFF_FFFF, ss_ar, ss_selector);
    sregs.ds = ar_to_kvm_segment(0, 0xFFFF_FFFF, segs.data_ar, user_ss);
    sregs.es = ar_to_kvm_segment(0, 0xFFFF_FFFF, segs.data_ar, user_ss);
    sregs.fs = data(s.fs_base);
    sregs.gs = data(s.gs_base);
    let fault_slot = vcpu.x86_fault_slot();
    sregs.tr = ar_to_kvm_segment(
        carrick_x86::fault_slot_gpa(carrick_x86::fault_tss_base(layout), fault_slot)?,
        carrick_x86::fault::X86_TSS64_LIMIT,
        segs.tr_ar,
        seg_selector(X86Seg::Tr),
    );
    sregs.ldt = ar_to_kvm_segment(0, 0, segs.ldtr_ar, seg_selector(X86Seg::Ldtr));
    sregs.gdt = kvm_dtable {
        base: layout.gdt_base,
        limit: segs.gdt_limit as u16,
        ..Default::default()
    };
    sregs.idt = kvm_dtable {
        base: carrick_x86::fault_slot_gpa(carrick_x86::fault_idt_base(layout), fault_slot)?,
        limit: (carrick_x86::fault::X86_IDT_BYTES - 1) as u16,
        ..Default::default()
    };
    vcpu.fd()
        .set_sregs(&sregs)
        .map_err(|e| TrapError::Hypervisor(format!("KVM_SET_SREGS(restore): {e}")))?;

    let mut regs = vcpu
        .fd()
        .get_regs()
        .map_err(|e| TrapError::Hypervisor(format!("KVM_GET_REGS(restore): {e}")))?;
    regs.rax = s.gprs[0];
    regs.rbx = s.gprs[1];
    regs.rcx = s.gprs[2];
    regs.rdx = s.gprs[3];
    regs.rsi = s.gprs[4];
    regs.rdi = s.gprs[5];
    regs.rbp = s.gprs[6];
    regs.rsp = s.rsp;
    regs.r8 = s.gprs[8];
    regs.r9 = s.gprs[9];
    regs.r10 = s.gprs[10];
    regs.r11 = s.gprs[11];
    regs.r12 = s.gprs[12];
    regs.r13 = s.gprs[13];
    regs.r14 = s.gprs[14];
    regs.r15 = s.gprs[15];
    regs.rip = s.rip;
    regs.rflags = s.rflags;
    vcpu.fd()
        .set_regs(&regs)
        .map_err(|e| TrapError::Hypervisor(format!("KVM_SET_REGS(restore): {e}")))?;

    if let Some(xs) = &s.xsave {
        let _ = vcpu.set_xsave(xs)?;
    }
    vcpu.set_syscall_msrs(layout.trampoline_base, boot.star, boot.sfmask)?;
    vcpu.record_x86_restore_state(crate::kvm::KvmX86RestoreState {
        rip: s.rip,
        rsp: s.rsp,
        rflags: s.rflags,
        rax: s.gprs[0],
        rcx: s.gprs[2],
        rdx: s.gprs[3],
        rdi: s.gprs[5],
        r8: s.gprs[8],
        r11: s.gprs[11],
        fs_base: s.fs_base,
        gs_base: s.gs_base,
        cr0: s.cr0,
        cr3: s.cr3,
        cr4: s.cr4,
        efer: s.efer,
        rcx_walk,
        rdx_walk,
        rsp_walk,
        fs_walk,
    });
    Ok(())
}

impl KvmVcpu {
    fn collect_x86_fault_record(&mut self, first_data: &[u8]) -> Result<X86Exit, TrapError> {
        use carrick_hal::{HvVcpu, VcpuExit};

        let mut words = Vec::with_capacity(X86_FAULT_RECORD_U32_WORDS);
        words.push(fault_out_word(first_data)?);
        while words.len() < X86_FAULT_RECORD_U32_WORDS {
            match <Self as HvVcpu>::run(self).map_err(|e| TrapError::Hypervisor(e.to_string()))? {
                VcpuExit::IoOut { port, data } if port == FAULT_DOORBELL_PORT => {
                    words.push(fault_out_word(&data)?);
                }
                VcpuExit::Kicked => continue,
                other => {
                    return Err(TrapError::Hypervisor(format!(
                        "kvm-x86: fault doorbell record interrupted by {}",
                        vcpu_exit_name(&other)
                    )));
                }
            }
        }

        let record = FaultDoorbellRecord::from_u32_words(&words)?;
        if std::env::var_os("CARRICK_TRACE_X86_FAULTS").is_some() {
            eprintln!("[KVM-X86-FAULT] {record:?}");
        }
        fault_exit_from_record(self, record, "kvm-x86")
    }
}

fn fault_out_word(data: &[u8]) -> Result<u32, TrapError> {
    let bytes: [u8; 4] = data.try_into().map_err(|_| {
        TrapError::Hypervisor(format!(
            "kvm-x86: fault doorbell OUT expected 4 bytes, got {}",
            data.len()
        ))
    })?;
    Ok(u32::from_le_bytes(bytes))
}

fn vcpu_exit_name(exit: &carrick_hal::VcpuExit) -> &'static str {
    match exit {
        carrick_hal::VcpuExit::MmioWrite { .. } => "MMIO write",
        carrick_hal::VcpuExit::Exception { .. } => "exception",
        carrick_hal::VcpuExit::Kicked => "kick",
        carrick_hal::VcpuExit::Halt => "halt",
        carrick_hal::VcpuExit::IoOut { .. } => "I/O out",
    }
}

impl X86Vcpu for KvmVcpu {
    fn read_msr(&self, index: u32) -> Result<u64, TrapError> {
        let mut msrs = Msrs::from_entries(&[kvm_msr_entry {
            index,
            ..Default::default()
        }])
        .map_err(|e| TrapError::Hypervisor(format!("Msrs::from_entries({index:#x}): {e}")))?;
        if self
            .fd()
            .get_msrs(&mut msrs)
            .map_err(|e| TrapError::Hypervisor(format!("KVM_GET_MSRS({index:#x}): {e}")))?
            != 1
        {
            return Err(TrapError::Hypervisor(format!(
                "KVM_GET_MSRS({index:#x}) returned no entry"
            )));
        }
        msrs.as_slice()
            .first()
            .map(|entry| entry.data)
            .ok_or_else(|| TrapError::Hypervisor(format!("KVM_GET_MSRS({index:#x}) empty")))
    }

    fn get_gpr(&self, reg: X86Reg) -> Result<u64, TrapError> {
        // GPRs/RIP/RSP/RFLAGS via KVM_GET_REGS; control regs/EFER via KVM_GET_SREGS.
        Ok(match reg {
            X86Reg::Cr0 | X86Reg::Cr2 | X86Reg::Cr3 | X86Reg::Cr4 | X86Reg::Efer => {
                crate::kvm::record_kvm_stat(crate::kvm::KvmStat::GetSregs);
                let s = self
                    .fd()
                    .get_sregs()
                    .map_err(|e| TrapError::Hypervisor(format!("KVM_GET_SREGS: {e}")))?;
                match reg {
                    X86Reg::Cr0 => s.cr0,
                    X86Reg::Cr2 => s.cr2,
                    X86Reg::Cr3 => s.cr3,
                    X86Reg::Cr4 => s.cr4,
                    X86Reg::Efer => s.efer,
                    _ => unreachable!(),
                }
            }
            _ => {
                crate::kvm::record_kvm_stat(crate::kvm::KvmStat::GetRegs);
                let r = self
                    .fd()
                    .get_regs()
                    .map_err(|e| TrapError::Hypervisor(format!("KVM_GET_REGS: {e}")))?;
                match reg {
                    X86Reg::Rax => r.rax,
                    X86Reg::Rbx => r.rbx,
                    X86Reg::Rcx => r.rcx,
                    X86Reg::Rdx => r.rdx,
                    X86Reg::Rsi => r.rsi,
                    X86Reg::Rdi => r.rdi,
                    X86Reg::Rbp => r.rbp,
                    X86Reg::Rsp => r.rsp,
                    X86Reg::R8 => r.r8,
                    X86Reg::R9 => r.r9,
                    X86Reg::R10 => r.r10,
                    X86Reg::R11 => r.r11,
                    X86Reg::R12 => r.r12,
                    X86Reg::R13 => r.r13,
                    X86Reg::R14 => r.r14,
                    X86Reg::R15 => r.r15,
                    X86Reg::Rip => r.rip,
                    X86Reg::Rflags => r.rflags,
                    _ => unreachable!(),
                }
            }
        })
    }

    fn prepare_sysret_resume(&mut self, _layout: BringupLayout) -> Result<(), TrapError> {
        use carrick_hal::guest_arch::GuestArch as _;
        use carrick_hal::x8664_arch::X8664GuestArch;

        let boot = X8664GuestArch::bootstrap_sysregs();
        let segs = carrick_x86::long_mode_segment_state();
        let kernel_cs = ((boot.star >> 32) & 0xFFFF) as u16;
        let kernel_ss = kernel_cs.wrapping_add(8);
        let want_cs = ar_to_kvm_segment(0, 0xFFFF_FFFF, segs.kernel_cs_ar, kernel_cs);
        let want_ss = ar_to_kvm_segment(0, 0xFFFF_FFFF, segs.kernel_data_ar, kernel_ss);

        // Read sregs from the mmap'd kvm_run.s.regs (the kernel synced it out on
        // the doorbell exit; kvm_valid_regs requests SREGS too) instead of a
        // KVM_GET_SREGS ioctl. Read-only mirror — kernel sregs stay authoritative.
        let mut sregs = if self.sync_regs_usable() {
            self.fd().sync_regs().sregs
        } else {
            crate::kvm::record_kvm_stat(crate::kvm::KvmStat::GetSregs);
            self.fd()
                .get_sregs()
                .map_err(|e| TrapError::Hypervisor(format!("KVM_GET_SREGS(sysret): {e}")))?
        };
        // A guest SYSCALL already loaded kernel CS/SS — selector AND the fixed
        // hidden descriptor (base 0, 4 GiB limit, kernel AR) — from STAR, so the
        // reprogram is normally a no-op. Skip the KVM_SET_SREGS when CS/SS already
        // match; only the first sysret after a fresh/forked vCPU needs the write.
        if sregs.cs == want_cs && sregs.ss == want_ss {
            return Ok(());
        }
        sregs.cs = want_cs;
        sregs.ss = want_ss;
        crate::kvm::record_kvm_stat(crate::kvm::KvmStat::SetSregs);
        self.fd()
            .set_sregs(&sregs)
            .map_err(|e| TrapError::Hypervisor(format!("KVM_SET_SREGS(sysret): {e}")))
    }

    fn set_gpr(&mut self, reg: X86Reg, v: u64) -> Result<(), TrapError> {
        match reg {
            X86Reg::Cr0 | X86Reg::Cr2 | X86Reg::Cr3 | X86Reg::Cr4 | X86Reg::Efer => {
                crate::kvm::record_kvm_stat(crate::kvm::KvmStat::GetSregs);
                let mut s = self
                    .fd()
                    .get_sregs()
                    .map_err(|e| TrapError::Hypervisor(format!("KVM_GET_SREGS: {e}")))?;
                match reg {
                    X86Reg::Cr0 => s.cr0 = v,
                    X86Reg::Cr2 => s.cr2 = v,
                    X86Reg::Cr3 => s.cr3 = v,
                    X86Reg::Cr4 => s.cr4 = v,
                    X86Reg::Efer => s.efer = v,
                    _ => unreachable!(),
                }
                crate::kvm::record_kvm_stat(crate::kvm::KvmStat::SetSregs);
                self.fd()
                    .set_sregs(&s)
                    .map_err(|e| TrapError::Hypervisor(format!("KVM_SET_SREGS: {e}")))
            }
            _ => {
                crate::kvm::record_kvm_stat(crate::kvm::KvmStat::GetRegs);
                let mut r = self
                    .fd()
                    .get_regs()
                    .map_err(|e| TrapError::Hypervisor(format!("KVM_GET_REGS: {e}")))?;
                match reg {
                    X86Reg::Rax => r.rax = v,
                    X86Reg::Rbx => r.rbx = v,
                    X86Reg::Rcx => r.rcx = v,
                    X86Reg::Rdx => r.rdx = v,
                    X86Reg::Rsi => r.rsi = v,
                    X86Reg::Rdi => r.rdi = v,
                    X86Reg::Rbp => r.rbp = v,
                    X86Reg::Rsp => r.rsp = v,
                    X86Reg::R8 => r.r8 = v,
                    X86Reg::R9 => r.r9 = v,
                    X86Reg::R10 => r.r10 = v,
                    X86Reg::R11 => r.r11 = v,
                    X86Reg::R12 => r.r12 = v,
                    X86Reg::R13 => r.r13 = v,
                    X86Reg::R14 => r.r14 = v,
                    X86Reg::R15 => r.r15 = v,
                    X86Reg::Rip => r.rip = v,
                    X86Reg::Rflags => r.rflags = v,
                    _ => unreachable!(),
                }
                crate::kvm::record_kvm_stat(crate::kvm::KvmStat::SetRegs);
                self.fd()
                    .set_regs(&r)
                    .map_err(|e| TrapError::Hypervisor(format!("KVM_SET_REGS: {e}")))
            }
        }
    }

    fn complete_sysret(
        &mut self,
        layout: BringupLayout,
        return_value: i64,
        resume_pc: u64,
    ) -> Result<(u64, u64), TrapError> {
        // Read the whole GPR snapshot ONCE (RCX/R11 for the parked user PC/RFLAGS,
        // and as the base for the RAX/RIP writes), then flush it in ONE
        // KVM_SET_REGS. With KVM_CAP_SYNC_REGS the snapshot is the mmap'd
        // kvm_run.s.regs the kernel synced out on the doorbell exit — no
        // KVM_GET_REGS at all. The snapshot is a READ-ONLY mirror (we never set
        // kvm_dirty_regs), so the kernel registers stay authoritative and every
        // other accessor (get_gpr/set_gpr) is unaffected. RAX/RIP are independent
        // of RCX/R11, so reading first preserves their values.
        let mut regs = if self.sync_regs_usable() {
            self.fd().sync_regs().regs
        } else {
            crate::kvm::record_kvm_stat(crate::kvm::KvmStat::GetRegs);
            self.fd()
                .get_regs()
                .map_err(|e| TrapError::Hypervisor(format!("KVM_GET_REGS(sysret): {e}")))?
        };
        let user_pc = regs.rcx;
        let user_rflags = regs.r11 | 0x2;
        self.prepare_sysret_resume(layout)?;
        regs.rax = return_value as u64;
        // RIP fix-up for the M:N reclaim resume:
        //
        // The syscall trampoline is `out %al,$0xC5 ; sysretq`; `resume_pc` is the
        // OUT address (trampoline_base). On the NORMAL path the vCPU is still
        // parked at that KVM_EXIT_IO with a pending PIO completion, so the NEXT
        // KVM_RUN advances RIP past the 2-byte OUT (to the sysretq) before
        // executing — landing the guest on the SYSRET. The reclaim path swaps in a
        // freshly-installed vCPU whose pending PIO was FLUSHED at acquisition
        // (`create_vcpu_on_shared_vm`), so KVM has NOTHING to auto-advance: setting
        // RIP=resume_pc would re-execute the OUT, re-trap the doorbell with RAX
        // clobbered to the syscall's return value, and the guest would re-issue the
        // SAME syscall with a bogus number (read/EBADF) — glibc's "futex facility
        // returned an unexpected error code". `sync_regs_usable()` is false exactly
        // for that un-run installed vCPU, so step the RIP past the OUT ourselves.
        let stale_reclaim = !self.sync_regs_usable();
        regs.rip = if stale_reclaim && resume_pc == layout.trampoline_base {
            const SYSCALL_DOORBELL_OUT_LEN: u64 = 2; // `E6 C5` = out %al,$0xC5
            resume_pc + SYSCALL_DOORBELL_OUT_LEN
        } else {
            resume_pc
        };
        crate::kvm::record_kvm_stat(crate::kvm::KvmStat::SetRegs);
        self.fd()
            .set_regs(&regs)
            .map_err(|e| TrapError::Hypervisor(format!("KVM_SET_REGS(sysret): {e}")))?;
        Ok((user_pc, user_rflags))
    }

    fn set_segment(
        &mut self,
        seg: X86Seg,
        base: u64,
        limit: u32,
        ar: u32,
    ) -> Result<(), TrapError> {
        crate::kvm::record_kvm_stat(crate::kvm::KvmStat::GetSregs);
        let mut s = self
            .fd()
            .get_sregs()
            .map_err(|e| TrapError::Hypervisor(format!("KVM_GET_SREGS(seg): {e}")))?;
        match seg {
            X86Seg::Gdtr => {
                s.gdt = kvm_dtable {
                    base,
                    limit: limit as u16,
                    ..Default::default()
                };
            }
            X86Seg::Idtr => {
                s.idt = kvm_dtable {
                    base,
                    limit: limit as u16,
                    ..Default::default()
                };
            }
            _ => {
                let kseg = ar_to_kvm_segment(base, limit, ar, seg_selector(seg));
                match seg {
                    X86Seg::Cs => s.cs = kseg,
                    X86Seg::Ds => s.ds = kseg,
                    X86Seg::Es => s.es = kseg,
                    X86Seg::Fs => s.fs = kseg,
                    X86Seg::Gs => s.gs = kseg,
                    X86Seg::Ss => s.ss = kseg,
                    X86Seg::Tr => s.tr = kseg,
                    X86Seg::Ldtr => s.ldt = kseg,
                    X86Seg::Gdtr | X86Seg::Idtr => unreachable!(),
                }
            }
        }
        crate::kvm::record_kvm_stat(crate::kvm::KvmStat::SetSregs);
        self.fd()
            .set_sregs(&s)
            .map_err(|e| TrapError::Hypervisor(format!("KVM_SET_SREGS(seg): {e}")))
    }

    fn get_fs_base(&self) -> Result<u64, TrapError> {
        crate::kvm::record_kvm_stat(crate::kvm::KvmStat::GetSregs);
        let s = self
            .fd()
            .get_sregs()
            .map_err(|e| TrapError::Hypervisor(format!("KVM_GET_SREGS(fs): {e}")))?;
        Ok(s.fs.base)
    }

    fn set_fs_base(&mut self, v: u64) -> Result<(), TrapError> {
        crate::kvm::record_kvm_stat(crate::kvm::KvmStat::GetSregs);
        let mut s = self
            .fd()
            .get_sregs()
            .map_err(|e| TrapError::Hypervisor(format!("KVM_GET_SREGS(fs): {e}")))?;
        s.fs.base = v;
        crate::kvm::record_kvm_stat(crate::kvm::KvmStat::SetSregs);
        self.fd()
            .set_sregs(&s)
            .map_err(|e| TrapError::Hypervisor(format!("KVM_SET_SREGS(fs.base): {e}")))
    }

    fn get_gs_base(&self) -> Result<u64, TrapError> {
        crate::kvm::record_kvm_stat(crate::kvm::KvmStat::GetSregs);
        let s = self
            .fd()
            .get_sregs()
            .map_err(|e| TrapError::Hypervisor(format!("KVM_GET_SREGS(gs): {e}")))?;
        Ok(s.gs.base)
    }

    fn set_gs_base(&mut self, v: u64) -> Result<(), TrapError> {
        crate::kvm::record_kvm_stat(crate::kvm::KvmStat::GetSregs);
        let mut s = self
            .fd()
            .get_sregs()
            .map_err(|e| TrapError::Hypervisor(format!("KVM_GET_SREGS(gs): {e}")))?;
        s.gs.base = v;
        crate::kvm::record_kvm_stat(crate::kvm::KvmStat::SetSregs);
        self.fd()
            .set_sregs(&s)
            .map_err(|e| TrapError::Hypervisor(format!("KVM_SET_SREGS(gs.base): {e}")))
    }

    fn set_syscall_msrs(
        &mut self,
        lstar: u64,
        star: u64,
        sfmask: u64,
    ) -> Result<MsrInstall, TrapError> {
        // KVM exposes the SYSCALL MSRs directly via KVM_SET_MSRS — Direct.
        let msrs = Msrs::from_entries(&[
            kvm_msr_entry {
                index: 0xc000_0081,
                data: star,
                ..Default::default()
            }, // STAR
            kvm_msr_entry {
                index: 0xc000_0082,
                data: lstar,
                ..Default::default()
            }, // LSTAR
            kvm_msr_entry {
                index: 0xc000_0084,
                data: sfmask,
                ..Default::default()
            }, // SFMASK
        ])
        .map_err(|e| TrapError::Hypervisor(format!("kvm-x86: Msrs::from_entries: {e}")))?;
        crate::kvm::record_kvm_stat(crate::kvm::KvmStat::SetMsrs);
        let n = self
            .fd()
            .set_msrs(&msrs)
            .map_err(|e| TrapError::Hypervisor(format!("kvm-x86: KVM_SET_MSRS: {e}")))?;
        if n != 3 {
            return Err(TrapError::Hypervisor(format!(
                "kvm-x86: KVM_SET_MSRS wrote {n}/3 (partial)"
            )));
        }
        Ok(MsrInstall::Direct)
    }

    fn get_fp(&self) -> Result<Option<[u8; 512]>, TrapError> {
        // KVM_GET_FPU yields the native 512-byte fxsave area. The `kvm_fpu`
        // struct's first 512 bytes ARE the legacy fxsave region (fpr/xmm/mxcsr/
        // control words at the architectural offsets), so we serialize it.
        crate::kvm::record_kvm_stat(crate::kvm::KvmStat::GetFpu);
        let fpu = self
            .fd()
            .get_fpu()
            .map_err(|e| TrapError::Hypervisor(format!("KVM_GET_FPU: {e}")))?;
        Ok(Some(kvm_fpu_to_fxsave(&fpu)))
    }

    fn set_fp(&mut self, fx: &[u8; 512]) -> Result<bool, TrapError> {
        crate::kvm::record_kvm_stat(crate::kvm::KvmStat::GetFpu);
        let mut fpu = self
            .fd()
            .get_fpu()
            .map_err(|e| TrapError::Hypervisor(format!("KVM_GET_FPU(set): {e}")))?;
        fxsave_into_kvm_fpu(fx, &mut fpu);
        crate::kvm::record_kvm_stat(crate::kvm::KvmStat::SetFpu);
        self.fd()
            .set_fpu(&fpu)
            .map_err(|e| TrapError::Hypervisor(format!("KVM_SET_FPU: {e}")))?;
        Ok(true)
    }

    fn get_xsave(&self) -> Result<Option<[u8; carrick_x86::XSAVE_LEN]>, TrapError> {
        // KVM_GET_XSAVE yields the standard-format XSAVE area (legacy FXSAVE +
        // 64-byte header + AVX YMM_Hi at offset 576). Copy our XSAVE_LEN-byte
        // prefix out of the 4 KiB `kvm_xsave` region — this is what preserves a
        // guest's AVX upper halves across fork/clone/execve and signals (the
        // FXSAVE-only get_fp drops them, corrupting AVX state).
        let xsave = self
            .fd()
            .get_xsave()
            .map_err(|e| TrapError::Hypervisor(format!("KVM_GET_XSAVE: {e}")))?;
        let mut out = [0u8; carrick_x86::XSAVE_LEN];
        for (i, chunk) in out.chunks_mut(4).enumerate() {
            chunk.copy_from_slice(&xsave.region[i].to_ne_bytes());
        }
        Ok(Some(out))
    }

    fn set_xsave(&mut self, xs: &[u8; carrick_x86::XSAVE_LEN]) -> Result<bool, TrapError> {
        // Read-modify-write: preserve any `kvm_xsave` bytes beyond our window
        // (none with XCR0 = x87|SSE|AVX), overwrite the standard prefix.
        let mut xsave = self
            .fd()
            .get_xsave()
            .map_err(|e| TrapError::Hypervisor(format!("KVM_GET_XSAVE(set): {e}")))?;
        for (i, chunk) in xs.chunks(4).enumerate() {
            xsave.region[i] = u32::from_ne_bytes(chunk.try_into().unwrap_or([0u8; 4]));
        }
        // SAFETY: `xsave` is a fully-initialized kvm_xsave whose standard-format
        // region we populated from a valid XSAVE image; KVM validates xstate_bv.
        unsafe {
            self.fd()
                .set_xsave(&xsave)
                .map_err(|e| TrapError::Hypervisor(format!("KVM_SET_XSAVE: {e}")))?;
        }
        Ok(true)
    }

    fn run(&mut self) -> Result<X86Exit, TrapError> {
        use carrick_hal::{HvVcpu, VcpuExit};

        match <Self as HvVcpu>::run(self).map_err(|e| TrapError::Hypervisor(e.to_string()))? {
            // SYSCALL doorbell: OUT 0xC5 → KVM_EXIT_IO. KVM reports the native
            // current RIP (observed as the OUT address on Linux/KVM); it
            // completes the PIO step when userspace re-enters. The shared x86
            // engine treats either trampoline address as syscall-return state.
            VcpuExit::IoOut { port, .. } if port == carrick_hal::SYSCALL_DOORBELL_PORT => {
                // With KVM_CAP_SYNC_REGS the kernel already mirrored the GPRs into
                // kvm_run.s.regs on this exit (kvm_valid_regs was set before the
                // run), so read the frame from the mmap page — no KVM_GET_REGS.
                let regs = if self.sync_regs_usable() {
                    self.fd().sync_regs().regs
                } else {
                    crate::kvm::record_kvm_stat(crate::kvm::KvmStat::GetRegs);
                    self.fd().get_regs().map_err(|e| {
                        TrapError::Hypervisor(format!("KVM_GET_REGS(doorbell): {e}"))
                    })?
                };
                let frame = carrick_guest_mem::X8664SyscallFrame {
                    rax: regs.rax,
                    rdi: regs.rdi,
                    rsi: regs.rsi,
                    rdx: regs.rdx,
                    r10: regs.r10,
                    r8: regs.r8,
                    r9: regs.r9,
                };
                Ok(X86Exit::Syscall {
                    frame,
                    resume_pc: regs.rip,
                })
            }
            VcpuExit::IoOut { port, data } if port == FAULT_DOORBELL_PORT => {
                self.collect_x86_fault_record(&data)
            }
            VcpuExit::IoOut { port, .. } => {
                let mut msg = format!("kvm-x86: unexpected OUT to port 0x{port:04X}");
                self.append_debug_state(&mut msg);
                Err(TrapError::Hypervisor(msg))
            }
            VcpuExit::Halt => Ok(X86Exit::Halt),
            VcpuExit::Kicked => Ok(X86Exit::Kicked),
            VcpuExit::MmioWrite { gpa, .. } => Err(TrapError::Hypervisor(format!(
                "kvm-x86: unexpected MMIO write to gpa=0x{gpa:x} (ring-3 fault / PML4 gap)"
            ))),
            VcpuExit::Exception { syndrome, far } => Err(TrapError::Hypervisor(format!(
                "kvm-x86: unexpected Exception syndrome=0x{syndrome:x} far=0x{far:x}"
            ))),
        }
    }

    fn enable_halt_exit(&mut self) -> Result<(), TrapError> {
        // KVM exits on HLT by default (KVM_EXIT_HLT); no capability to enable.
        Ok(())
    }
}

/// Serialize a `kvm_fpu` into the 512-byte legacy fxsave layout (Intel SDM
/// vol. 1 §10.5.1): control words +0, st_space (x87) +32, xmm_space +160,
/// mxcsr +24.
fn kvm_fpu_to_fxsave(fpu: &kvm_bindings::kvm_fpu) -> [u8; 512] {
    use zerocopy::IntoBytes;
    let mut fx = [0u8; 512];
    let header = carrick_abi::LinuxFxsaveHeader {
        fcw: fpu.fcw,
        fsw: fpu.fsw,
        ftwx: fpu.ftwx,
        _reserved1: 0,
        last_opcode: fpu.last_opcode,
        last_ip: fpu.last_ip,
        last_dp: fpu.last_dp,
        mxcsr: fpu.mxcsr,
        mxcsr_mask: 0,
    };
    fx[0..32].copy_from_slice(header.as_bytes());
    // st_space: 8 × 16 bytes at +32 (KVM stores [u32; 32] = 128 bytes).
    for (i, w) in fpu.fpr.iter().enumerate() {
        let off = 32 + i * 16;
        fx[off..off + 16].copy_from_slice(&w[..16.min(w.len())]);
    }
    // xmm_space: 16 × 16 bytes at +160.
    for (i, w) in fpu.xmm.iter().enumerate() {
        let off = 160 + i * 16;
        fx[off..off + 16].copy_from_slice(&w[..16.min(w.len())]);
    }
    fx
}

/// Inverse of [`kvm_fpu_to_fxsave`]: load a 512-byte fxsave image into `fpu`.
fn fxsave_into_kvm_fpu(fx: &[u8; 512], fpu: &mut kvm_bindings::kvm_fpu) {
    fpu.fcw = u16::from_le_bytes([fx[0], fx[1]]);
    fpu.fsw = u16::from_le_bytes([fx[2], fx[3]]);
    fpu.ftwx = fx[4];
    fpu.last_opcode = u16::from_le_bytes([fx[6], fx[7]]);
    fpu.last_ip = u64::from_le_bytes(fx[8..16].try_into().unwrap_or_default());
    fpu.last_dp = u64::from_le_bytes(fx[16..24].try_into().unwrap_or_default());
    fpu.mxcsr = u32::from_le_bytes(fx[24..28].try_into().unwrap_or_default());
    for (i, w) in fpu.fpr.iter_mut().enumerate() {
        let off = 32 + i * 16;
        let n = w.len().min(16);
        w[..n].copy_from_slice(&fx[off..off + n]);
    }
    for (i, w) in fpu.xmm.iter_mut().enumerate() {
        let off = 160 + i * 16;
        let n = w.len().min(16);
        w[..n].copy_from_slice(&fx[off..off + n]);
    }
}

#[cfg(test)]
mod tests {
    use carrick_hal::{guest_arch::GuestArch, x8664_arch::X8664GuestArch};
    /// Verify the GDT selector encoding and the STAR arithmetic.
    ///
    /// STAR bits[47:32] = kernel CS selector = 0x08 (GDT[1] kCS64).
    /// STAR bits[63:48] = "user base" = 0x0013; SYSRET computes:
    ///   SS = 0x0013 + 8  = 0x1B (0x18 | RPL3) → GDT[3] uSS with RPL=3
    ///   CS = 0x0013 + 16 = 0x23 (0x20 | RPL3) → GDT[4] uCS64 with RPL=3
    ///
    /// Source: AMD APM vol. 2 §3.1.7 "SYSCALL/SYSRET Target Address Registers".
    #[test]
    fn gdt_selector_encoding() {
        let boot = X8664GuestArch::bootstrap_sysregs();

        // STAR kernel-base field: bits[47:32] = 0x0008 (kernel CS selector).
        assert_eq!(
            (boot.star >> 32) & 0xFFFF,
            0x0008,
            "STAR kernel CS base = 0x08"
        );
        // STAR user-base field: bits[63:48] = 0x0013.
        assert_eq!((boot.star >> 48) & 0xFFFF, 0x0013, "STAR user base = 0x13");

        // Derived user selectors (with RPL=3):
        let user_ss = ((boot.star >> 48) as u16).wrapping_add(8); // 0x1B
        let user_cs = ((boot.star >> 48) as u16).wrapping_add(16); // 0x23
        // Strip RPL bits to get the descriptor index × 8.
        assert_eq!(
            user_ss & !0x3,
            0x18,
            "user SS descriptor index = 0x18 (GDT[3])"
        );
        assert_eq!(
            user_cs & !0x3,
            0x20,
            "user CS descriptor index = 0x20 (GDT[4])"
        );
    }

    /// Verify the segment type nibble constants carry the accessed bit.
    ///
    /// Per Intel SDM vol. 3 §3.4.5.1 "Segment Descriptor", the type field bits:
    ///   bit0 = Accessed, bit1 = Write/Read, bit2 = Expand-Down/Conforming, bit3 = Code/Data.
    ///
    /// Code+Read+Accessed  = 0b1011 = 11 = 0xB.
    /// Data+Write+Accessed = 0b0011 =  3 = 0x3.
    ///
    /// KVM validates these on `KVM_SET_SREGS`; an unset accessed bit causes EINVAL
    /// on some kernels (Ubuntu 18.04 regression, dpw/kvm-hello-world#5 — same
    /// accessed-bit lesson as the bhyve M1 blocker).
    #[test]
    fn segment_type_accessed_bits() {
        assert_eq!(
            (carrick_x86::long_mode_segment_state().kernel_cs_ar & 0xf) as u8,
            11u8,
            "code seg type = 11 (0xB = exec/read/accessed)"
        );
        assert_eq!(
            (carrick_x86::long_mode_segment_state().kernel_data_ar & 0xf) as u8,
            3u8,
            "data seg type =  3 (0x3 = data/write/accessed)"
        );
        // Accessed bit (bit 0) must be set in both.
        assert_ne!(
            (carrick_x86::long_mode_segment_state().kernel_cs_ar & 0xf) as u8 & 1,
            0,
            "(carrick_x86::long_mode_segment_state().kernel_cs_ar & 0xf) as u8 accessed bit set"
        );
        assert_ne!(
            (carrick_x86::long_mode_segment_state().kernel_data_ar & 0xf) as u8 & 1,
            0,
            "(carrick_x86::long_mode_segment_state().kernel_data_ar & 0xf) as u8 accessed bit set"
        );
    }

    /// Verify CR0/CR4/EFER bit patterns match the spec values.
    ///
    /// Sources: Intel SDM vol. 3 §2.5 "Control Registers";
    ///          AMD APM vol. 2 §3.1.7 "Extended Feature Enable Register".
    #[test]
    fn cr0_cr4_efer_bit_patterns() {
        let boot = X8664GuestArch::bootstrap_sysregs();
        // CR0 = 0x8001_0033: PE(0)|MP(1)|ET(4)|NE(5)|WP(16)|PG(31).
        assert_eq!(boot.cr0, 0x8001_0033, "CR0");
        // CR4 = 0x0004_0620: PAE(5)|OSFXSR(9)|OSXMMEXCPT(10)|OSXSAVE(18).
        assert_eq!(boot.cr4, 0x0004_0620, "CR4");
        // EFER = 0x0000_0D01: SCE(0)|LME(8)|LMA(10)|NXE(11).
        assert_eq!(boot.efer, 0x0000_0D01, "EFER");
    }

    /// Verify SFMASK masks the interrupt flag (IF=bit9), so the 2-instruction
    /// LSTAR stub (OUT + SYSRETQ) runs without an interrupt window.
    ///
    /// Source: AMD APM vol. 2 §3.1.7 "SFMASK" + Intel SDM vol. 1 §3.4.3 (IF=bit9).
    #[test]
    fn sfmask_masks_interrupts() {
        let boot = X8664GuestArch::bootstrap_sysregs();
        // IF is bit 9 of RFLAGS.
        assert!(
            boot.sfmask & (1 << 9) != 0,
            "SFMASK must mask IF (bit 9) so no interrupt window in the LSTAR stub"
        );
    }
}
