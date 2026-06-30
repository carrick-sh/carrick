//! `Aarch64GuestArch` — the aarch64 implementation of the [`GuestArch`] seam.
//!
//! Lives in `carrick-hal` (not `carrick-mem`) because `carrick-hal` already
//! depends on `carrick-mem` + `carrick-guest-mem` + `carrick-abi`, while
//! `carrick-mem` does NOT depend on `carrick-hal` (placing the impl in
//! `carrick-mem` would form a `mem → hal → mem` cycle). See the Phase 1 plan,
//! Task 1 Step 1.
//!
//! Phase 1 is behavior-preserving: every method body calls the existing
//! function verbatim. No routing through the trait happens yet (that starts in
//! later plan tasks).

use crate::guest_arch::{GuestArch, PageTableCodec, PtGranule, SyscallRemap, SyscallTable};
use carrick_guest_mem::Aarch64SyscallFrame;

/// ELF `e_machine` for AArch64 (`EM_AARCH64`).
const EM_AARCH64: u16 = 183;

/// AArch64 stage-1 walks 4 levels of a 4 KiB-granule long-descriptor table,
/// 9 index bits per level. Mirrors `carrick-mem::page_table`.
const AARCH64_PAGE_SHIFT: u32 = 12;
const AARCH64_PT_LEVELS: u8 = 4;
const AARCH64_PT_INDEX_BITS: u32 = 9;

/// The AArch64 page-table descriptor codec: the granule parameters mirroring
/// `carrick-mem::page_table` (4 KiB granule, 4 levels) plus the descriptor
/// editor (`PageTableManager`, which carries the per-descriptor bit helpers)
/// and the stateless diagnostic walk, delegated verbatim.
#[derive(Clone, Copy, Debug)]
pub struct Aarch64Mmu;

impl PageTableCodec for Aarch64Mmu {
    fn page_shift() -> u32 {
        AARCH64_PAGE_SHIFT
    }

    fn granule() -> PtGranule {
        PtGranule {
            page_shift: AARCH64_PAGE_SHIFT,
            levels: AARCH64_PT_LEVELS,
            index_bits: AARCH64_PT_INDEX_BITS,
        }
    }

    type Manager = carrick_mem::page_table::PageTableManager;
    type Error = carrick_mem::page_table::PageTableError;

    fn new_manager(bytes: Vec<u8>, base: u64) -> Self::Manager {
        carrick_mem::page_table::PageTableManager::new(bytes, base)
    }

    fn walk_descriptors(bytes: &[u8], base: u64, va: u64) -> [u64; 4] {
        carrick_mem::page_table::walk_descriptors(bytes, base, va)
    }
}

/// The AArch64 syscall-number metadata table — a thin wrapper over
/// `carrick_abi::syscall::lookup_aarch64` (today's `AARCH64_SYSCALLS`).
#[derive(Clone, Copy, Debug)]
pub struct Aarch64SyscallTable;

impl SyscallTable for Aarch64SyscallTable {
    fn name(number: u64) -> Option<&'static str> {
        carrick_abi::syscall::lookup_aarch64(number).map(|syscall| syscall.name)
    }

    fn is_known(number: u64) -> bool {
        carrick_abi::syscall::lookup_aarch64(number).is_some()
    }

    /// AArch64 IS the canonical numbering (asm-generic), so every known
    /// syscall number remaps to itself via `Direct(n)`. Unknown numbers
    /// produce `Unknown` (honest -ENOSYS).
    fn remap(number: u64) -> SyscallRemap {
        if Self::is_known(number) {
            SyscallRemap::Direct(number)
        } else {
            SyscallRemap::Unknown
        }
    }
}

/// The aarch64 initial bring-up sysreg VALUES (see `carrick_mem::arch_sysregs`
/// for the canonical bit-by-bit rationale). Values only; each backend's
/// programming procedure (and its PAN/SPAN divergence) stays backend-private.
#[derive(Clone, Copy, Debug)]
pub struct Aarch64BootSysregs {
    pub mair_el1: u64,
    pub tcr_el1: u64,
    pub sctlr_el1: u64,
    pub cpacr_el1: u64,
}

/// The aarch64 [`GuestArch`] impl. Unit struct selected as `ThreadedEngine::Arch`
/// on both the HVF and KVM backends; monomorphized, so zero-cost.
#[derive(Clone, Copy, Debug, Default)]
pub struct Aarch64GuestArch;

impl GuestArch for Aarch64GuestArch {
    type Frame = Aarch64SyscallFrame;
    type Mmu = Aarch64Mmu;
    type Table = Aarch64SyscallTable;
    type BootSysregs = Aarch64BootSysregs;

    fn decode_syscall(frame: &Self::Frame) -> (u64, [u64; 6]) {
        // Verbatim from `SyscallRequest::from_aarch64_frame`: x8 → number,
        // x0..x5 → the six argument registers.
        (
            frame.x8,
            [frame.x0, frame.x1, frame.x2, frame.x3, frame.x4, frame.x5],
        )
    }

    fn elf_machine() -> u16 {
        EM_AARCH64
    }

    fn uname_machine() -> &'static str {
        "aarch64"
    }

    fn linux_guest_abi() -> carrick_abi::LinuxGuestAbi {
        carrick_abi::LinuxGuestAbi::Aarch64
    }

    fn vdso_bytes() -> Vec<u8> {
        carrick_mem::vdso::vdso_image_bytes()
    }

    fn entry_trampoline_bytes() -> Vec<u8> {
        carrick_mem::memory::el0_trampoline_bytes()
    }

    fn bootstrap_sysregs() -> Aarch64BootSysregs {
        Aarch64BootSysregs {
            mair_el1: carrick_mem::arch_sysregs::MAIR_EL1_BOOTSTRAP,
            tcr_el1: carrick_mem::arch_sysregs::TCR_EL1_BOOTSTRAP,
            sctlr_el1: carrick_mem::arch_sysregs::SCTLR_EL1_BOOTSTRAP,
            cpacr_el1: carrick_mem::arch_sysregs::CPACR_EL1_BOOTSTRAP,
        }
    }

    fn build_sigframe<E: crate::RegAccess + carrick_guest_mem::GuestMemory>(
        engine: &mut E,
        params: crate::sigframe::InjectParams,
    ) -> Result<crate::sigframe::SigframeInject, crate::TrapError> {
        crate::sigframe::build_sigframe(engine, params)
    }

    fn restore_sigframe<E: crate::RegAccess + carrick_guest_mem::GuestMemory>(
        engine: &mut E,
        fpsimd_enabled: bool,
    ) -> Result<crate::sigframe::SigframeRestore, crate::TrapError> {
        crate::sigframe::restore_sigframe(engine, fpsimd_enabled)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decode_maps_x8_and_x0_through_x5() {
        let frame = Aarch64SyscallFrame {
            x0: 10,
            x1: 11,
            x2: 12,
            x3: 13,
            x4: 14,
            x5: 15,
            x8: 64,
        };
        let (number, args) = Aarch64GuestArch::decode_syscall(&frame);
        assert_eq!(number, 64);
        assert_eq!(args, [10, 11, 12, 13, 14, 15]);
    }

    #[test]
    fn arch_tags_are_aarch64() {
        assert_eq!(Aarch64GuestArch::elf_machine(), 183);
        assert_eq!(Aarch64GuestArch::uname_machine(), "aarch64");
    }

    #[test]
    fn vdso_and_trampoline_bytes_are_nonempty() {
        assert!(!Aarch64GuestArch::vdso_bytes().is_empty());
        assert!(!Aarch64GuestArch::entry_trampoline_bytes().is_empty());
    }

    #[test]
    fn syscall_table_knows_a_real_number() {
        // 64 is `write` on aarch64 — present in AARCH64_SYSCALLS.
        assert!(Aarch64SyscallTable::is_known(64));
        assert_eq!(Aarch64SyscallTable::name(64), Some("write"));
        // A wildly-out-of-range number is unknown.
        assert!(!Aarch64SyscallTable::is_known(u64::MAX));
    }

    #[test]
    fn bootstrap_sysregs_match_the_carrick_mem_constants() {
        let boot = Aarch64GuestArch::bootstrap_sysregs();
        assert_eq!(boot.mair_el1, carrick_mem::arch_sysregs::MAIR_EL1_BOOTSTRAP);
        assert_eq!(boot.tcr_el1, carrick_mem::arch_sysregs::TCR_EL1_BOOTSTRAP);
        assert_eq!(
            boot.sctlr_el1,
            carrick_mem::arch_sysregs::SCTLR_EL1_BOOTSTRAP
        );
        assert_eq!(
            boot.cpacr_el1,
            carrick_mem::arch_sysregs::CPACR_EL1_BOOTSTRAP
        );
    }

    #[test]
    fn mmu_granule_is_4kib_4_level() {
        assert_eq!(Aarch64Mmu::page_shift(), 12);
        let granule = Aarch64Mmu::granule();
        assert_eq!(granule.page_shift, 12);
        assert_eq!(granule.levels, 4);
        assert_eq!(granule.index_bits, 9);
    }

    #[test]
    fn mmu_codec_builds_manager_and_walks_descriptors() {
        // A small zeroed table image: every descriptor invalid, so both the
        // manager's translate and the stateless walk see nothing.
        let base = 0x8000_0000u64;
        let bytes = vec![0u8; 4096 * 6];
        let mgr = Aarch64Mmu::new_manager(bytes.clone(), base);
        assert_eq!(mgr.translate(0x40_0000), None);
        assert_eq!(
            Aarch64Mmu::walk_descriptors(&bytes, base, 0x40_0000),
            [0; 4]
        );
    }

    // ── aarch64 sigframe codec round-trip + bad-frame rejection ───────────────
    //
    // The shared aarch64 `rt_sigframe` codec (`crate::sigframe::build_sigframe` /
    // `restore_sigframe`, reached through the `Aarch64GuestArch` seam) had no unit
    // test, while the x86_64 twin in `x8664_arch.rs` did. These drive the REAL
    // encode→decode path against a host-neutral in-memory engine double (no HVF,
    // no guest — plain `cargo test`), mirroring the x86 `SigframeRoundtrip` setup.

    /// A round-trippable aarch64 signal-frame engine: sparse guest memory plus the
    /// GPR / SP / ELR_EL1 / SPSR_EL1 + V-register state the codec reads and writes.
    /// Enough to drive `build_sigframe → restore_sigframe` through the real
    /// `write_bytes` / `read_bytes`.
    struct SigframeEngine {
        mem: std::collections::HashMap<u64, u8>,
        /// x0..x30 (31 GPRs).
        x: [u64; 31],
        sp: u64,
        pc: u64,
        elr_el1: u64,
        spsr_el1: u64,
        vregs: [u128; 32],
        fpsr: u64,
        fpcr: u64,
    }

    impl carrick_guest_mem::GuestMemory for SigframeEngine {
        fn read_bytes_raw(
            &self,
            a: u64,
            l: usize,
        ) -> Result<Vec<u8>, carrick_guest_mem::MemoryError> {
            Ok((0..l as u64)
                .map(|i| *self.mem.get(&a.wrapping_add(i)).unwrap_or(&0))
                .collect())
        }
        fn write_bytes_raw(
            &mut self,
            a: u64,
            b: &[u8],
        ) -> Result<(), carrick_guest_mem::MemoryError> {
            for (i, &byte) in b.iter().enumerate() {
                self.mem.insert(a.wrapping_add(i as u64), byte);
            }
            Ok(())
        }
    }

    impl crate::RegAccess for SigframeEngine {
        fn get_reg(&self, r: crate::Reg) -> Result<u64, crate::OsError> {
            Ok(match r {
                crate::Reg::X(i) => self.x[i as usize],
                crate::Reg::Sp => self.sp,
                crate::Reg::Pc => self.pc,
                crate::Reg::ElrEl1 => self.elr_el1,
                crate::Reg::SpsrEl1 => self.spsr_el1,
                _ => 0,
            })
        }
        fn set_reg(&mut self, r: crate::Reg, v: u64) -> Result<(), crate::OsError> {
            match r {
                crate::Reg::X(i) => self.x[i as usize] = v,
                crate::Reg::Sp => self.sp = v,
                crate::Reg::Pc => self.pc = v,
                crate::Reg::ElrEl1 => self.elr_el1 = v,
                crate::Reg::SpsrEl1 => self.spsr_el1 = v,
                _ => {}
            }
            Ok(())
        }
        fn get_sys_reg(&self, _: crate::SysReg) -> Result<u64, crate::OsError> {
            Ok(0)
        }
        fn set_sys_reg(&mut self, _: crate::SysReg, _: u64) -> Result<(), crate::OsError> {
            Ok(())
        }
        fn get_vreg(&self, n: u32) -> Result<u128, crate::OsError> {
            Ok(self.vregs[n as usize])
        }
        fn set_vreg(&mut self, n: u32, v: u128) -> Result<(), crate::OsError> {
            self.vregs[n as usize] = v;
            Ok(())
        }
        fn get_fpcr(&self) -> Result<u64, crate::OsError> {
            Ok(self.fpcr)
        }
        fn set_fpcr(&mut self, v: u64) -> Result<(), crate::OsError> {
            self.fpcr = v;
            Ok(())
        }
        fn get_fpsr(&self) -> Result<u64, crate::OsError> {
            Ok(self.fpsr)
        }
        fn set_fpsr(&mut self, v: u64) -> Result<(), crate::OsError> {
            self.fpsr = v;
            Ok(())
        }
    }

    fn empty_engine() -> SigframeEngine {
        SigframeEngine {
            mem: std::collections::HashMap::new(),
            x: [0; 31],
            sp: 0,
            pc: 0,
            elr_el1: 0,
            spsr_el1: 0,
            vregs: [0; 32],
            fpsr: 0,
            fpcr: 0,
        }
    }

    /// An `InjectParams` for a plain (no-fault, no-altstack, no-restart) signal
    /// delivery carrying the given interrupted PSTATE. `fpsimd_enabled` is on so
    /// the V-register save/restore path is exercised too.
    fn inject_params(pstate_source: u64) -> crate::sigframe::InjectParams {
        crate::sigframe::InjectParams {
            signum: 11,
            handler: 0x4444_0000,
            sa_restorer: 0x5555_0000,
            pending_syscall_retval: None,
            interrupted_pc: None,
            altstack: None,
            saved_sigmask: 0x00FF,
            fault_siginfo: None,
            queued_siginfo: None,
            restart_syscall: false,
            pstate_source,
            orig_x0: 0,
            fault_esr: 0,
            fpsimd_enabled: true,
            sigreturn_trampoline_base: 0x6666_0000,
        }
    }

    #[test]
    fn aarch64_sigframe_round_trips_gprs_pstate_pc() {
        let mut e = empty_engine();
        // Distinctive pre-signal register state.
        for i in 0..31 {
            e.x[i] = 0x1000 + i as u64;
        }
        e.sp = 0x20_0000; // 16-aligned user stack
        e.elr_el1 = 0xDEAD_BEE0; // becomes saved_pc (interrupted_pc == None)
        // EL0t PSTATE: mode bits [3:0] == 0, NZCV all set to prove the condition
        // flags survive verbatim through the frame.
        let pstate = 0xF000_0000u64;
        for i in 0..32 {
            e.vregs[i] = ((i as u128) << 64) | 0xCAFE_F00D_ABCD;
        }
        e.fpsr = 0x11;
        e.fpcr = 0x22;

        let saved_x = e.x;
        let saved_sp = e.sp;
        let saved_pc = e.elr_el1;
        let saved_vregs = e.vregs;

        let inject = Aarch64GuestArch::build_sigframe(&mut e, inject_params(pstate))
            .expect("build_sigframe writes the frame to the engine's guest memory");

        // build redirected the LIVE registers to the handler-entry ABI (x0=signum,
        // x1/x2 = &siginfo/&ucontext, x30 = restorer, SP = the new frame). The
        // ORIGINALS live only in the frame now. Simulate the handler returning via
        // rt_sigreturn: SP already points at the frame (build set it), so clobber
        // the live GPR/V state to prove restore truly reloads from the frame.
        assert_eq!(e.sp, inject.new_sp, "build leaves SP at the new frame");
        e.x = [0; 31];
        e.vregs = [0; 32];

        let restore = Aarch64GuestArch::restore_sigframe(&mut e, true)
            .expect("restore_sigframe reads the frame back");

        assert_eq!(e.x, saved_x, "x0..x30 must round-trip through the sigframe");
        assert_eq!(e.sp, saved_sp, "SP_EL0 must round-trip");
        assert_eq!(e.elr_el1, saved_pc, "resume PC (ELR_EL1) must round-trip");
        assert_eq!(e.spsr_el1, pstate, "PSTATE (incl. NZCV) must round-trip");
        assert_eq!(restore.saved_pc, saved_pc, "reported saved_pc matches");
        assert_eq!(
            restore.sigmask, 0x00FF,
            "uc_sigmask must round-trip for the caller's resmask"
        );
        assert_eq!(e.vregs, saved_vregs, "V0..V31 must round-trip");
    }

    #[test]
    fn aarch64_sigframe_rejects_non_el0_pstate() {
        use carrick_guest_mem::GuestMemory;
        use zerocopy::IntoBytes;
        // A readable-but-INVALID frame: the restored PSTATE selects a non-EL0
        // exception level (EL1h, mode bits 0b0101). Linux's `valid_user_regs`
        // refuses such a frame at rt_sigreturn; carrick must return
        // SignalDeliveryFault (→ guest force_sigsegv), NOT silently `eret` the vCPU
        // into EL1 garbage. The frame is fully written to guest memory first, so
        // the read SUCCEEDS — this exercises the PSTATE-validation arm, not the
        // bad-SP read-fault arm.
        let mut e = empty_engine();
        let frame_addr = 0x30_0000u64;

        // Build the bad frame via whole-substruct assignment (the packed structs
        // forbid taking references to nested fields).
        let mut mc = carrick_abi::LinuxSignalContext::empty();
        mc.pstate = 0b0101; // EL1h: low nibble != 0 → must be rejected
        mc.regs = [0xBAD0_0000; 31]; // values that MUST NOT be applied
        mc.sp = 0xDEAD;
        mc.pc = 0xBEEF;
        let mut uc = carrick_abi::LinuxUcontext::empty();
        uc.uc_mcontext = mc;
        let mut frame = carrick_abi::CarrickSigframe::empty();
        frame.ucontext = uc;
        e.write_bytes(frame_addr, frame.as_bytes())
            .expect("seed the bad frame into guest memory");
        e.sp = frame_addr;

        let before_x = e.x;
        let before_elr = e.elr_el1;
        match Aarch64GuestArch::restore_sigframe(&mut e, false) {
            Err(crate::TrapError::SignalDeliveryFault) => {}
            Err(other) => panic!(
                "a non-EL0 restored PSTATE must be rejected with SignalDeliveryFault, got {other:?}"
            ),
            Ok(_) => {
                panic!("a non-EL0 restored PSTATE must be rejected, not silently restored")
            }
        }
        // The validation arm fires BEFORE any register write, so the bad frame's
        // contents must not have leaked into the vCPU.
        assert_eq!(e.x, before_x, "rejected frame must not mutate the GPRs");
        assert_eq!(
            e.elr_el1, before_elr,
            "rejected frame must not set the resume PC"
        );
    }
}
