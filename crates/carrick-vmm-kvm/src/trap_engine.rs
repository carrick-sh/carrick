//! `KvmTrapEngine` — now a thin TYPE ALIAS for the shared
//! [`carrick_aarch64::Aarch64EngineCore`] specialized to the KVM aarch64 backend
//! ([`crate::kvm_aarch64_engine::KvmAarch64Vmm`]).
//!
//! Stage 2 of the aarch64-engine consolidation lifted the trap loop, register
//! walk, guest-memory access, stage-1 page-table edits, snapshot/restore pair,
//! fork sequencing, and threaded lifecycle OUT of this file and INTO
//! `carrick-aarch64`, generic over the thin `Aarch64Vmm`/`Aarch64Vcpu` trait
//! pair. The KVM-specific marshalling now lives in
//! [`crate::kvm_aarch64_engine`]; this module keeps only the historical
//! `KvmTrapEngine` name (so `run_elf.rs` / downstream callers are unchanged) plus
//! the `/dev/kvm`-gated unit tests that exercise the KVM bring-up end to end.

use carrick_aarch64::Aarch64EngineCore;
use carrick_hal::TrapError;
use carrick_mem::memory::AddressSpace;

use crate::kvm_aarch64_engine::{KvmAarch64Vmm, bring_up};

/// The KVM aarch64 trap engine: `Aarch64EngineCore<KvmAarch64Vmm>`. The trait
/// surface (`SyscallTrap` / `RegAccess` / `GuestMemory` / `ThreadedEngine`) and
/// the inherent `read_guest` helper are all provided by the shared engine, so
/// every existing call site keeps working through this alias.
pub type KvmTrapEngine = Aarch64EngineCore<KvmAarch64Vmm>;

/// Bring up the guest from a freestanding ELF image and return an engine parked
/// at the EL1 trampoline (the first `next_syscall` runs into EL0). A free function
/// because `KvmTrapEngine` is a type alias to a foreign type, so it cannot carry
/// an inherent `new` in this crate; delegates to
/// [`crate::kvm_aarch64_engine::bring_up`].
pub fn new_kvm_trap_engine(image: &AddressSpace) -> Result<KvmTrapEngine, TrapError> {
    bring_up(image)
}

#[cfg(test)]
mod execve_tests {
    //! `execve_into` (+ fork/inject/alias) unit tests. These build a REAL
    //! `KvmTrapEngine` (needing `/dev/kvm`) and assert post-execve / post-inject
    //! vCPU state directly — no full guest run. They therefore execute only where
    //! `/dev/kvm` is present (the lima L2 lane / a native aarch64 Linux host); on
    //! a host without KVM they SKIP (the crate itself is `cfg(target_os =
    //! "linux")`, so macOS never compiles them). They now drive the SHARED engine
    //! via its public API (accessors + the `*_for_test` setters) rather than the
    //! private fields the old hand-rolled engine exposed.
    use carrick_aarch64::Aarch64Vcpu;
    use carrick_hal::{Reg, RegAccess, SyscallTrap};
    use carrick_mem::memory::{AddressSpace, LINUX_EL1_VECTORS_BASE, LINUX_PAGE_TABLES_BASE};

    use super::*;

    // Two freestanding static aarch64 ELFs committed under fixtures/: the
    // fork-wait4 driver (initial image) and the exit0 execve target (new image).
    // Both are valid ELFs `AddressSpace::load_elf_bytes` can parse.
    const INITIAL_ELF: &[u8] = include_bytes!("../fixtures/fork-wait4/fork-wait4");
    const TARGET_ELF: &[u8] = include_bytes!("../fixtures/exec-target-exit0/exec-target-exit0");

    /// True when `/dev/kvm` is usable; tests SKIP (return early) otherwise so the
    /// suite is green on KVM-less hosts.
    fn kvm_available() -> bool {
        std::path::Path::new("/dev/kvm").exists()
    }

    fn engine_for(bytes: &[u8]) -> KvmTrapEngine {
        let image = AddressSpace::load_elf_bytes(bytes).expect("load test ELF");
        new_kvm_trap_engine(&image).expect("bring up test engine")
    }

    /// Like `engine_for`, but gives the guest a real Linux initial stack (8 MiB at
    /// `LINUX_STACK_TOP`) so signal-frame pushes have writable headroom. The
    /// committed freestanding fixtures (e.g. fork-wait4) deliberately set up no
    /// stack of their own.
    fn engine_for_with_stack(bytes: &[u8]) -> KvmTrapEngine {
        let no_env: [&str; 0] = [];
        let image = AddressSpace::load_elf_bytes(bytes)
            .expect("load test ELF")
            .with_linux_initial_stack(["prog"], no_env)
            .expect("attach initial stack");
        new_kvm_trap_engine(&image).expect("bring up test engine")
    }

    /// Read a system register off the engine's vCPU through the `Aarch64Vcpu` trait.
    fn sys(engine: &KvmTrapEngine, r: carrick_hal::SysReg) -> u64 {
        engine.vcpu().get_sys_reg(r).expect("get_sys_reg")
    }

    /// After `execve_into`, the stage-1 MMU sysregs point at the canonical carrick
    /// page-table / vector bases and MAIR is the Normal-WB value — i.e. the new
    /// image is correctly re-bootstrapped on the LIVE vCPU.
    #[test]
    fn execve_into_reprograms_sysregs() {
        use carrick_hal::SysReg;
        if !kvm_available() {
            eprintln!("SKIP execve_into_reprograms_sysregs: no /dev/kvm");
            return;
        }
        let mut engine = engine_for(INITIAL_ELF);
        let new_image = AddressSpace::load_elf_bytes(TARGET_ELF).expect("load target ELF");
        engine.execve_into(&new_image).expect("execve_into");

        assert_eq!(
            sys(&engine, SysReg::Ttbr0),
            LINUX_PAGE_TABLES_BASE,
            "TTBR0 must point at the stage-1 identity tables"
        );
        assert_eq!(
            sys(&engine, SysReg::Ttbr1),
            LINUX_PAGE_TABLES_BASE,
            "TTBR1 shares the stage-1 root"
        );
        assert_eq!(
            sys(&engine, SysReg::Vbar),
            LINUX_EL1_VECTORS_BASE,
            "VBAR must point at the sentinel EL1 vectors"
        );
        assert_eq!(sys(&engine, SysReg::Mair), 0xFF, "MAIR slot 0 = Normal WB");
        // Stage-1 on (SCTLR_EL1.M = bit 0).
        assert_eq!(
            sys(&engine, SysReg::Sctlr) & 1,
            1,
            "SCTLR_EL1.M must be set (stage-1 MMU on)"
        );
        // execve resets the EL0 thread pointer.
        assert_eq!(
            sys(&engine, SysReg::TpidrEl0),
            0,
            "TPIDR_EL0 must be reset to 0 across execve"
        );
    }

    /// Linux execve starts the new program with x0..x30 clear. Dirty every GPR
    /// before execve and assert they are all zero afterwards.
    #[test]
    fn execve_into_clears_gprs() {
        if !kvm_available() {
            eprintln!("SKIP execve_into_clears_gprs: no /dev/kvm");
            return;
        }
        let mut engine = engine_for(INITIAL_ELF);
        for n in 0..=30u32 {
            engine
                .vcpu_mut()
                .set_reg(Reg::X(n), 0xDEAD_0000 | u64::from(n))
                .unwrap();
        }
        let new_image = AddressSpace::load_elf_bytes(TARGET_ELF).expect("load target ELF");
        engine.execve_into(&new_image).expect("execve_into");
        for n in 0..=30u32 {
            assert_eq!(
                engine.vcpu().get_reg(Reg::X(n)).unwrap(),
                0,
                "x{n} must be cleared by execve"
            );
        }
    }

    /// `is_forked_child` must survive execve (a forked-then-execve'd descendant
    /// keeps the `_exit`-without-report shutdown path).
    #[test]
    fn execve_into_preserves_is_forked_child() {
        if !kvm_available() {
            eprintln!("SKIP execve_into_preserves_is_forked_child: no /dev/kvm");
            return;
        }
        let new_image = AddressSpace::load_elf_bytes(TARGET_ELF).expect("load target ELF");

        // Case A: a NON-forked engine stays non-forked across execve.
        let mut e0 = engine_for(INITIAL_ELF);
        assert!(!e0.is_forked_child());
        e0.execve_into(&new_image)
            .expect("execve_into (non-forked)");
        assert!(
            !e0.is_forked_child(),
            "execve must not spuriously set is_forked_child"
        );

        // Case B: a forked engine stays forked across execve.
        let mut e1 = engine_for(INITIAL_ELF);
        e1.set_is_forked_child_for_test(true);
        e1.execve_into(&new_image).expect("execve_into (forked)");
        assert!(
            e1.is_forked_child(),
            "execve must preserve is_forked_child = true"
        );
    }

    /// PC after execve is the EL0 trampoline base (the vCPU restarts in EL1h and
    /// `eret`s into the new image's entry), and ELR_EL1 holds the new entry.
    #[test]
    fn execve_into_repositions_pc_to_new_entry() {
        if !kvm_available() {
            eprintln!("SKIP execve_into_repositions_pc_to_new_entry: no /dev/kvm");
            return;
        }
        use carrick_mem::memory::LINUX_EL0_TRAMPOLINE_BASE;
        let mut engine = engine_for(INITIAL_ELF);
        let new_image = AddressSpace::load_elf_bytes(TARGET_ELF).expect("load target ELF");
        let new_entry = new_image.entry();
        engine.execve_into(&new_image).expect("execve_into");
        assert_eq!(
            engine.vcpu().get_reg(Reg::Pc).unwrap(),
            LINUX_EL0_TRAMPOLINE_BASE,
            "PC must be the EL0 trampoline so the eret drops to EL0 at the new entry"
        );
        assert_eq!(
            engine.vcpu().get_reg(Reg::ElrEl1).unwrap(),
            new_entry,
            "ELR_EL1 must hold the new image's entry"
        );
    }

    #[test]
    fn kvm_fpsimd_roundtrip() {
        if !kvm_available() {
            eprintln!("SKIP kvm_fpsimd_roundtrip: no /dev/kvm");
            return;
        }
        let mut engine = engine_for(INITIAL_ELF);
        // Distinct u128 patterns into V0..V3, known u32s into FPSR/FPCR, read back.
        for n in 0..4u32 {
            let v = (0x1111_1111_0000_0000u128 << (n as u128)) | (u128::from(n) + 1);
            engine.set_vreg(n, v).unwrap();
            assert_eq!(engine.get_vreg(n).unwrap(), v, "V{n} must round-trip");
        }
        engine.set_fpsr(0x0000_0010).unwrap();
        engine.set_fpcr(0x0040_0000).unwrap();
        assert_eq!(engine.get_fpsr().unwrap(), 0x0000_0010, "FPSR round-trips");
        assert_eq!(engine.get_fpcr().unwrap(), 0x0040_0000, "FPCR round-trips");
    }

    #[test]
    fn kvm_fpsimd_snapshot_restore() {
        if !kvm_available() {
            eprintln!("SKIP kvm_fpsimd_snapshot_restore: no /dev/kvm");
            return;
        }
        let mut engine = engine_for(INITIAL_ELF);
        engine.set_vreg(0, 0xABCD_0000_0000_1234u128).unwrap();
        engine.set_fpsr(0x0000_0008).unwrap();
        let snap = engine.vcpu().snapshot().unwrap();
        assert_eq!(
            snap.vregs[0], 0xABCD_0000_0000_1234u128,
            "snapshot captures V0"
        );
        assert_eq!(snap.fpsr, 0x0000_0008, "snapshot captures FPSR");
        // Trash live state, then restore from the snapshot.
        engine.set_vreg(0, 0).unwrap();
        engine.set_fpsr(0).unwrap();
        engine.vcpu_mut().restore(&snap).unwrap();
        assert_eq!(
            engine.get_vreg(0).unwrap(),
            0xABCD_0000_0000_1234u128,
            "restore recovers V0"
        );
        assert_eq!(
            engine.get_fpsr().unwrap(),
            0x0000_0008,
            "restore recovers FPSR"
        );
    }

    #[test]
    fn kvm_orig_x0_and_nr_captured_on_syscall() {
        if !kvm_available() {
            eprintln!("SKIP kvm_orig_x0_and_nr_captured_on_syscall: no /dev/kvm");
            return;
        }
        let mut engine = engine_for(INITIAL_ELF);
        let frame = engine
            .next_syscall()
            .expect("run to first svc")
            .expect("a syscall frame");
        assert_eq!(
            engine.last_syscall_orig_x0(),
            frame.args[0],
            "orig_x0 latched from frame x0"
        );
        assert_eq!(
            engine.last_syscall_nr(),
            Some(frame.number.raw()),
            "last_syscall_nr latched from frame x8"
        );
    }

    #[test]
    fn kvm_tracking_fields_reset_across_execve() {
        if !kvm_available() {
            eprintln!("SKIP kvm_tracking_fields_reset_across_execve: no /dev/kvm");
            return;
        }
        let mut engine = engine_for(INITIAL_ELF);
        engine.set_last_fault_esr_for_test(0xDEAD);
        engine.set_last_syscall_for_test(Some(99), 0xBEEF);
        let new_image = AddressSpace::load_elf_bytes(TARGET_ELF).expect("load target ELF");
        engine.execve_into(&new_image).expect("execve_into");
        assert_eq!(engine.last_fault_esr(), 0, "fault_esr reset across execve");
        assert_eq!(
            engine.last_syscall_orig_x0(),
            0,
            "orig_x0 reset across execve"
        );
        assert_eq!(
            engine.last_syscall_nr(),
            None,
            "last_syscall_nr reset across execve"
        );
    }

    #[test]
    fn kvm_inject_signal_redirects_to_handler() {
        if !kvm_available() {
            eprintln!("SKIP kvm_inject_signal_redirects_to_handler: no /dev/kvm");
            return;
        }
        let mut engine = engine_for_with_stack(INITIAL_ELF);
        // Run to the guest's first svc so the engine is in a post-syscall state
        // (ELR_EL1 = svc+4, SPSR_EL1 = EL0t, tracking fields populated).
        engine
            .next_syscall()
            .expect("first svc")
            .expect("a syscall frame");

        let handler = 0x4_0000u64;
        let sp_before = engine.get_reg(Reg::Sp).unwrap();
        engine
            .inject_signal(
                libc::SIGUSR1,
                handler,
                0,
                None,
                None,
                None,
                0,
                None,
                None,
                false,
            )
            .expect("inject_signal");

        // Syscall path (interrupted_pc = None) redirects ELR_EL1, not live PC.
        assert_eq!(
            engine.get_reg(Reg::ElrEl1).unwrap(),
            handler,
            "handler entry on ELR_EL1"
        );
        assert_eq!(
            engine.get_reg(Reg::X(0)).unwrap(),
            libc::SIGUSR1 as u64,
            "x0 = signum"
        );
        assert!(
            engine.get_reg(Reg::Sp).unwrap() < sp_before,
            "frame pushed: SP_EL0 moved down"
        );
    }

    #[test]
    fn kvm_inject_then_restore_roundtrips() {
        if !kvm_available() {
            eprintln!("SKIP kvm_inject_then_restore_roundtrips: no /dev/kvm");
            return;
        }
        let mut engine = engine_for_with_stack(INITIAL_ELF);
        engine
            .next_syscall()
            .expect("first svc")
            .expect("a syscall frame");

        let saved_elr = engine.get_reg(Reg::ElrEl1).unwrap(); // pre-signal resume PC
        let saved_sp = engine.get_reg(Reg::Sp).unwrap();
        engine.set_vreg(0, 0x0BAD_F00D_0000_1234u128).unwrap();
        let v0_before = engine.get_vreg(0).unwrap();
        let sigmask = 0x0000_0000_0000_FF00u64;

        engine
            .inject_signal(
                libc::SIGUSR1,
                0x4_0000,
                0,
                None,
                None,
                None,
                sigmask,
                None,
                None,
                false,
            )
            .expect("inject_signal");
        // Simulate the handler clobbering V0 before rt_sigreturn.
        engine.set_vreg(0, 0).unwrap();

        let got_mask = engine
            .restore_from_sigframe()
            .expect("restore_from_sigframe");
        assert_eq!(
            got_mask, sigmask,
            "restore returns the SAVED SIGMASK (not saved_pc)"
        );
        assert_eq!(
            engine.get_reg(Reg::ElrEl1).unwrap(),
            saved_elr,
            "resume PC restored"
        );
        assert_eq!(
            engine.get_reg(Reg::Sp).unwrap(),
            saved_sp,
            "SP_EL0 restored"
        );
        assert_eq!(
            engine.get_vreg(0).unwrap(),
            v0_before,
            "V0 restored from the frame"
        );
    }

    /// `map_host_alias` with `file=None` (a high-VA anonymous alias) seeds the
    /// payload into a fresh KVM-backed window and the syscall read-path resolves
    /// the high alias VA back to it (proving the VA-keyed window + the live slot).
    #[test]
    fn kvm_map_host_alias_anon_roundtrips() {
        use carrick_guest_mem::GuestMemory;
        use carrick_mem::memory::LINUX_HIGH_VA_THRESHOLD;
        if !kvm_available() {
            eprintln!("SKIP kvm_map_host_alias_anon_roundtrips: no /dev/kvm");
            return;
        }
        let mut engine = engine_for(INITIAL_ELF);
        // 2 MiB into the alias VA span (2 MiB-aligned -> map_aliased block path).
        let va = LINUX_HIGH_VA_THRESHOLD + 0x20_0000;
        let payload = b"carrick alias payload".to_vec();
        engine
            .map_host_alias(va, 0, 0x1000, &payload, None)
            .expect("map_host_alias anon");
        let got = engine.read_bytes(va, payload.len()).expect("read alias VA");
        assert_eq!(
            got, payload,
            "read_bytes at the alias VA returns the payload"
        );
    }

    /// `map_host_alias` with `file=Some(..)` maps a host fd MAP_SHARED; the alias
    /// VA reads back the file's bytes (the MAP_SHARED-file coherence path).
    #[test]
    fn kvm_map_host_alias_file_roundtrips() {
        use carrick_guest_mem::GuestMemory;
        use carrick_mem::memory::LINUX_HIGH_VA_THRESHOLD;
        if !kvm_available() {
            eprintln!("SKIP kvm_map_host_alias_file_roundtrips: no /dev/kvm");
            return;
        }
        let mut engine = engine_for(INITIAL_ELF);
        let content = b"file-backed alias via MAP_SHARED";
        // An anonymous host file (memfd) with known content.
        let fd = unsafe { libc::memfd_create(c"carrick-alias".as_ptr(), 0) };
        assert!(fd >= 0, "memfd_create");
        assert_eq!(unsafe { libc::ftruncate(fd, 0x1000) }, 0, "ftruncate");
        let n = unsafe { libc::pwrite(fd, content.as_ptr().cast(), content.len(), 0) };
        assert_eq!(n, content.len() as isize, "pwrite");
        // map_host_alias closes the fd it receives, so hand it a dup.
        let dup = unsafe { libc::dup(fd) };
        assert!(dup >= 0, "dup");
        let va = LINUX_HIGH_VA_THRESHOLD + 0x40_0000;
        engine
            .map_host_alias(
                va,
                0,
                0x1000,
                &[],
                Some((dup, 0, libc::PROT_READ | libc::PROT_WRITE)),
            )
            .expect("map_host_alias file");
        let got = engine
            .read_bytes(va, content.len())
            .expect("read file alias VA");
        assert_eq!(
            got, content,
            "read_bytes at the file-alias VA returns the file content"
        );
        unsafe { libc::close(fd) };
    }

    /// A guest-FIXED VA outside the 64 GiB alias arena (e.g. the Rosetta 128 TiB
    /// range) is rejected with an error, NOT silently mapped to a colliding GPA.
    #[test]
    fn kvm_map_host_alias_rejects_out_of_arena_va() {
        use carrick_mem::memory::LINUX_HIGH_VA_THRESHOLD;
        if !kvm_available() {
            eprintln!("SKIP kvm_map_host_alias_rejects_out_of_arena_va: no /dev/kvm");
            return;
        }
        let mut engine = engine_for(INITIAL_ELF);
        // 1 TiB + ~6.4 TiB: well past the 64 GiB arena.
        let va = LINUX_HIGH_VA_THRESHOLD + 0x10_0000_0000u64 * 100;
        let r = engine.map_host_alias(va, 0, 0x1000, &[1, 2, 3], None);
        assert!(
            r.is_err(),
            "a VA outside the alias arena must be rejected, not corrupt memory"
        );
    }
}
