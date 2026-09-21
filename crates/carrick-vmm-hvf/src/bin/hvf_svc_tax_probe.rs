// SPDX-License-Identifier: Apache-2.0 OR MIT
// Independent Carrick micro-VMM probe; it contains no copied LTP source.
#![allow(
    clippy::expect_used,
    clippy::panic,
    clippy::print_stdout,
    clippy::unwrap_used
)]
//! Micro-vmm syscall-tax probe: what one guest `svc #0` costs as a VM exit.
//!
//! WHAT IT MEASURES (the 2026-08-07 ET_EXEC options paper §7 decisive
//! experiment for Route A, the HVF stage-1 micro-vmm):
//!
//! 1. `svc-exit` — the full `hv_vcpu_run` round trip for one EL0 `svc #0`
//!    under carrick's PRODUCTION guest plumbing: the vCPU enters at the EL0
//!    trampoline (`el0_trampoline_bytes`), drops to EL0, executes `svc #0`,
//!    the EL1 vector page (`el1_vectors_bytes`) forwards it via `hvc #2`, HVF
//!    exits to the host, and the next `hv_vcpu_run` resumes the vector's
//!    `eret` back to EL0. One timed `hv_vcpu_run` therefore brackets exactly
//!    one complete guest-syscall cycle (eret + branch + svc + vector + hvc +
//!    exit + host loop). Three arms: `floor` — stage-1 MMU OFF
//!    (SCTLR_EL1.M=0), no register traffic: the absolute hardware floor of
//!    the exit path. `stage1` — stage-1 MMU ON through the HOST-BUILT
//!    identity tables (`stage1_identity_page_tables`, TTBR0/TTBR1/TCR/MAIR
//!    programmed from `carrick_mem::arch_sysregs` exactly as `trap.rs`
//!    does): the micro-vmm's actual shape, simultaneously re-proving
//!    host-built stage-1 PTs drive an EL0 guest. `dispatch` — `stage1` plus
//!    the minimal per-syscall register traffic a real dispatcher needs when
//!    no mailbox is mapped: 7x `hv_vcpu_get_reg` (x8, x0..x5) + 1x
//!    `hv_vcpu_set_reg` (x0); an upper bracket for register plumbing —
//!    carrick's production mailbox path would sit between `stage1` and this.
//! 2. `portal` — a bounded feasibility experiment for a synchronous shared
//!    syscall portal. EL0 still enters EL1 with `svc #0`, but EL1 publishes a
//!    typed cache-line slot and polls for a host helper's response instead of
//!    issuing one HVC per operation. The guest issues one final HVC after the
//!    whole batch. A fixed same-binary `stage1, portal, portal, stage1` schedule
//!    reports both wall and aggregate process CPU per operation; it does not
//!    implement or select any production syscall behavior.
//! 3. `ulock-ipc` — the cross-process hand-off a shared-VM micro-vmm adds on
//!    top of the exit: a fork-child ping-pong over a `MAP_SHARED` page using
//!    carrick's production futex primitive (`carrick_host::ulock::wait/wake`,
//!    i.e. `os_sync_wait_on_address` SHARED). One timed round trip = wake the
//!    servicing process + it wakes us back = the mailbox hand-off both ways.
//!
//! QUALIFIED FACTS (this host, Mac16,12 M4, macOS 27.0):
//!   - HVF requires the `com.apple.security.hypervisor` entitlement: this
//!     probe run UNSIGNED reports `HV_DENIED(0xfae94007)` from
//!     `hv_vm_create` and exits 2; the SAME binary re-signed with
//!     `scripts/entitlements.plist` succeeds. Sign before trusting a negative.
//!   - `hv_vcpu_run` must be called from the thread that created the vCPU;
//!     everything here runs on the main thread.
//!   - Exit syndrome EC for the vector's `hvc #2` is 0x16 (HVC64); the probe
//!     FAILS CLOSED on any other exit class in a timed window (zero events or
//!     a wrong EC is an error, never an empty summary).
//!
//! PERTURBATION: none of a live workload — the probe is self-contained and
//! runs no guest OS, no carrick runtime, no Docker. Per-iteration `Instant`
//! reads add ~20-40 ns to each measured cycle; the `aggregate` line (whole
//! batch bracketed by two clock reads) bounds that overhead.
//!
//! Scheduling caveat: nothing is pinned (macOS offers no affinity); on this
//! 4P+6E part the scheduler chooses the core class, so distributions can be
//! bimodal (documented in AGENTS.md — core class is never a clean variable).
//! Report the whole distribution, not the mean.
//!
//! Usage: `hvf_svc_tax_probe [all|portal|ipc|floor|stage1|dispatch]` (default all).
//! Output: one JSON line per batch on stdout; provenance lines first.

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
mod imp {
    use std::ffi::c_void;
    use std::ptr;
    use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
    use std::time::Instant;

    use applevisor_sys::{
        HV_MEMORY_EXEC, HV_MEMORY_READ, HV_MEMORY_WRITE, hv_exit_reason_t, hv_reg_t, hv_return_t,
        hv_sys_reg_t, hv_vcpu_create, hv_vcpu_destroy, hv_vcpu_exit_t, hv_vcpu_get_reg,
        hv_vcpu_run, hv_vcpu_set_reg, hv_vcpu_set_sys_reg, hv_vcpu_t, hv_vm_config_create,
        hv_vm_config_get_max_ipa_size, hv_vm_config_set_ipa_size, hv_vm_create, hv_vm_destroy,
        hv_vm_map, os_release,
    };
    use carrick_host::ulock;
    use carrick_mem::arch_sysregs::{
        CPACR_EL1_BOOTSTRAP, MAIR_EL1_BOOTSTRAP, SCTLR_EL1_BOOTSTRAP, TCR_EL1_BOOTSTRAP,
    };
    use carrick_mem::memory::{
        LINUX_EL0_TRAMPOLINE_BASE, LINUX_EL1_VECTORS_BASE, LINUX_PAGE_TABLES_BASE,
        LINUX_SYSCALL_MAILBOX_BASE, el0_trampoline_bytes, el1_vectors_bytes,
        stage1_identity_page_tables,
    };

    const HV_SUCCESS: hv_return_t = 0;
    const HV_DENIED: hv_return_t = 0xfae94007u32 as hv_return_t;

    /// Guest VA/IPA of the `svc #0` loop page. 4 MiB: inside the stage-1
    /// identity map's user 2 MiB blocks (executable, UXN clear) and 16 KiB
    /// aligned for `hv_vm_map`. Deliberately a LOW address — the exact class
    /// of VA the micro-vmm exists to serve (Go's ET_EXEC text).
    const GUEST_CODE_BASE: u64 = 0x40_0000;
    // The EL1 handler must use a privileged stage-1 mapping. A low user VA is
    // blocked by PAN on exception entry before it can publish the request.
    const PORTAL_SLOT_BASE: u64 = LINUX_SYSCALL_MAILBOX_BASE;
    const REGION_ALIGN: usize = 0x4000; // HVF page size (16 KiB)

    const AARCH64_SVC0: u32 = 0xd400_0001; // svc #0
    const AARCH64_B_BACK_4: u32 = 0x17ff_ffff; // b .-4 (back to the svc)
    const AARCH64_ERET_OPCODE: u32 = 0xd69f_03e0;
    const AARCH64_HVC_SYSCALL_OPCODE: u32 = 0xd400_0042; // hvc #2
    const PORTAL_EXIT_NR: u16 = 1;
    const LOWER_EL_SYNC_OFFSET: usize = 0x400;

    // PSTATE values, mirroring `trap.rs`.
    const PSTATE_EL1H_DAIF_MASKED: u64 = 0x3c5;
    const PSTATE_EL0T_DAIF_MASKED: u64 = 0x3c0;

    const WARMUP_ITERS: usize = 1_000;
    const BATCHES: usize = 5;
    const EXIT_ITERS_PER_BATCH: usize = 20_000;
    const IPC_ITERS_PER_BATCH: usize = 10_000;
    const PORTAL_ITERS_PER_BATCH: usize = 20_000;

    /// One fixed-layout host/EL1 protocol slot used only by the feasibility probe.
    ///
    /// The fields are named and offset-checked so the emitted instructions and
    /// host helper share a typed protocol rather than ad-hoc byte offsets.
    #[repr(C, align(64))]
    struct PortalSlot {
        request: AtomicU32,
        response: AtomicU32,
        stop: AtomicU32,
        _reserved: [u8; 52],
    }

    impl PortalSlot {
        const fn new() -> Self {
            Self {
                request: AtomicU32::new(0),
                response: AtomicU32::new(0),
                stop: AtomicU32::new(0),
                _reserved: [0; 52],
            }
        }
    }

    const _: () = assert!(std::mem::size_of::<PortalSlot>() == 64);
    const _: () = assert!(std::mem::align_of::<PortalSlot>() == 64);

    struct Vm {
        vcpu: hv_vcpu_t,
        exit: *const hv_vcpu_exit_t,
        // Host allocations backing guest regions; kept alive for the VM's life.
        allocations: Vec<(*mut c_void, usize)>,
    }

    impl Vm {
        fn create() -> Result<Self, hv_return_t> {
            let mut max_ipa = 0u32;
            let rc = unsafe { hv_vm_config_get_max_ipa_size(&mut max_ipa) };
            if rc != HV_SUCCESS {
                return Err(rc);
            }
            let config = unsafe { hv_vm_config_create() };
            if config.is_null() {
                return Err(HV_DENIED);
            }
            let rc = unsafe { hv_vm_config_set_ipa_size(config, max_ipa) };
            if rc != HV_SUCCESS {
                unsafe { os_release(config.cast::<c_void>()) };
                return Err(rc);
            }
            let rc = unsafe { hv_vm_create(config) };
            unsafe { os_release(config.cast::<c_void>()) };
            if rc != HV_SUCCESS {
                return Err(rc);
            }
            let mut vcpu = 0;
            let mut exit: *const hv_vcpu_exit_t = ptr::null();
            let rc = unsafe { hv_vcpu_create(&mut vcpu, &mut exit, ptr::null_mut()) };
            if rc != HV_SUCCESS {
                let _ = unsafe { hv_vm_destroy() };
                return Err(rc);
            }
            Ok(Self {
                vcpu,
                exit,
                allocations: Vec::new(),
            })
        }

        /// Map `bytes` into the guest at `ipa` (16 KiB-aligned), padding the
        /// backing host allocation to the HVF page size.
        fn map(&mut self, ipa: u64, bytes: &[u8]) -> *mut c_void {
            assert!(
                (ipa as usize).is_multiple_of(REGION_ALIGN),
                "unaligned ipa 0x{ipa:x}"
            );
            let size = bytes.len().next_multiple_of(REGION_ALIGN);
            let host = unsafe {
                libc::mmap(
                    ptr::null_mut(),
                    size,
                    libc::PROT_READ | libc::PROT_WRITE,
                    libc::MAP_ANON | libc::MAP_PRIVATE,
                    -1,
                    0,
                )
            };
            assert!(host != libc::MAP_FAILED, "host mmap failed");
            unsafe {
                ptr::copy_nonoverlapping(bytes.as_ptr(), host.cast::<u8>(), bytes.len());
            }
            let rc = unsafe {
                hv_vm_map(
                    host,
                    ipa,
                    size,
                    HV_MEMORY_READ | HV_MEMORY_WRITE | HV_MEMORY_EXEC,
                )
            };
            assert!(
                rc == HV_SUCCESS,
                "hv_vm_map(0x{ipa:x}, 0x{size:x}) -> {}",
                rc_label(rc)
            );
            self.allocations.push((host, size));
            host
        }

        fn set_sys(&self, reg: hv_sys_reg_t, value: u64) {
            let rc = unsafe { hv_vcpu_set_sys_reg(self.vcpu, reg, value) };
            assert!(rc == HV_SUCCESS, "set_sys_reg {reg:?} -> {}", rc_label(rc));
        }

        fn set_reg(&self, reg: hv_reg_t, value: u64) {
            let rc = unsafe { hv_vcpu_set_reg(self.vcpu, reg, value) };
            assert!(rc == HV_SUCCESS, "set_reg {reg:?} -> {}", rc_label(rc));
        }

        fn get_reg(&self, reg: hv_reg_t) -> u64 {
            let mut value = 0u64;
            let rc = unsafe { hv_vcpu_get_reg(self.vcpu, reg, &mut value) };
            assert!(rc == HV_SUCCESS, "get_reg {reg:?} -> {}", rc_label(rc));
            value
        }

        /// Run once and demand the exit be the vector page's `hvc #2`
        /// (EC=0x16). Fails loud with the full syndrome otherwise: a silent
        /// wrong-class exit would time the wrong thing.
        fn run_expect_hvc(&self) {
            let rc = unsafe { hv_vcpu_run(self.vcpu) };
            assert!(rc == HV_SUCCESS, "hv_vcpu_run -> {}", rc_label(rc));
            let exit = unsafe { self.exit.as_ref() }.expect("null exit pointer");
            let syndrome = exit.exception.syndrome;
            let ec = (syndrome >> 26) & 0x3f;
            assert!(
                exit.reason == hv_exit_reason_t::EXCEPTION && ec == 0x16,
                "unexpected exit: reason={:?} syndrome=0x{:x} (EC=0x{:x}) va=0x{:x} pa=0x{:x}",
                exit.reason,
                syndrome,
                ec,
                exit.exception.virtual_address,
                exit.exception.physical_address,
            );
            // HVF leaves PC on the trapping HVC. Production completion must
            // advance past that transport instruction before it resumes the
            // EL1 vector, so the probe includes the same required host work.
            let pc = self.get_reg(hv_reg_t::PC);
            self.set_reg(hv_reg_t::PC, pc + 4);
        }

        fn destroy(mut self) {
            let rc = unsafe { hv_vcpu_destroy(self.vcpu) };
            assert!(rc == HV_SUCCESS, "hv_vcpu_destroy -> {}", rc_label(rc));
            let rc = unsafe { hv_vm_destroy() };
            assert!(rc == HV_SUCCESS, "hv_vm_destroy -> {}", rc_label(rc));
            for (host, size) in self.allocations.drain(..) {
                unsafe { libc::munmap(host, size) };
            }
        }
    }

    fn guest_code_page() -> Vec<u8> {
        let mut bytes = vec![0u8; REGION_ALIGN];
        bytes[0..4].copy_from_slice(&AARCH64_SVC0.to_le_bytes());
        bytes[4..8].copy_from_slice(&AARCH64_B_BACK_4.to_le_bytes());
        bytes
    }

    fn enc_movz_xn(reg: u32, imm16: u16, hw: u32) -> u32 {
        0xD280_0000 | (hw << 21) | (u32::from(imm16) << 5) | (reg & 0x1f)
    }

    fn enc_movk_xn(reg: u32, imm16: u16, hw: u32) -> u32 {
        0xF280_0000 | (hw << 21) | (u32::from(imm16) << 5) | (reg & 0x1f)
    }

    fn enc_cmp_x8_imm(imm: u16) -> u32 {
        0xF100_011F | ((u32::from(imm) & 0xfff) << 10)
    }

    fn enc_bne(pc: usize, target: usize) -> u32 {
        let imm19 = (((target as i64 - pc as i64) >> 2) as u32) & 0x7ffff;
        0x5400_0001 | (imm19 << 5)
    }

    fn enc_add_xd_xn_imm(rd: u32, rn: u32, imm: u16) -> u32 {
        0x9100_0000 | ((u32::from(imm) & 0xfff) << 10) | ((rn & 0x1f) << 5) | (rd & 0x1f)
    }

    fn enc_ldr_wt_xn(rt: u32, rn: u32, offset: usize) -> u32 {
        0xB940_0000 | ((((offset / 4) as u32) & 0xfff) << 10) | ((rn & 0x1f) << 5) | (rt & 0x1f)
    }

    fn enc_add_wd_wn_imm(rd: u32, rn: u32, imm: u16) -> u32 {
        0x1100_0000 | ((u32::from(imm) & 0xfff) << 10) | ((rn & 0x1f) << 5) | (rd & 0x1f)
    }

    fn enc_subs_xd_xn_imm(rd: u32, rn: u32, imm: u16) -> u32 {
        0xF100_0000 | ((u32::from(imm) & 0xfff) << 10) | ((rn & 0x1f) << 5) | (rd & 0x1f)
    }

    fn enc_stlr_wt_xn(rt: u32, rn: u32) -> u32 {
        0x889F_FC00 | ((rn & 0x1f) << 5) | (rt & 0x1f)
    }

    fn enc_ldar_wt_xn(rt: u32, rn: u32) -> u32 {
        0x88DF_FC00 | ((rn & 0x1f) << 5) | (rt & 0x1f)
    }

    fn enc_cmp_wn_wm(rn: u32, rm: u32) -> u32 {
        0x6B00_001F | ((rm & 0x1f) << 16) | ((rn & 0x1f) << 5)
    }

    fn put_word(bytes: &mut [u8], offset: usize, word: u32) {
        bytes[offset..offset + 4].copy_from_slice(&word.to_le_bytes());
    }

    /// EL1 handler for the experiment. SVCs with x8=0 publish `request` and
    /// wait for the matching `response`; nonzero x8 exits to the host. The
    /// latter provides one untimed ready exit and one timed exit after the
    /// full batch, without adding a separate instruction protocol.
    fn portal_vector_page() -> Vec<u8> {
        let mut bytes = el1_vectors_bytes();
        let mut pc = LOWER_EL_SYNC_OFFSET;
        let emit = |bytes: &mut [u8], pc: &mut usize, word: u32| {
            put_word(bytes, *pc, word);
            *pc += 4;
        };
        emit(&mut bytes, &mut pc, enc_cmp_x8_imm(0));
        let exit_branch = pc;
        emit(&mut bytes, &mut pc, 0);
        emit(
            &mut bytes,
            &mut pc,
            enc_movz_xn(16, PORTAL_SLOT_BASE as u16, 0),
        );
        for half in 1..4 {
            emit(
                &mut bytes,
                &mut pc,
                enc_movk_xn(16, (PORTAL_SLOT_BASE >> (half * 16)) as u16, half),
            );
        }
        emit(
            &mut bytes,
            &mut pc,
            enc_ldr_wt_xn(17, 16, std::mem::offset_of!(PortalSlot, request)),
        );
        emit(&mut bytes, &mut pc, enc_add_wd_wn_imm(17, 17, 1));
        emit(&mut bytes, &mut pc, enc_stlr_wt_xn(17, 16));
        emit(&mut bytes, &mut pc, enc_add_xd_xn_imm(16, 16, 4));
        let poll = pc;
        emit(&mut bytes, &mut pc, enc_ldar_wt_xn(0, 16));
        emit(&mut bytes, &mut pc, enc_cmp_wn_wm(0, 17));
        let poll_branch = pc;
        emit(&mut bytes, &mut pc, enc_bne(poll_branch, poll));
        emit(&mut bytes, &mut pc, enc_movz_xn(0, 0, 0));
        emit(&mut bytes, &mut pc, AARCH64_ERET_OPCODE);
        let exit = pc;
        emit(&mut bytes, &mut pc, AARCH64_HVC_SYSCALL_OPCODE);
        emit(&mut bytes, &mut pc, AARCH64_ERET_OPCODE);
        put_word(&mut bytes, exit_branch, enc_bne(exit_branch, exit));
        bytes
    }

    fn portal_guest_code_page() -> Vec<u8> {
        let mut bytes = vec![0u8; REGION_ALIGN];
        // Untimed ready exit: the timed run starts after the trampoline and
        // first EL0->EL1->host transition have completed.
        put_word(&mut bytes, 0, enc_movz_xn(8, PORTAL_EXIT_NR, 0));
        put_word(&mut bytes, 4, AARCH64_SVC0);
        put_word(&mut bytes, 8, enc_movz_xn(8, 0, 0));
        put_word(&mut bytes, 12, AARCH64_SVC0);
        put_word(&mut bytes, 16, enc_subs_xd_xn_imm(20, 20, 1));
        put_word(&mut bytes, 20, enc_bne(20, 12));
        put_word(&mut bytes, 24, enc_movz_xn(8, PORTAL_EXIT_NR, 0));
        put_word(&mut bytes, 28, AARCH64_SVC0);
        put_word(&mut bytes, 32, 0x1400_0000); // b .
        bytes
    }

    /// Build a VM parked at carrick's EL0 entry trampoline with the EL1
    /// vector page installed, ready to loop `svc #0` at EL0. `stage1` selects
    /// the host-built identity page tables (the micro-vmm shape) vs MMU off.
    fn build_svc_vm(stage1: bool) -> Vm {
        let mut vm = match Vm::create() {
            Ok(vm) => vm,
            Err(rc) => {
                println!(
                    "{{\"probe\":\"svc-exit\",\"error\":\"hv_vm_create\",\"rc\":\"{}\"}}",
                    rc_label(rc)
                );
                if rc == HV_DENIED {
                    eprintln!(
                        "HV_DENIED: this binary is not signed with \
                         com.apple.security.hypervisor; sign it with \
                         scripts/entitlements.plist before trusting a negative"
                    );
                }
                std::process::exit(2);
            }
        };
        vm.map(LINUX_EL0_TRAMPOLINE_BASE, &el0_trampoline_bytes());
        vm.map(LINUX_EL1_VECTORS_BASE, &el1_vectors_bytes());
        vm.map(GUEST_CODE_BASE, &guest_code_page());
        if stage1 {
            vm.map(LINUX_PAGE_TABLES_BASE, &stage1_identity_page_tables());
        }

        // Mirrors `trap.rs` map_plan initial-boot programming.
        vm.set_reg(hv_reg_t::CPSR, PSTATE_EL1H_DAIF_MASKED);
        vm.set_reg(hv_reg_t::PC, LINUX_EL0_TRAMPOLINE_BASE);
        vm.set_sys(hv_sys_reg_t::SPSR_EL1, PSTATE_EL0T_DAIF_MASKED);
        vm.set_sys(hv_sys_reg_t::ELR_EL1, GUEST_CODE_BASE);
        vm.set_sys(hv_sys_reg_t::VBAR_EL1, LINUX_EL1_VECTORS_BASE);
        vm.set_sys(hv_sys_reg_t::CPACR_EL1, CPACR_EL1_BOOTSTRAP);
        let mut sctlr = SCTLR_EL1_BOOTSTRAP & !1;
        if stage1 {
            vm.set_sys(hv_sys_reg_t::MAIR_EL1, MAIR_EL1_BOOTSTRAP);
            vm.set_sys(hv_sys_reg_t::TCR_EL1, TCR_EL1_BOOTSTRAP);
            vm.set_sys(hv_sys_reg_t::TTBR0_EL1, LINUX_PAGE_TABLES_BASE);
            vm.set_sys(hv_sys_reg_t::TTBR1_EL1, LINUX_PAGE_TABLES_BASE);
            sctlr |= 1;
        }
        vm.set_sys(hv_sys_reg_t::SCTLR_EL1, sctlr);
        vm
    }

    /// Build the isolated portal guest and return its typed host mapping.
    /// The mapping is owned by `Vm`, and the helper is always joined before
    /// `Vm::destroy` unmaps it.
    fn build_portal_vm(iters: usize) -> (Vm, *mut PortalSlot) {
        let mut vm = match Vm::create() {
            Ok(vm) => vm,
            Err(rc) => {
                println!(
                    "{{\"probe\":\"svc-portal\",\"error\":\"hv_vm_create\",\"rc\":\"{}\"}}",
                    rc_label(rc)
                );
                if rc == HV_DENIED {
                    eprintln!(
                        "HV_DENIED: this binary is not signed with \
                         com.apple.security.hypervisor; sign it with \
                         scripts/entitlements.plist before trusting a negative"
                    );
                }
                std::process::exit(2);
            }
        };
        vm.map(LINUX_EL0_TRAMPOLINE_BASE, &el0_trampoline_bytes());
        vm.map(LINUX_EL1_VECTORS_BASE, &portal_vector_page());
        vm.map(GUEST_CODE_BASE, &portal_guest_code_page());
        vm.map(LINUX_PAGE_TABLES_BASE, &stage1_identity_page_tables());
        let portal = vm
            .map(PORTAL_SLOT_BASE, &vec![0u8; REGION_ALIGN])
            .cast::<PortalSlot>();
        unsafe { portal.write(PortalSlot::new()) };

        vm.set_reg(hv_reg_t::CPSR, PSTATE_EL1H_DAIF_MASKED);
        vm.set_reg(hv_reg_t::PC, LINUX_EL0_TRAMPOLINE_BASE);
        vm.set_reg(hv_reg_t::X20, iters as u64);
        vm.set_sys(hv_sys_reg_t::SPSR_EL1, PSTATE_EL0T_DAIF_MASKED);
        vm.set_sys(hv_sys_reg_t::ELR_EL1, GUEST_CODE_BASE);
        vm.set_sys(hv_sys_reg_t::VBAR_EL1, LINUX_EL1_VECTORS_BASE);
        vm.set_sys(hv_sys_reg_t::CPACR_EL1, CPACR_EL1_BOOTSTRAP);
        vm.set_sys(hv_sys_reg_t::MAIR_EL1, MAIR_EL1_BOOTSTRAP);
        vm.set_sys(hv_sys_reg_t::TCR_EL1, TCR_EL1_BOOTSTRAP);
        vm.set_sys(hv_sys_reg_t::TTBR0_EL1, LINUX_PAGE_TABLES_BASE);
        vm.set_sys(hv_sys_reg_t::TTBR1_EL1, LINUX_PAGE_TABLES_BASE);
        vm.set_sys(hv_sys_reg_t::SCTLR_EL1, SCTLR_EL1_BOOTSTRAP | 1);
        (vm, portal)
    }

    #[derive(Clone, Copy)]
    struct PortalSample {
        wall_ns: u64,
        cpu_ns: u64,
        iters: usize,
        exits: usize,
    }

    impl PortalSample {
        fn wall_ns_per_op(self) -> f64 {
            self.wall_ns as f64 / self.iters as f64
        }

        fn cpu_ns_per_op(self) -> f64 {
            self.cpu_ns as f64 / self.iters as f64
        }
    }

    /// Aggregate process CPU includes the vCPU runner and portal helper, so a
    /// wall-time win cannot hide a full busy core in this experiment.
    fn process_cpu_ns() -> u64 {
        let mut usage = unsafe { std::mem::zeroed::<libc::rusage>() };
        let rc = unsafe { libc::getrusage(libc::RUSAGE_SELF, &mut usage) };
        assert_eq!(rc, 0, "getrusage(RUSAGE_SELF) failed");
        let user =
            usage.ru_utime.tv_sec as u64 * 1_000_000_000 + usage.ru_utime.tv_usec as u64 * 1_000;
        let system =
            usage.ru_stime.tv_sec as u64 * 1_000_000_000 + usage.ru_stime.tv_usec as u64 * 1_000;
        user + system
    }

    fn measure_stage1_batch(iters: usize) -> PortalSample {
        let vm = build_svc_vm(true);
        vm.run_expect_hvc();
        let cpu_before = process_cpu_ns();
        let wall_before = Instant::now();
        for _ in 0..iters {
            vm.run_expect_hvc();
        }
        let wall_ns = wall_before.elapsed().as_nanos() as u64;
        let cpu_ns = process_cpu_ns() - cpu_before;
        vm.destroy();
        PortalSample {
            wall_ns,
            cpu_ns,
            iters,
            exits: iters,
        }
    }

    fn measure_portal_batch(iters: usize) -> PortalSample {
        assert!(iters > 0 && iters <= u32::MAX as usize);
        let (vm, portal) = build_portal_vm(iters);
        // Consume the explicit ready exit outside both clocks.
        vm.run_expect_hvc();

        let ready = std::sync::Arc::new(AtomicBool::new(false));
        let helper_ready = ready.clone();
        let portal_address = portal as usize;
        let helper = std::thread::spawn(move || {
            let slot = unsafe { &*(portal_address as *const PortalSlot) };
            helper_ready.store(true, Ordering::Release);
            let mut seen = 0u32;
            while seen < iters as u32 && slot.stop.load(Ordering::Relaxed) == 0 {
                let request = slot.request.load(Ordering::Acquire);
                if request != seen {
                    assert_eq!(request, seen + 1, "portal request skipped a sequence");
                    slot.response.store(request, Ordering::Release);
                    seen = request;
                } else {
                    std::hint::spin_loop();
                }
            }
            seen
        });
        while !ready.load(Ordering::Acquire) {
            std::hint::spin_loop();
        }

        let cpu_before = process_cpu_ns();
        let wall_before = Instant::now();
        vm.run_expect_hvc();
        let wall_ns = wall_before.elapsed().as_nanos() as u64;
        let cpu_ns = process_cpu_ns() - cpu_before;
        unsafe { &*portal }.stop.store(1, Ordering::Release);
        let serviced = helper.join().expect("portal helper panicked");
        let slot = unsafe { &*portal };
        assert_eq!(serviced, iters as u32);
        assert_eq!(slot.request.load(Ordering::Acquire), iters as u32);
        assert_eq!(slot.response.load(Ordering::Acquire), iters as u32);
        vm.destroy();
        PortalSample {
            wall_ns,
            cpu_ns,
            iters,
            exits: 1,
        }
    }

    fn report_portal_sample(arm: &str, block: usize, order: usize, sample: PortalSample) {
        println!(
            "{{\"probe\":\"svc-portal\",\"arm\":\"{arm}\",\"block\":{block},\
             \"order\":{order},\"iters\":{},\"exits\":{},\"wall_ns\":{},\
             \"wall_ns_per_op\":{:.1},\"cpu_ns\":{},\"cpu_ns_per_op\":{:.1}}}",
            sample.iters,
            sample.exits,
            sample.wall_ns,
            sample.wall_ns_per_op(),
            sample.cpu_ns,
            sample.cpu_ns_per_op(),
        );
    }

    fn run_portal_probe() {
        // Separate VMs make warm-up and every ABBA leg independent. VM setup,
        // stage-1 installation, and helper creation are outside the clocks.
        let _ = measure_stage1_batch(WARMUP_ITERS);
        let _ = measure_portal_batch(WARMUP_ITERS);
        for block in 1..=BATCHES {
            let stage1_a = measure_stage1_batch(PORTAL_ITERS_PER_BATCH);
            let portal_a = measure_portal_batch(PORTAL_ITERS_PER_BATCH);
            let portal_b = measure_portal_batch(PORTAL_ITERS_PER_BATCH);
            let stage1_b = measure_stage1_batch(PORTAL_ITERS_PER_BATCH);
            report_portal_sample("stage1", block, 0, stage1_a);
            report_portal_sample("portal", block, 1, portal_a);
            report_portal_sample("portal", block, 2, portal_b);
            report_portal_sample("stage1", block, 3, stage1_b);

            let stage1_wall = (stage1_a.wall_ns_per_op() + stage1_b.wall_ns_per_op()) / 2.0;
            let portal_wall = (portal_a.wall_ns_per_op() + portal_b.wall_ns_per_op()) / 2.0;
            let stage1_cpu = (stage1_a.cpu_ns_per_op() + stage1_b.cpu_ns_per_op()) / 2.0;
            let portal_cpu = (portal_a.cpu_ns_per_op() + portal_b.cpu_ns_per_op()) / 2.0;
            println!(
                "{{\"probe\":\"svc-portal-comparison\",\"block\":{block},\
                 \"stage1_wall_ns_per_op\":{stage1_wall:.1},\
                 \"portal_wall_ns_per_op\":{portal_wall:.1},\
                 \"portal_to_stage1_wall_ratio\":{:.3},\
                 \"stage1_cpu_ns_per_op\":{stage1_cpu:.1},\
                 \"portal_cpu_ns_per_op\":{portal_cpu:.1},\
                 \"portal_to_stage1_cpu_ratio\":{:.3}}}",
                portal_wall / stage1_wall,
                portal_cpu / stage1_cpu,
            );
        }
    }

    fn percentile(sorted: &[u64], p: f64) -> u64 {
        let index = ((sorted.len() as f64) * p) as usize;
        sorted[index.min(sorted.len() - 1)]
    }

    fn report(probe: &str, arm: &str, batch: usize, mut lat_ns: Vec<u64>, extra: &str) {
        lat_ns.sort_unstable();
        let n = lat_ns.len();
        let mean = lat_ns.iter().sum::<u64>() as f64 / n as f64;
        println!(
            "{{\"probe\":\"{probe}\",\"arm\":\"{arm}\",\"batch\":{batch},\"iters\":{n},\
             \"unit\":\"ns\",\"min\":{},\"p25\":{},\"p50\":{},\"p75\":{},\"p90\":{},\
             \"p95\":{},\"p99\":{},\"p999\":{},\"max\":{},\"mean\":{mean:.1}{extra}}}",
            lat_ns[0],
            percentile(&lat_ns, 0.25),
            percentile(&lat_ns, 0.50),
            percentile(&lat_ns, 0.75),
            percentile(&lat_ns, 0.90),
            percentile(&lat_ns, 0.95),
            percentile(&lat_ns, 0.99),
            percentile(&lat_ns, 0.999),
            lat_ns[n - 1],
        );
    }

    fn run_exit_arm(arm: &str, stage1: bool, dispatch_regs: bool) {
        let vm = build_svc_vm(stage1);
        // First entry: trampoline (tlbi/ic/isb/eret) + first EL0 svc. Prove
        // the plumbing before timing anything.
        vm.run_expect_hvc();
        for _ in 0..WARMUP_ITERS {
            vm.run_expect_hvc();
        }
        for batch in 1..=BATCHES {
            let mut lat = Vec::with_capacity(EXIT_ITERS_PER_BATCH);
            for _ in 0..EXIT_ITERS_PER_BATCH {
                let t0 = Instant::now();
                vm.run_expect_hvc();
                if dispatch_regs {
                    // The minimal syscall ABI read a dispatcher needs
                    // (nr + 6 args) and the return-value write.
                    let mut acc = vm.get_reg(hv_reg_t::X8);
                    acc ^= vm.get_reg(hv_reg_t::X0);
                    acc ^= vm.get_reg(hv_reg_t::X1);
                    acc ^= vm.get_reg(hv_reg_t::X2);
                    acc ^= vm.get_reg(hv_reg_t::X3);
                    acc ^= vm.get_reg(hv_reg_t::X4);
                    acc ^= vm.get_reg(hv_reg_t::X5);
                    vm.set_reg(hv_reg_t::X0, acc & 0xfff);
                }
                lat.push(t0.elapsed().as_nanos() as u64);
            }
            report("svc-exit", arm, batch, lat, "");
        }
        // Timer-overhead bound: one batch bracketed by a single clock pair.
        let t0 = Instant::now();
        for _ in 0..EXIT_ITERS_PER_BATCH {
            vm.run_expect_hvc();
            if dispatch_regs {
                let mut acc = vm.get_reg(hv_reg_t::X8);
                acc ^= vm.get_reg(hv_reg_t::X0);
                acc ^= vm.get_reg(hv_reg_t::X1);
                acc ^= vm.get_reg(hv_reg_t::X2);
                acc ^= vm.get_reg(hv_reg_t::X3);
                acc ^= vm.get_reg(hv_reg_t::X4);
                acc ^= vm.get_reg(hv_reg_t::X5);
                vm.set_reg(hv_reg_t::X0, acc & 0xfff);
            }
        }
        let aggregate_ns = t0.elapsed().as_nanos() as u64 / EXIT_ITERS_PER_BATCH as u64;
        println!(
            "{{\"probe\":\"svc-exit\",\"arm\":\"{arm}\",\"mode\":\"aggregate\",\
             \"iters\":{EXIT_ITERS_PER_BATCH},\"unit\":\"ns\",\"per_iter\":{aggregate_ns}}}"
        );
        vm.destroy();
    }

    /// Cross-process mailbox hand-off cost: fork a child, ping-pong over a
    /// `MAP_SHARED` page with carrick's production SHARED futex primitive.
    /// One round trip = parent wakes child + child wakes parent — the two
    /// hops a shared-VM micro-vmm pays per syscall to hand the exit to the
    /// owning process and get the result back.
    fn run_ipc_probe() {
        let page = unsafe {
            libc::mmap(
                ptr::null_mut(),
                REGION_ALIGN,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_ANON | libc::MAP_SHARED,
                -1,
                0,
            )
        };
        assert!(page != libc::MAP_FAILED, "shared mmap failed");
        let ping = unsafe { &*(page.cast::<AtomicU32>()) };
        let pong = unsafe { &*(page.cast::<u8>().add(64).cast::<AtomicU32>()) };
        let ping_addr = ping as *const AtomicU32 as usize;
        let pong_addr = pong as *const AtomicU32 as usize;
        let total = (WARMUP_ITERS + BATCHES * IPC_ITERS_PER_BATCH) as u32;

        let child = unsafe { libc::fork() };
        assert!(child >= 0, "fork failed");
        if child == 0 {
            // Servicing process: wait for round i, complete it, wake caller.
            for i in 1..=total {
                loop {
                    let seen = ping.load(Ordering::Acquire);
                    if seen >= i {
                        break;
                    }
                    let _ = ulock::wait(ping_addr, seen, 0);
                }
                pong.store(i, Ordering::Release);
                let _ = ulock::wake(pong_addr, false);
            }
            unsafe { libc::_exit(0) };
        }

        let mut round = 0u32;
        let mut ping_pong = |lat: &mut Vec<u64>, timed: bool| {
            round += 1;
            let i = round;
            let t0 = Instant::now();
            ping.store(i, Ordering::Release);
            let _ = ulock::wake(ping_addr, false);
            loop {
                let seen = pong.load(Ordering::Acquire);
                if seen >= i {
                    break;
                }
                let _ = ulock::wait(pong_addr, seen, 0);
            }
            if timed {
                lat.push(t0.elapsed().as_nanos() as u64);
            }
        };

        let mut scratch = Vec::new();
        for _ in 0..WARMUP_ITERS {
            ping_pong(&mut scratch, false);
        }
        for batch in 1..=BATCHES {
            let mut lat = Vec::with_capacity(IPC_ITERS_PER_BATCH);
            for _ in 0..IPC_ITERS_PER_BATCH {
                ping_pong(&mut lat, true);
            }
            report("ulock-ipc", "shared-roundtrip", batch, lat, "");
        }

        let mut status = 0i32;
        let rc = unsafe { libc::waitpid(child, &mut status, 0) };
        assert!(rc == child, "waitpid failed");
        unsafe { libc::munmap(page, REGION_ALIGN) };
    }

    fn rc_label(rc: hv_return_t) -> String {
        match rc as u32 {
            0 => "HV_SUCCESS".to_owned(),
            0xfae94001 => "HV_ERROR(0xfae94001)".to_owned(),
            0xfae94002 => "HV_BUSY(0xfae94002)".to_owned(),
            0xfae94005 => "HV_NO_RESOURCES(0xfae94005)".to_owned(),
            0xfae94006 => "HV_NO_DEVICE(0xfae94006)".to_owned(),
            0xfae94007 => "HV_DENIED(0xfae94007)".to_owned(),
            0xfae94008 => "HV_FAULT(0xfae94008)".to_owned(),
            0xfae9400f => "HV_UNSUPPORTED(0xfae9400f)".to_owned(),
            other => format!("HV_UNKNOWN(0x{other:08x})"),
        }
    }

    pub fn main() {
        let mode = std::env::args().nth(1).unwrap_or_else(|| "all".to_owned());
        let mut load = [0f64; 3];
        unsafe { libc::getloadavg(load.as_mut_ptr(), 3) };
        println!(
            "{{\"probe\":\"provenance\",\"pid\":{},\"loadavg1\":{:.2},\"mode\":\"{mode}\"}}",
            std::process::id(),
            load[0]
        );
        if mode == "all" || mode == "ipc" {
            run_ipc_probe();
        }
        if mode == "all" || mode == "portal" {
            run_portal_probe();
        }
        if mode == "all" || mode == "floor" {
            run_exit_arm("floor-mmu-off", false, false);
        }
        if mode == "all" || mode == "stage1" {
            run_exit_arm("stage1", true, false);
        }
        if mode == "all" || mode == "dispatch" {
            run_exit_arm("stage1-dispatch-regs", true, true);
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn portal_slot_has_stable_typed_layout() {
            assert_eq!(std::mem::align_of::<PortalSlot>(), 64);
            assert_eq!(std::mem::size_of::<PortalSlot>(), 64);
            assert_eq!(std::mem::offset_of!(PortalSlot, request), 0);
            assert_eq!(std::mem::offset_of!(PortalSlot, response), 4);
            assert_eq!(std::mem::offset_of!(PortalSlot, stop), 8);
        }

        #[test]
        fn portal_vector_routes_one_svc_through_shared_state_before_batch_exit() {
            let words = portal_vector_page()
                .chunks_exact(4)
                .map(|word| u32::from_le_bytes(word.try_into().expect("instruction word")))
                .collect::<Vec<_>>();
            let sync = 0x400 / 4;
            assert_eq!(words[sync], enc_cmp_x8_imm(0));
            assert!(words[sync..].contains(&enc_stlr_wt_xn(17, 16)));
            assert!(words[sync..].contains(&enc_ldar_wt_xn(0, 16)));
            assert!(words[sync..].contains(&AARCH64_HVC_SYSCALL_OPCODE));
            assert!(words[sync..].contains(&AARCH64_ERET_OPCODE));
        }
    }
}

#[cfg(not(all(target_os = "macos", target_arch = "aarch64")))]
mod imp {
    pub fn main() {
        eprintln!("hvf_svc_tax_probe requires macOS arm64");
        std::process::exit(1);
    }
}

fn main() {
    imp::main();
}
