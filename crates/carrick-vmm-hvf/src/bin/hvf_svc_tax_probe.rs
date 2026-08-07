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
//! 2. `ulock-ipc` — the cross-process hand-off a shared-VM micro-vmm adds on
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
//! Usage: `hvf_svc_tax_probe [all|ipc|floor|stage1|dispatch]` (default all).
//! Output: one JSON line per batch on stdout; provenance lines first.

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
mod imp {
    use std::ffi::c_void;
    use std::ptr;
    use std::sync::atomic::{AtomicU32, Ordering};
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
        el0_trampoline_bytes, el1_vectors_bytes, stage1_identity_page_tables,
    };

    const HV_SUCCESS: hv_return_t = 0;
    const HV_DENIED: hv_return_t = 0xfae94007u32 as hv_return_t;

    /// Guest VA/IPA of the `svc #0` loop page. 4 MiB: inside the stage-1
    /// identity map's user 2 MiB blocks (executable, UXN clear) and 16 KiB
    /// aligned for `hv_vm_map`. Deliberately a LOW address — the exact class
    /// of VA the micro-vmm exists to serve (Go's ET_EXEC text).
    const GUEST_CODE_BASE: u64 = 0x40_0000;
    const REGION_ALIGN: usize = 0x4000; // HVF page size (16 KiB)

    const AARCH64_SVC0: u32 = 0xd400_0001; // svc #0
    const AARCH64_B_BACK_4: u32 = 0x17ff_ffff; // b .-4 (back to the svc)

    // PSTATE values, mirroring `trap.rs`.
    const PSTATE_EL1H_DAIF_MASKED: u64 = 0x3c5;
    const PSTATE_EL0T_DAIF_MASKED: u64 = 0x3c0;

    const WARMUP_ITERS: usize = 1_000;
    const BATCHES: usize = 5;
    const EXIT_ITERS_PER_BATCH: usize = 20_000;
    const IPC_ITERS_PER_BATCH: usize = 10_000;

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
        fn map(&mut self, ipa: u64, bytes: &[u8]) {
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
