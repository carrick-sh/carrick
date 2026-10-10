#![allow(dead_code)]

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
pub mod platform {
    use std::ffi::c_void;
    use std::ptr;
    use std::time::Instant;

    use applevisor_sys::{
        HV_MEMORY_EXEC, HV_MEMORY_READ, HV_MEMORY_WRITE, hv_exit_reason_t, hv_memory_flags_t,
        hv_reg_t, hv_return_t, hv_sys_reg_t, hv_vcpu_create, hv_vcpu_destroy, hv_vcpu_exit_t,
        hv_vcpu_get_reg, hv_vcpu_get_sys_reg, hv_vcpu_run, hv_vcpu_set_reg, hv_vcpu_set_sys_reg,
        hv_vcpu_t, hv_vm_config_create, hv_vm_config_get_max_ipa_size, hv_vm_config_set_ipa_size,
        hv_vm_create, hv_vm_destroy, hv_vm_map, os_release,
    };
    use carrick_mem::arch_sysregs::{
        CPACR_EL1_BOOTSTRAP, MAIR_EL1_BOOTSTRAP, SCTLR_EL1_BOOTSTRAP, TCR_EL1_BOOTSTRAP,
    };
    use carrick_mem::memory::{
        LINUX_EL0_TRAMPOLINE_BASE, LINUX_EL1_VECTORS_BASE, LINUX_PAGE_TABLES_BASE,
        el0_trampoline_bytes, el1_vectors_bytes, stage1_identity_page_tables,
    };

    use carrick_vmm_hvf::hvpatch_probe_support::{
        GUEST_CODE_BASE, UnderlyingExit, classify_underlying_exit, words_to_page,
    };

    pub const HV_SUCCESS: hv_return_t = 0;
    pub const HV_DENIED: hv_return_t = 0xfae9_4007_u32 as hv_return_t;
    pub const REGION_ALIGN: usize = 0x4000;
    pub const PSTATE_EL1H_DAIF_MASKED: u64 = 0x3c5;
    pub const PSTATE_EL0T_DAIF_MASKED: u64 = 0x3c0;

    #[derive(Clone, Copy, Debug)]
    pub struct Completion {
        pub elapsed_ns: u64,
        pub run_calls: u64,
        pub sysreg_exits: u64,
        pub completion_esr: u64,
    }

    pub struct ProbeVm {
        vcpu: hv_vcpu_t,
        exit: *const hv_vcpu_exit_t,
        allocations: Vec<(*mut c_void, usize)>,
    }

    impl ProbeVm {
        pub fn create() -> Result<Self, hv_return_t> {
            let mut max_ipa = 0_u32;
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
            let mut exit = ptr::null();
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

        pub fn map_code_words(&mut self, ipa: u64, words: &[u32]) {
            self.map_bytes(ipa, &words_to_page(words), HV_MEMORY_READ | HV_MEMORY_EXEC);
        }

        pub fn map_read_write(&mut self, ipa: u64, bytes: &[u8]) {
            self.map_bytes(ipa, bytes, HV_MEMORY_READ | HV_MEMORY_WRITE);
        }

        fn map_bytes(&mut self, ipa: u64, bytes: &[u8], flags: hv_memory_flags_t) {
            assert_eq!(ipa as usize % REGION_ALIGN, 0, "unaligned IPA {ipa:#x}");
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
            unsafe { ptr::copy_nonoverlapping(bytes.as_ptr(), host.cast::<u8>(), bytes.len()) };
            let rc = unsafe { hv_vm_map(host, ipa, size, flags) };
            assert_eq!(
                rc,
                HV_SUCCESS,
                "hv_vm_map({ipa:#x}, {size:#x}) -> {}",
                rc_label(rc)
            );
            self.allocations.push((host, size));
        }

        pub fn install_stage1_runtime(&mut self, guest_words: &[u32]) {
            self.map_bytes(
                LINUX_EL0_TRAMPOLINE_BASE,
                &el0_trampoline_bytes(),
                HV_MEMORY_READ | HV_MEMORY_EXEC,
            );
            self.map_bytes(
                LINUX_EL1_VECTORS_BASE,
                &el1_vectors_bytes(),
                HV_MEMORY_READ | HV_MEMORY_EXEC,
            );
            self.map_code_words(GUEST_CODE_BASE, guest_words);
            self.map_bytes(
                LINUX_PAGE_TABLES_BASE,
                &stage1_identity_page_tables(),
                HV_MEMORY_READ | HV_MEMORY_WRITE,
            );

            self.set_reg(hv_reg_t::CPSR, PSTATE_EL1H_DAIF_MASKED);
            self.set_reg(hv_reg_t::PC, LINUX_EL0_TRAMPOLINE_BASE);
            self.set_sys(hv_sys_reg_t::SPSR_EL1, PSTATE_EL0T_DAIF_MASKED);
            self.set_sys(hv_sys_reg_t::ELR_EL1, GUEST_CODE_BASE);
            self.set_sys(hv_sys_reg_t::VBAR_EL1, LINUX_EL1_VECTORS_BASE);
            self.set_sys(hv_sys_reg_t::CPACR_EL1, CPACR_EL1_BOOTSTRAP);
            self.set_sys(hv_sys_reg_t::MAIR_EL1, MAIR_EL1_BOOTSTRAP);
            self.set_sys(hv_sys_reg_t::TCR_EL1, TCR_EL1_BOOTSTRAP);
            self.set_sys(hv_sys_reg_t::TTBR0_EL1, LINUX_PAGE_TABLES_BASE);
            self.set_sys(hv_sys_reg_t::TTBR1_EL1, LINUX_PAGE_TABLES_BASE);
            self.set_sys(hv_sys_reg_t::SCTLR_EL1, SCTLR_EL1_BOOTSTRAP | 1);
        }

        pub fn set_reg(&self, reg: hv_reg_t, value: u64) {
            let rc = unsafe { hv_vcpu_set_reg(self.vcpu, reg, value) };
            assert_eq!(rc, HV_SUCCESS, "set_reg {reg:?} -> {}", rc_label(rc));
        }

        pub fn get_reg(&self, reg: hv_reg_t) -> u64 {
            let mut value = 0;
            let rc = unsafe { hv_vcpu_get_reg(self.vcpu, reg, &mut value) };
            assert_eq!(rc, HV_SUCCESS, "get_reg {reg:?} -> {}", rc_label(rc));
            value
        }

        pub fn set_sys(&self, reg: hv_sys_reg_t, value: u64) {
            let rc = unsafe { hv_vcpu_set_sys_reg(self.vcpu, reg, value) };
            assert_eq!(rc, HV_SUCCESS, "set_sys_reg {reg:?} -> {}", rc_label(rc));
        }

        fn get_sys(&self, reg: hv_sys_reg_t) -> u64 {
            let mut value = 0;
            let rc = unsafe { hv_vcpu_get_sys_reg(self.vcpu, reg, &mut value) };
            assert_eq!(rc, HV_SUCCESS, "get_sys_reg {reg:?} -> {}", rc_label(rc));
            value
        }

        pub fn run_to_completion(&self, emulated_sysreg_value: Option<u64>) -> Completion {
            let started = Instant::now();
            let mut run_calls = 0_u64;
            let mut sysreg_exits = 0_u64;
            loop {
                run_calls += 1;
                let rc = unsafe { hv_vcpu_run(self.vcpu) };
                assert_eq!(rc, HV_SUCCESS, "hv_vcpu_run -> {}", rc_label(rc));
                let exit = unsafe { self.exit.as_ref() }.expect("null HVF exit pointer");
                let host_ec = (exit.exception.syndrome >> 26) & 0x3f;
                assert!(
                    exit.reason == hv_exit_reason_t::EXCEPTION && host_ec == 0x16,
                    "unexpected host exit: reason={:?} syndrome={:#x} ec={host_ec:#x} va={:#x} pa={:#x}",
                    exit.reason,
                    exit.exception.syndrome,
                    exit.exception.virtual_address,
                    exit.exception.physical_address,
                );
                let underlying = self.get_sys(hv_sys_reg_t::ESR_EL1);
                match classify_underlying_exit(underlying) {
                    UnderlyingExit::CompletionSvc => {
                        return Completion {
                            elapsed_ns: started.elapsed().as_nanos() as u64,
                            run_calls,
                            sysreg_exits,
                            completion_esr: underlying,
                        };
                    }
                    UnderlyingExit::SystemRegisterRead => {
                        let value = emulated_sysreg_value
                            .expect("unexpected system-register exit in an exit-free probe arm");
                        sysreg_exits += 1;
                        self.set_reg(hv_reg_t::X0, value);
                        let elr = self.get_sys(hv_sys_reg_t::ELR_EL1);
                        self.set_sys(hv_sys_reg_t::ELR_EL1, elr.wrapping_add(4));
                    }
                    UnderlyingExit::Other(ec) => {
                        panic!(
                            "unexpected underlying EL0 exception: esr={underlying:#x} ec={ec:#x}"
                        );
                    }
                }
            }
        }
    }

    impl Drop for ProbeVm {
        fn drop(&mut self) {
            let _ = unsafe { hv_vcpu_destroy(self.vcpu) };
            let _ = unsafe { hv_vm_destroy() };
            for (host, size) in self.allocations.drain(..) {
                unsafe { libc::munmap(host, size) };
            }
        }
    }

    pub fn print_provenance(probe: &str, iterations: u64) {
        let mut load = [0_f64; 3];
        unsafe { libc::getloadavg(load.as_mut_ptr(), 3) };
        println!(
            "{{\"probe\":\"provenance\",\"name\":\"{probe}\",\"pid\":{},\"iterations\":{iterations},\"loadavg1\":{:.2},\"host_page_size\":{}}}",
            std::process::id(),
            load[0],
            unsafe { libc::sysconf(libc::_SC_PAGESIZE) },
        );
    }

    pub fn create_or_exit(probe: &str) -> ProbeVm {
        match ProbeVm::create() {
            Ok(vm) => vm,
            Err(rc) => {
                println!(
                    "{{\"probe\":\"{probe}\",\"error\":\"hv_vm_create\",\"rc\":\"{}\"}}",
                    rc_label(rc)
                );
                if rc == HV_DENIED {
                    eprintln!(
                        "HV_DENIED: sign this probe with scripts/entitlements.plist before trusting a negative"
                    );
                }
                std::process::exit(2);
            }
        }
    }

    pub fn rc_label(rc: hv_return_t) -> String {
        match rc as u32 {
            0 => "HV_SUCCESS".to_owned(),
            0xfae9_4001 => "HV_ERROR(0xfae94001)".to_owned(),
            0xfae9_4002 => "HV_BUSY(0xfae94002)".to_owned(),
            0xfae9_4005 => "HV_NO_RESOURCES(0xfae94005)".to_owned(),
            0xfae9_4006 => "HV_NO_DEVICE(0xfae94006)".to_owned(),
            0xfae9_4007 => "HV_DENIED(0xfae94007)".to_owned(),
            0xfae9_4008 => "HV_FAULT(0xfae94008)".to_owned(),
            0xfae9_400f => "HV_UNSUPPORTED(0xfae9400f)".to_owned(),
            other => format!("HV_UNKNOWN(0x{other:08x})"),
        }
    }
}
