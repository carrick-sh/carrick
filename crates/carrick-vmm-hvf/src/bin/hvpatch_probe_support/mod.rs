#![allow(dead_code)]

pub const GUEST_CODE_BASE: u64 = 0x40_0000;
pub const ISLAND_CODE_BASE: u64 = 0x40_4000;
pub const INFO_PAGE_BASE: u64 = 0x40_8000;

pub const AARCH64_SVC0: u32 = 0xd400_0001;
pub const AARCH64_RET: u32 = 0xd65f_03c0;
pub const AARCH64_MOV_X0_42: u32 = 0xd280_0540;

pub fn encode_bl(pc: u64, target: u64) -> u32 {
    let delta = target as i64 - pc as i64;
    assert_eq!(delta & 3, 0, "BL target must be instruction aligned");
    let words = delta >> 2;
    assert!(
        (-(1_i64 << 25)..(1_i64 << 25)).contains(&words),
        "BL target is outside the signed imm26 range"
    );
    0x9400_0000 | ((words as u32) & 0x03ff_ffff)
}

pub fn encode_bne(pc: u64, target: u64) -> u32 {
    let delta = target as i64 - pc as i64;
    assert_eq!(delta & 3, 0, "B.NE target must be instruction aligned");
    let words = delta >> 2;
    assert!(
        (-(1_i64 << 18)..(1_i64 << 18)).contains(&words),
        "B.NE target is outside the signed imm19 range"
    );
    0x5400_0001 | (((words as u32) & 0x7ffff) << 5)
}

pub fn encode_subs_imm(rd: u32, rn: u32, imm12: u16) -> u32 {
    assert!(rd < 32 && rn < 32 && imm12 < 4096);
    0xf100_0000 | (u32::from(imm12) << 10) | (rn << 5) | rd
}

pub fn encode_ldr_x(rt: u32, rn: u32, byte_offset: u16) -> u32 {
    assert!(rt < 32 && rn < 32);
    assert_eq!(byte_offset & 7, 0, "LDR X offset must be 8-byte aligned");
    0xf940_0000 | ((u32::from(byte_offset) / 8) << 10) | (rn << 5) | rt
}

pub fn words_to_page(words: &[u32]) -> Vec<u8> {
    assert!(words.len() * 4 <= 0x4000);
    let mut page = vec![0; 0x4000];
    for (index, word) in words.iter().enumerate() {
        let offset = index * 4;
        page[offset..offset + 4].copy_from_slice(&word.to_le_bytes());
    }
    page
}

pub fn bl_probe_guest_words() -> Vec<u32> {
    vec![
        encode_bl(GUEST_CODE_BASE, ISLAND_CODE_BASE),
        encode_subs_imm(9, 9, 1),
        encode_bne(GUEST_CODE_BASE + 8, GUEST_CODE_BASE),
        AARCH64_SVC0,
        0x1400_0000,
    ]
}

pub fn bl_probe_island_words() -> Vec<u32> {
    vec![AARCH64_MOV_X0_42, AARCH64_RET]
}

pub fn info_load_words() -> Vec<u32> {
    vec![
        encode_ldr_x(0, 20, 0),
        encode_subs_imm(9, 9, 1),
        encode_bne(GUEST_CODE_BASE + 8, GUEST_CODE_BASE),
        AARCH64_SVC0,
        0x1400_0000,
    ]
}

pub fn tpidr_read_words() -> Vec<u32> {
    vec![
        0xd53b_d040,
        encode_subs_imm(9, 9, 1),
        encode_bne(GUEST_CODE_BASE + 8, GUEST_CODE_BASE),
        AARCH64_SVC0,
        0x1400_0000,
    ]
}

pub fn compute_words() -> Vec<u32> {
    let mut words = compute_loop_words();
    words.extend([AARCH64_SVC0, 0x1400_0000]);
    words
}

pub fn host_compute_words() -> Vec<u32> {
    let mut words = compute_loop_words();
    words.push(AARCH64_RET);
    words
}

fn compute_loop_words() -> Vec<u32> {
    vec![
        0xaa02_03e9,
        0x8b01_0003,
        0xaa01_03e0,
        0xaa03_03e1,
        encode_subs_imm(9, 9, 1),
        encode_bne(GUEST_CODE_BASE + 20, GUEST_CODE_BASE + 4),
    ]
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UnderlyingExit {
    CompletionSvc,
    SystemRegisterRead,
    Other(u64),
}

pub fn classify_underlying_exit(esr: u64) -> UnderlyingExit {
    let exception_class = (esr >> 26) & 0x3f;
    match exception_class {
        0x15 => UnderlyingExit::CompletionSvc,
        0x18 => UnderlyingExit::SystemRegisterRead,
        other => UnderlyingExit::Other(other),
    }
}

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

    use super::{GUEST_CODE_BASE, UnderlyingExit, classify_underlying_exit, words_to_page};

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn branch_encoders_preserve_forward_and_backward_targets() {
        assert_eq!(encode_bl(0x40_0000, 0x40_4000), 0x9400_1000);
        assert_eq!(encode_bne(0x40_0008, 0x40_0000), 0x54ff_ffc1);
    }

    #[test]
    fn data_processing_encoders_name_the_intended_registers() {
        assert_eq!(encode_subs_imm(9, 9, 1), 0xf100_0529);
        assert_eq!(encode_ldr_x(0, 20, 0), 0xf940_0280);
        assert_eq!(encode_ldr_x(3, 20, 24), 0xf940_0e83);
    }

    #[test]
    fn word_page_is_little_endian_and_hvf_granule_sized() {
        let page = words_to_page(&[AARCH64_SVC0, AARCH64_RET]);
        assert_eq!(&page[..8], &[1, 0, 0, 0xd4, 0xc0, 3, 0x5f, 0xd6]);
        assert_eq!(page.len(), 0x4000);
        assert!(page[8..].iter().all(|byte| *byte == 0));
    }

    #[test]
    fn bl_probe_calls_the_island_exactly_before_each_countdown_step() {
        assert_eq!(
            bl_probe_guest_words(),
            vec![
                0x9400_1000,
                0xf100_0529,
                0x54ff_ffc1,
                AARCH64_SVC0,
                0x1400_0000,
            ]
        );
        assert_eq!(
            bl_probe_island_words(),
            vec![AARCH64_MOV_X0_42, AARCH64_RET]
        );
    }

    #[test]
    fn info_load_and_tpidr_arms_share_the_same_counted_completion_shape() {
        assert_eq!(
            info_load_words(),
            vec![
                0xf940_0280,
                0xf100_0529,
                0x54ff_ffc1,
                AARCH64_SVC0,
                0x1400_0000,
            ]
        );
        assert_eq!(
            tpidr_read_words(),
            vec![
                0xd53b_d040,
                0xf100_0529,
                0x54ff_ffc1,
                AARCH64_SVC0,
                0x1400_0000,
            ]
        );
    }

    #[test]
    fn compute_arm_is_a_dependent_fibonacci_loop_with_one_completion_svc() {
        assert_eq!(
            compute_words(),
            vec![
                0xaa02_03e9,
                0x8b01_0003,
                0xaa01_03e0,
                0xaa03_03e1,
                0xf100_0529,
                0x54ff_ff81,
                AARCH64_SVC0,
                0x1400_0000,
            ]
        );
        assert_eq!(
            host_compute_words(),
            vec![
                0xaa02_03e9,
                0x8b01_0003,
                0xaa01_03e0,
                0xaa03_03e1,
                0xf100_0529,
                0x54ff_ff81,
                AARCH64_RET,
            ]
        );
    }

    #[test]
    fn underlying_esr_classification_distinguishes_completion_from_sysreg_traps() {
        assert_eq!(
            classify_underlying_exit(0x15 << 26),
            UnderlyingExit::CompletionSvc
        );
        assert_eq!(
            classify_underlying_exit(0x18 << 26),
            UnderlyingExit::SystemRegisterRead
        );
        assert_eq!(
            classify_underlying_exit(0x24 << 26),
            UnderlyingExit::Other(0x24)
        );
    }
}
