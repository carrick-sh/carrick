#![allow(
    clippy::expect_used,
    clippy::panic,
    clippy::print_stderr,
    clippy::print_stdout
)]
//! Phase 0b decisive probe for the `hvpatch` plan.
//!
//! WHAT IT MEASURES: two counted EL0 loops read the same known value either
//! through `ldr x0, [x20]` from a stage-1 info page or through
//! `mrs x0, tpidr_el0`. Each arm executes 100,000 reads and then one completion
//! `svc`. The TPIDR arm emulates an EC=0x18 exit if HVF produces one, while
//! counting every such exit.
//!
//! IMPORTANT: the plan projects that `mrs tpidr_el0` exits. This probe treats
//! that as a hypothesis. A direct, exit-free MRS is reported as such and means
//! patching TPIDR is unnecessary; it is not coerced into the projected result.
//!
//! PERTURBATION: self-contained micro-VM; no Carrick guest workload or Docker.

mod hvpatch_probe_support;

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
fn main() {
    use applevisor_sys::{hv_reg_t, hv_sys_reg_t};
    use hvpatch_probe_support::platform::{create_or_exit, print_provenance};
    use hvpatch_probe_support::{INFO_PAGE_BASE, info_load_words, tpidr_read_words};

    const ITERATIONS: u64 = 100_000;
    const BATCHES: u32 = 5;
    const KNOWN_VALUE: u64 = 0x4849_4252_4944_303b;

    print_provenance("hvf-info-load", ITERATIONS);
    for batch in 1..=BATCHES {
        let mut info_page = vec![0_u8; 0x4000];
        info_page[..8].copy_from_slice(&KNOWN_VALUE.to_le_bytes());

        let mut load_vm = create_or_exit("hvf-info-load");
        load_vm.map_read_write(INFO_PAGE_BASE, &info_page);
        load_vm.install_stage1_runtime(&info_load_words());
        load_vm.set_reg(hv_reg_t::X20, INFO_PAGE_BASE);
        load_vm.set_reg(hv_reg_t::X9, ITERATIONS);
        let load = load_vm.run_to_completion(None);
        let load_value = load_vm.get_reg(hv_reg_t::X0);
        let load_countdown = load_vm.get_reg(hv_reg_t::X9);
        assert_eq!(
            load_value, KNOWN_VALUE,
            "info-page load returned wrong value"
        );
        assert_eq!(load_countdown, 0, "info-page loop did not finish");
        assert_eq!(load.run_calls, 1, "info-page loop exited before completion");

        println!(
            "{{\"probe\":\"hvf-info-load\",\"arm\":\"ldr-info-page\",\"batch\":{batch},\"status\":\"PASS\",\"iterations\":{ITERATIONS},\"run_calls\":{},\"loop_vm_exits\":0,\"elapsed_ns\":{},\"ns_per_read\":{:.3},\"value\":\"{load_value:#x}\"}}",
            load.run_calls,
            load.elapsed_ns,
            load.elapsed_ns as f64 / ITERATIONS as f64,
        );
        drop(load_vm);

        let mut mrs_vm = create_or_exit("hvf-info-load");
        mrs_vm.install_stage1_runtime(&tpidr_read_words());
        mrs_vm.set_sys(hv_sys_reg_t::TPIDR_EL0, KNOWN_VALUE);
        mrs_vm.set_reg(hv_reg_t::X9, ITERATIONS);
        let mrs = mrs_vm.run_to_completion(Some(KNOWN_VALUE));
        let mrs_value = mrs_vm.get_reg(hv_reg_t::X0);
        let mrs_countdown = mrs_vm.get_reg(hv_reg_t::X9);
        assert_eq!(mrs_value, KNOWN_VALUE, "TPIDR read returned wrong value");
        assert_eq!(mrs_countdown, 0, "TPIDR loop did not finish");
        assert_eq!(
            mrs.run_calls,
            mrs.sysreg_exits + 1,
            "every non-completion run return must be a counted sysreg exit"
        );
        assert!(
            mrs.sysreg_exits == 0 || mrs.sysreg_exits == ITERATIONS,
            "TPIDR trapping must be consistent across the counted loop"
        );
        let mode = if mrs.sysreg_exits == 0 {
            "exit-free"
        } else {
            "trapped-and-emulated"
        };

        println!(
            "{{\"probe\":\"hvf-info-load\",\"arm\":\"mrs-tpidr-el0\",\"batch\":{batch},\"status\":\"PASS\",\"mode\":\"{mode}\",\"iterations\":{ITERATIONS},\"run_calls\":{},\"sysreg_vm_exits\":{},\"elapsed_ns\":{},\"ns_per_read\":{:.3},\"value\":\"{mrs_value:#x}\"}}",
            mrs.run_calls,
            mrs.sysreg_exits,
            mrs.elapsed_ns,
            mrs.elapsed_ns as f64 / ITERATIONS as f64,
        );
        drop(mrs_vm);
    }
}

#[cfg(not(all(target_os = "macos", target_arch = "aarch64")))]
fn main() {
    eprintln!("hvf_info_load_probe requires macOS arm64");
    std::process::exit(1);
}
