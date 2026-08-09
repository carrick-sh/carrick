#![allow(
    clippy::expect_used,
    clippy::panic,
    clippy::print_stderr,
    clippy::print_stdout
)]
//! Phase 0a decisive probe for the `hvpatch` plan.
//!
//! WHAT IT MEASURES: a counted EL0 loop executes `bl` from one stage-1 RX
//! page to an island on another stage-1 RX page exactly 100,000 times. The
//! island writes x0=42 and returns. Only after the countdown reaches zero does
//! the guest execute one `svc #0`, forwarded by Carrick's production EL1
//! vector as `hvc #2`, so the host can observe completion.
//!
//! PASS CONTRACT: `hv_vcpu_run` returns exactly once, for that completion
//! marker; x9 is zero and x0 is 42. Any earlier BL/fetch/stage-2 exit is a
//! loud failure, never an empty result.
//!
//! PERTURBATION: self-contained micro-VM; no Carrick guest workload or Docker.

mod hvpatch_probe_support;

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
fn main() {
    use applevisor_sys::hv_reg_t;
    use hvpatch_probe_support::platform::{create_or_exit, print_provenance};
    use hvpatch_probe_support::{ISLAND_CODE_BASE, bl_probe_guest_words, bl_probe_island_words};

    const ITERATIONS: u64 = 100_000;

    print_provenance("hvf-bl-exit-free", ITERATIONS);
    let mut vm = create_or_exit("hvf-bl-exit-free");
    vm.map_code_words(ISLAND_CODE_BASE, &bl_probe_island_words());
    vm.install_stage1_runtime(&bl_probe_guest_words());
    vm.set_reg(hv_reg_t::X9, ITERATIONS);

    let completion = vm.run_to_completion(None);
    let countdown = vm.get_reg(hv_reg_t::X9);
    let island_value = vm.get_reg(hv_reg_t::X0);
    let loop_vm_exits = completion.run_calls.saturating_sub(1);

    assert_eq!(countdown, 0, "guest countdown did not finish");
    assert_eq!(island_value, 42, "island did not execute through RET");
    assert_eq!(completion.sysreg_exits, 0, "unexpected sysreg exit");
    assert_eq!(loop_vm_exits, 0, "BL loop returned to the host early");

    println!(
        "{{\"probe\":\"hvf-bl-exit-free\",\"status\":\"PASS\",\"iterations\":{ITERATIONS},\"run_calls\":{},\"loop_vm_exits\":{loop_vm_exits},\"completion_exits\":1,\"elapsed_ns\":{},\"ns_per_call\":{:.3},\"x0\":{island_value},\"x9\":{countdown},\"completion_esr\":\"{:#x}\"}}",
        completion.run_calls,
        completion.elapsed_ns,
        completion.elapsed_ns as f64 / ITERATIONS as f64,
        completion.completion_esr,
    );
}

#[cfg(not(all(target_os = "macos", target_arch = "aarch64")))]
fn main() {
    eprintln!("hvf_bl_exit_free_probe requires macOS arm64");
    std::process::exit(1);
}
