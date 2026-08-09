#![allow(
    clippy::expect_used,
    clippy::missing_safety_doc,
    clippy::panic,
    clippy::print_stderr,
    clippy::print_stdout
)]
//! Phase 0c decisive probe for the `hvpatch` plan.
//!
//! WHAT IT MEASURES: the same hand-assembled dependent Fibonacci loop runs for
//! one million iterations (a) at EL0 in Carrick's production host-built
//! stage-1 tables inside one HVF VM and (b) as host-native MAP_JIT code. The
//! guest uses one final `svc` completion marker; its timed loop must otherwise
//! produce zero VM exits. Batches alternate guest-first and host-first.
//!
//! PERTURBATION: self-contained micro-VM plus one local MAP_JIT page; no
//! Carrick guest workload or Docker. The final SVC/RET difference is amortized
//! over one million identical loop iterations.

mod hvpatch_probe_support;

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
mod imp {
    use std::ffi::c_void;
    use std::ptr;
    use std::time::Instant;

    use crate::hvpatch_probe_support::platform::{REGION_ALIGN, create_or_exit, print_provenance};
    use crate::hvpatch_probe_support::{compute_words, host_compute_words};
    use applevisor_sys::hv_reg_t;

    const ITERATIONS: u64 = 1_000_000;
    const BATCHES: u32 = 6;

    unsafe extern "C" {
        fn sys_icache_invalidate(start: *mut c_void, len: usize);
    }

    struct HostCode {
        base: *mut c_void,
    }

    impl HostCode {
        fn new() -> Self {
            assert_ne!(
                unsafe { libc::pthread_jit_write_protect_supported_np() },
                0,
                "MAP_JIT write protection is unavailable"
            );
            let base = unsafe {
                libc::mmap(
                    ptr::null_mut(),
                    REGION_ALIGN,
                    libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC,
                    libc::MAP_PRIVATE | libc::MAP_ANON | libc::MAP_JIT,
                    -1,
                    0,
                )
            };
            assert!(base != libc::MAP_FAILED, "host MAP_JIT mmap failed");
            let words = host_compute_words();
            unsafe {
                libc::pthread_jit_write_protect_np(0);
                ptr::copy_nonoverlapping(words.as_ptr().cast::<u8>(), base.cast(), words.len() * 4);
                sys_icache_invalidate(base, words.len() * 4);
                libc::pthread_jit_write_protect_np(1);
            }
            Self { base }
        }

        fn run(&self) -> (u64, u64) {
            type FibonacciFn = unsafe extern "C" fn(u64, u64, u64) -> u64;
            let function: FibonacciFn = unsafe { std::mem::transmute(self.base) };
            let started = Instant::now();
            let value = unsafe { function(0, 1, ITERATIONS) };
            (started.elapsed().as_nanos() as u64, value)
        }
    }

    impl Drop for HostCode {
        fn drop(&mut self) {
            unsafe {
                libc::pthread_jit_write_protect_np(0);
                libc::munmap(self.base, REGION_ALIGN);
                libc::pthread_jit_write_protect_np(1);
            }
        }
    }

    fn run_guest() -> (u64, u64) {
        let mut vm = create_or_exit("hvf-compute-baseline");
        vm.install_stage1_runtime(&compute_words());
        vm.set_reg(hv_reg_t::X0, 0);
        vm.set_reg(hv_reg_t::X1, 1);
        vm.set_reg(hv_reg_t::X2, ITERATIONS);
        let completion = vm.run_to_completion(None);
        let value = vm.get_reg(hv_reg_t::X0);
        let countdown = vm.get_reg(hv_reg_t::X9);
        assert_eq!(countdown, 0, "guest compute loop did not finish");
        assert_eq!(
            completion.run_calls, 1,
            "compute loop exited before completion"
        );
        assert_eq!(completion.sysreg_exits, 0, "compute loop had a sysreg exit");
        (completion.elapsed_ns, value)
    }

    fn report(batch: u32, arm: &str, order: &str, elapsed_ns: u64, value: u64) {
        println!(
            "{{\"probe\":\"hvf-compute-baseline\",\"arm\":\"{arm}\",\"batch\":{batch},\"order\":\"{order}\",\"status\":\"PASS\",\"iterations\":{ITERATIONS},\"elapsed_ns\":{elapsed_ns},\"ns_per_iter\":{:.3},\"value\":\"{value:#x}\"}}",
            elapsed_ns as f64 / ITERATIONS as f64,
        );
    }

    pub fn main() {
        print_provenance("hvf-compute-baseline", ITERATIONS);
        let host = HostCode::new();

        for batch in 1..=BATCHES {
            let (guest, native) = if batch % 2 == 1 {
                let guest = run_guest();
                let native = host.run();
                (guest, native)
            } else {
                let native = host.run();
                let guest = run_guest();
                (guest, native)
            };
            assert_eq!(guest.1, native.1, "guest and host compute results differ");
            let order = if batch % 2 == 1 {
                "guest-host"
            } else {
                "host-guest"
            };
            report(batch, "hvf-stage1-el0", order, guest.0, guest.1);
            report(batch, "host-map-jit", order, native.0, native.1);
        }
    }
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
fn main() {
    imp::main();
}

#[cfg(not(all(target_os = "macos", target_arch = "aarch64")))]
fn main() {
    eprintln!("hvf_compute_baseline_probe requires macOS arm64");
    std::process::exit(1);
}
