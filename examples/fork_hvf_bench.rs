//! Measure HVF vCPU FIRST-ENTRY (cold) latency vs subsequent (warm) hv_vcpu_run.
//! Hypothesis: a freshly-forked carrick process pays ~4ms cold vcpu entry.
#![allow(clippy::unwrap_used)]
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
mod sys { pub use applevisor_sys::*; }
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
fn main() {
    use std::time::Instant;
    unsafe {
        let cfg = sys::hv_vm_config_create();
        let mut bits=0u32; sys::hv_vm_config_get_max_ipa_size(&mut bits); sys::hv_vm_config_set_ipa_size(cfg,bits);
        assert_eq!(sys::hv_vm_create(cfg),0);
        // Code page at IPA 0x4000 holding `svc #0` (0xd4000001) repeated.
        let page_sz = 0x4000usize;
        let code = libc::mmap(std::ptr::null_mut(), page_sz, libc::PROT_READ|libc::PROT_WRITE, libc::MAP_ANON|libc::MAP_PRIVATE, -1, 0) as *mut u32;
        for i in 0..(page_sz/4) { *code.add(i) = 0xd4000001; } // svc #0
        assert_eq!(sys::hv_vm_map(code as *mut _, 0x4000, page_sz, sys::HV_MEMORY_READ|sys::HV_MEMORY_EXEC),0);

        let mut vcpu=0u64; let mut exit: *const sys::hv_vcpu_exit_t = std::ptr::null();
        assert_eq!(sys::hv_vcpu_create(&mut vcpu, &mut exit, sys::hv_vcpu_config_create()),0);
        // EL1h, DAIF masked; PC at the code page.
        sys::hv_vcpu_set_reg(vcpu, sys::hv_reg_t::CPSR, 0x3c5);
        sys::hv_vcpu_set_reg(vcpu, sys::hv_reg_t::PC, 0x4000);

        // COLD: first run.
        let t=Instant::now(); let r=sys::hv_vcpu_run(vcpu); let cold=t.elapsed();
        println!("cold hv_vcpu_run: {:.3} ms (ret={r:#x})", cold.as_secs_f64()*1e3);

        // WARM: reset PC, run 20x, average.
        let mut warm = std::time::Duration::ZERO; let runs=20;
        for _ in 0..runs {
            sys::hv_vcpu_set_reg(vcpu, sys::hv_reg_t::PC, 0x4000);
            let t=Instant::now(); sys::hv_vcpu_run(vcpu); warm += t.elapsed();
        }
        println!("warm hv_vcpu_run avg: {:.4} ms (n={runs})", warm.as_secs_f64()*1e3/runs as f64);
    }
}
#[cfg(not(all(target_os = "macos", target_arch = "aarch64")))]
fn main() {}
