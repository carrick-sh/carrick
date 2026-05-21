//! Microbench: isolate the HVF per-process context cost (plan.md open Q#2).
//! Times VM create + vcpu create + a few region maps + teardown, the work
//! carrick's fork/execve paths repeat per guest process.
//!
//!   cargo build --release --example hvf_vm_lifecycle_bench
//!   codesign --force --sign - --entitlements scripts/entitlements.plist \
//!     target/release/examples/hvf_vm_lifecycle_bench
//!   target/release/examples/hvf_vm_lifecycle_bench
#![allow(clippy::unwrap_used, clippy::expect_used)]

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
fn main() {
    use applevisor::prelude::*;
    use std::time::Instant;

    let iters = 200u32;

    // (a) VM + vcpu create + destroy only (no mappings).
    let mut create = std::time::Duration::ZERO;
    let mut destroy = std::time::Duration::ZERO;
    for _ in 0..iters {
        let t0 = Instant::now();
        let max_ipa = VirtualMachineConfig::get_max_ipa_size().unwrap();
        let mut cfg = VirtualMachineConfig::new();
        cfg.set_ipa_size(max_ipa).unwrap();
        let vm = VirtualMachine::with_config(cfg).unwrap();
        let vcpu = vm.vcpu_create().unwrap();
        create += t0.elapsed();
        let t1 = Instant::now();
        drop(vcpu);
        drop(vm);
        destroy += t1.elapsed();
    }
    println!(
        "VM+vcpu create: {:.3} ms/iter   teardown: {:.3} ms/iter   (n={iters})",
        create.as_secs_f64() * 1e3 / iters as f64,
        destroy.as_secs_f64() * 1e3 / iters as f64,
    );

    // (b) Replicate carrick's REAL per-fork footprint: ~642 MiB across 8
    // regions (measured: heap 128 MiB, mmap window, interpreter, stack, ELF
    // segments). Time create + map + DESTROY (the full per-fork dance) so we
    // see whether large-region stage-2 setup/teardown is the ~10ms cost.
    let region_sizes: [usize; 8] = [
        512 * 1024 * 1024, // mmap window-ish
        128 * 1024 * 1024, // heap
        2 * 1024 * 1024,   // stack
        1024 * 1024,
        512 * 1024,
        256 * 1024,
        128 * 1024,
        64 * 1024,
    ];
    let mut bufs: Vec<Vec<u8>> = region_sizes.iter().map(|&s| vec![0u8; s]).collect();
    let total_mib: usize = region_sizes.iter().sum::<usize>() / (1024 * 1024);
    let biters = 50u32;
    let (mut t_create, mut t_map, mut t_destroy) = (
        std::time::Duration::ZERO,
        std::time::Duration::ZERO,
        std::time::Duration::ZERO,
    );
    for _ in 0..biters {
        let t0 = Instant::now();
        let max_ipa = VirtualMachineConfig::get_max_ipa_size().unwrap();
        let mut cfg = VirtualMachineConfig::new();
        cfg.set_ipa_size(max_ipa).unwrap();
        let vm = VirtualMachine::with_config(cfg).unwrap();
        let vcpu = vm.vcpu_create().unwrap();
        t_create += t0.elapsed();

        let t1 = Instant::now();
        let mut ipa = 0x10_0000_0000u64;
        for b in bufs.iter_mut() {
            let r = unsafe {
                applevisor_sys::hv_vm_map(
                    b.as_mut_ptr() as *mut std::ffi::c_void,
                    ipa,
                    b.len(),
                    applevisor_sys::HV_MEMORY_READ | applevisor_sys::HV_MEMORY_WRITE,
                )
            };
            assert_eq!(r, 0, "hv_vm_map failed");
            ipa += b.len() as u64;
        }
        t_map += t1.elapsed();

        let t2 = Instant::now();
        drop(vcpu);
        drop(vm); // VM Drop unmaps all + destroys — the per-fork teardown.
        t_destroy += t2.elapsed();
    }
    let n = biters as f64;
    println!(
        "carrick-like {total_mib} MiB / 8 regions per iter (n={biters}):\n  \
         create+vcpu: {:.3} ms   map: {:.3} ms   teardown(unmap+destroy): {:.3} ms   TOTAL: {:.3} ms",
        t_create.as_secs_f64() * 1e3 / n,
        t_map.as_secs_f64() * 1e3 / n,
        t_destroy.as_secs_f64() * 1e3 / n,
        (t_create + t_map + t_destroy).as_secs_f64() * 1e3 / n,
    );
}

#[cfg(not(all(target_os = "macos", target_arch = "aarch64")))]
fn main() {
    eprintln!("bench only runs on macOS/aarch64");
}
