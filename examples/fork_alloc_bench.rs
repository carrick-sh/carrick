//! Does carrick's guest-memory allocator (applevisor Memory = alloc_zeroed)
//! make libc::fork() slow, vs raw mmap? Maps ~640MiB both ways, hv_vm_destroy,
//! then times one libc::fork (child _exit, parent waitpid). Arg1: raw|applevisor
#![allow(clippy::unwrap_used)]
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
mod sys {
    pub use applevisor_sys::*;
}
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
fn rss_mb() -> f64 {
    let mut u: libc::rusage = unsafe { std::mem::zeroed() };
    unsafe { libc::getrusage(libc::RUSAGE_SELF, &mut u) };
    u.ru_maxrss as f64 / 1048576.0
}
fn time_fork(label: &str) {
    use std::time::Instant;
    let t = Instant::now();
    let pid = unsafe { libc::fork() };
    if pid == 0 {
        unsafe { libc::_exit(0) }
    }
    let mut st = 0;
    unsafe { libc::waitpid(pid, &mut st, 0) };
    println!(
        "{label}: libc::fork+wait = {:.3} ms",
        t.elapsed().as_secs_f64() * 1e3
    );
}
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
fn main() {
    use applevisor::prelude::*;
    let mode = std::env::args().nth(1).unwrap_or_else(|| "raw".into());
    let sizes = [512usize << 20, 128 << 20]; // 640 MiB, carrick's windows
    if mode == "applevisor" {
        let max = VirtualMachineConfig::get_max_ipa_size().unwrap();
        let mut cfg = VirtualMachineConfig::new();
        cfg.set_ipa_size(max).unwrap();
        let vm = VirtualMachine::with_config(cfg).unwrap();
        let _vcpu = vm.vcpu_create().unwrap();
        let mut ipa = 0x10_0000_0000u64;
        let mut mems = Vec::new();
        for &s in &sizes {
            let mut m = vm.memory_create(s).unwrap();
            m.map(ipa, MemPerms::RWX).unwrap();
            ipa += s as u64;
            mems.push(m);
        }
        // carrick's pre-fork teardown (raw), then forget applevisor objs (no Drop).
        unsafe {
            sys::hv_vm_destroy();
        }
        std::mem::forget(mems);
        std::mem::forget(_vcpu);
        std::mem::forget(vm);
        println!("  RSS after applevisor alloc: {:.1} MB", rss_mb());
        time_fork("applevisor Memory (alloc_zeroed) 640MiB");
    } else {
        let max = {
            let mut b = 0u32;
            unsafe { sys::hv_vm_config_get_max_ipa_size(&mut b) };
            b
        };
        let cfg = unsafe { sys::hv_vm_config_create() };
        unsafe {
            sys::hv_vm_config_set_ipa_size(cfg, max);
        }
        unsafe {
            assert_eq!(sys::hv_vm_create(cfg), 0);
        }
        let mut v = 0u64;
        let mut e: *const sys::hv_vcpu_exit_t = std::ptr::null();
        unsafe {
            assert_eq!(
                sys::hv_vcpu_create(&mut v, &mut e, sys::hv_vcpu_config_create()),
                0
            );
        }
        let mut ipa = 0x10_0000_0000u64;
        for &s in &sizes {
            let buf = unsafe {
                libc::mmap(
                    std::ptr::null_mut(),
                    s,
                    libc::PROT_READ | libc::PROT_WRITE,
                    libc::MAP_ANON | libc::MAP_PRIVATE,
                    -1,
                    0,
                )
            };
            unsafe {
                assert_eq!(
                    sys::hv_vm_map(
                        buf,
                        ipa,
                        s,
                        sys::HV_MEMORY_READ | sys::HV_MEMORY_WRITE | sys::HV_MEMORY_EXEC
                    ),
                    0
                );
            }
            ipa += s as u64;
        }
        unsafe {
            sys::hv_vcpu_destroy(v);
            sys::hv_vm_destroy();
        }
        println!("  RSS after raw mmap: {:.1} MB", rss_mb());
        time_fork("raw mmap 640MiB");
    }
}
#[cfg(not(all(target_os = "macos", target_arch = "aarch64")))]
fn main() {}
