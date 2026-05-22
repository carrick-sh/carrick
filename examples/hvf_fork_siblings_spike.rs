//! Feasibility spike for fork(2) with LIVE sibling vCPUs.
//!
//! carrick's normal fork tears down the process VM pre-fork (HVF isn't
//! fork-safe). That's fine with one thread, but a thread-creating-clone guest
//! may fork while sibling vCPUs are live — we can't destroy the VM out from
//! under them. So: can a forked CHILD that inherited a still-live VM rebuild
//! its own fresh HVF state (destroy inherited + create new + vcpu)?
//!
//! Build + sign + run:
//!   cargo build --release --example hvf_fork_siblings_spike
//!   codesign --force --sign - --entitlements scripts/entitlements.plist \
//!     target/release/examples/hvf_fork_siblings_spike
//!   target/release/examples/hvf_fork_siblings_spike ; echo "exit=$?"
#![allow(clippy::unwrap_used, clippy::expect_used)]

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
fn main() {
    use applevisor::prelude::*;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};

    let max_ipa = VirtualMachineConfig::get_max_ipa_size().expect("max_ipa");
    let mut config = VirtualMachineConfig::new();
    config.set_ipa_size(max_ipa).expect("set_ipa");
    let vm = VirtualMachine::with_config(config).expect("vm create");
    let _vcpu0 = vm.vcpu_create().expect("vcpu0 main");
    println!("OK: vm + vcpu0 on main thread");

    // Keep a sibling vCPU alive on another host thread (it just parks).
    let stop = Arc::new(AtomicBool::new(false));
    let stop_thread = Arc::clone(&stop);
    let vm_sib = vm.clone();
    let sib = std::thread::spawn(move || {
        let _vcpu1 = vm_sib.vcpu_create().expect("vcpu1 sibling");
        println!("OK: vcpu1 on sibling thread (parking)");
        while !stop_thread.load(Ordering::Relaxed) {
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        // Drop vcpu1 on its owning thread.
    });

    std::thread::sleep(std::time::Duration::from_millis(50));

    // Fork WITHOUT tearing down the parent's VM (siblings need it).
    let pid = unsafe { libc::fork() };
    if pid < 0 {
        eprintln!("FAIL: fork errno {}", std::io::Error::last_os_error());
        std::process::exit(1);
    }
    if pid == 0 {
        // ----- CHILD: single-threaded, inherited a live VM. -----
        // Try to clear the inherited (fork-unsafe) HVF state and rebuild.
        let d_vcpu = unsafe { applevisor_sys::hv_vcpu_destroy(_vcpu0.id()) };
        let d_vm = unsafe { applevisor_sys::hv_vm_destroy() };
        eprintln!("[child] hv_vcpu_destroy={d_vcpu} hv_vm_destroy={d_vm}");
        let max_ipa = match VirtualMachineConfig::get_max_ipa_size() {
            Ok(v) => v,
            Err(e) => {
                eprintln!("[child] FAIL get_max_ipa: {e:?}");
                unsafe { libc::_exit(11) };
            }
        };
        let mut cfg = VirtualMachineConfig::new();
        if let Err(e) = cfg.set_ipa_size(max_ipa) {
            eprintln!("[child] FAIL set_ipa: {e:?}");
            unsafe { libc::_exit(12) };
        }
        match VirtualMachine::with_config(cfg) {
            Ok(new_vm) => match new_vm.vcpu_create() {
                Ok(_v) => {
                    eprintln!("[child] OK: rebuilt VM + vcpu in forked child");
                    // Leak via forget so applevisor Drop doesn't run the
                    // panicky destructors on this rebuilt context.
                    std::mem::forget(new_vm);
                    unsafe { libc::_exit(0) };
                }
                Err(e) => {
                    eprintln!("[child] FAIL vcpu_create after rebuild: {e:?}");
                    unsafe { libc::_exit(13) };
                }
            },
            Err(e) => {
                eprintln!("[child] FAIL vm rebuild: {e:?}");
                unsafe { libc::_exit(14) };
            }
        }
    }

    // ----- PARENT: VM untouched; sibling should still be alive. -----
    let mut status: libc::c_int = 0;
    unsafe { libc::waitpid(pid, &mut status, 0) };
    let child_code = if libc::WIFEXITED(status) {
        libc::WEXITSTATUS(status)
    } else {
        -1
    };
    println!("[parent] child exit code = {child_code}");

    // Prove the parent's VM + sibling vcpu still work: create a 3rd vcpu.
    let vm_after = vm.clone();
    let after = std::thread::spawn(move || vm_after.vcpu_create().is_ok());
    let parent_vm_ok = after.join().unwrap_or(false);
    println!("[parent] post-fork vcpu_create on parent VM ok = {parent_vm_ok}");

    stop.store(true, Ordering::Relaxed);
    let _ = sib.join();

    if child_code == 0 && parent_vm_ok {
        println!("SPIKE PASS: child rebuilt HVF; parent VM survived fork-with-siblings");
        std::process::exit(0);
    } else {
        println!("SPIKE FAIL: child_code={child_code} parent_vm_ok={parent_vm_ok}");
        std::process::exit(2);
    }
}

#[cfg(not(all(target_os = "macos", target_arch = "aarch64")))]
fn main() {
    eprintln!("spike only runs on macOS/aarch64");
    std::process::exit(2);
}
