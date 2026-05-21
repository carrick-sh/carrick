//! Load-bearing spike for thread-creating clone(2): can we create a SECOND
//! vCPU on a SECOND host thread in the SAME process VM?
//!
//! The whole threading architecture (one VM/process, N vCPUs each pinned to a
//! host thread, sharing guest memory) rests on this. The `applevisor` docs say
//! yes (their vcpu_create example spawns N threads, each cloning the VM and
//! creating a vCPU), but we confirm on THIS machine + entitlement before
//! building the full machinery.
//!
//! Build + sign + run:
//!   cargo build --release --example hvf_thread_spike
//!   codesign --force --sign - --entitlements scripts/entitlements.plist \
//!     target/release/examples/hvf_thread_spike
//!   target/release/examples/hvf_thread_spike
//!
//! Exits 0 on success, non-zero (with a message) on failure.
#![allow(clippy::unwrap_used, clippy::expect_used)]

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
fn main() {
    use applevisor::prelude::*;

    let max_ipa = VirtualMachineConfig::get_max_ipa_size().expect("max_ipa");
    let mut config = VirtualMachineConfig::new();
    config.set_ipa_size(max_ipa).expect("set_ipa");
    let vm = VirtualMachine::with_config(config).expect("vm create");

    // First vCPU on the main thread (this is what carrick does today).
    let _vcpu0 = vm.vcpu_create().expect("vcpu0 on main thread");
    println!("OK: vcpu0 created on main thread");

    // Second + third vCPUs on separate host threads, each cloning the VM
    // handle — exactly the pattern thread-creating clone will use.
    let mut handles = Vec::new();
    for i in 1..=2u32 {
        let vm_thread = vm.clone();
        handles.push(std::thread::spawn(move || {
            let _vcpu = vm_thread
                .vcpu_create()
                .unwrap_or_else(|e| panic!("vcpu{i} on worker thread failed: {e:?}"));
            println!("OK: vcpu{i} created on worker thread");
            // Drop the vcpu on the same thread that created it (HVF requires
            // create+destroy on the owning thread).
        }));
    }
    for h in handles {
        h.join().expect("worker thread panicked");
    }

    println!("SPIKE PASS: N vCPUs across N host threads in one VM works");
}

#[cfg(not(all(target_os = "macos", target_arch = "aarch64")))]
fn main() {
    eprintln!("spike only runs on macOS/aarch64");
    std::process::exit(2);
}
