//! Consolidated `kvm`-lane integration-test binary for `carrick-vmm-kvm` (#2408).
//!
//! Compiling the 14 live/KVM integration suites as modules of one test binary
//! links `carrick-vmm-kvm` and `carrick-runtime` once instead of 14 times.
//! VM-free `tests/cpl0_image_inputs.rs` stays a separate `host`-lane binary.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
#[path = "../common/kvm_pool_fixture.rs"]
pub(crate) mod kvm_pool_fixture;
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
pub(crate) use kvm_pool_fixture::physical_inventory;

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
mod carrier_cpu;
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
mod carrier_memory;
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
mod cpl0_entry;
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
mod cpl0_exit_drain_wake;
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
mod cpl0_fork_e2e;
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
mod cpl0_group_exit;
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
mod cpl0_initial_mm;
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
mod cpl0_lifecycle;
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
mod cpl0_progress;
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
mod cpl0_shared_entry;
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
mod cpuid_v3_kvm;
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
mod detached_composition_root;
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
mod live_vcpu_x86;
#[cfg(target_os = "linux")]
mod sentinel_decode;
