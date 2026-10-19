#![cfg(target_os = "linux")]
//! `carrick-x86-cpl0-host` — Machine-neutral host coordinator and custody for the
//! x86 CPL0 production carrier.

#[cfg(target_arch = "x86_64")]
pub mod carrier_cpu;
#[cfg(target_arch = "x86_64")]
pub mod carrier_memory;
#[cfg(target_arch = "x86_64")]
pub mod cpl0_boot;
#[cfg(target_arch = "x86_64")]
mod cpl0_private_witness;
pub mod guest_ram;
