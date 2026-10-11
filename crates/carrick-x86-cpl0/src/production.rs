//! Production CPL0 image entry.
#![cfg_attr(target_os = "none", no_std)]
#![cfg_attr(target_os = "none", no_main)]

#[cfg(all(target_os = "none", target_arch = "x86_64"))]
carrick_x86_carrier::export_carrier!(carrick_x86_cpl0::linux_personality::LinuxPersonality);

#[allow(dead_code)]
fn main() {}
