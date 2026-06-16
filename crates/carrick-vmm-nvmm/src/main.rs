//! `carrick-vmm-nvmm` binary — the NVMM x86_64 ELF runner entry point.
//!
//! Usage: `carrick-vmm-nvmm run-elf <static-x86_64-elf>`
//!
//! NetBSD/x86_64 only (the binary is a no-op stub on all other hosts). Mirrors
//! `carrick-vmm-bhyve`'s standalone `run-elf` surface.

#[cfg(all(target_os = "netbsd", target_arch = "x86_64"))]
fn main() {
    let mut args = std::env::args().skip(1);
    match args.next().as_deref() {
        Some("run-elf") => {
            let Some(path) = args.next() else {
                eprintln!("usage: carrick-vmm-nvmm run-elf <x86_64-elf>");
                std::process::exit(2);
            };
            match carrick_vmm_nvmm::run_elf_nvmm(&path) {
                Ok(code) => std::process::exit(code),
                Err(e) => {
                    eprintln!("carrick-vmm-nvmm: {e}");
                    std::process::exit(127);
                }
            }
        }
        _ => {
            eprintln!("usage: carrick-vmm-nvmm run-elf <x86_64-elf>");
            std::process::exit(2);
        }
    }
}

#[cfg(not(all(target_os = "netbsd", target_arch = "x86_64")))]
fn main() {
    eprintln!("carrick-vmm-nvmm is a NetBSD/x86_64-only binary");
    std::process::exit(1);
}
