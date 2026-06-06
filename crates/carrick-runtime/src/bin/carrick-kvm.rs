//! `carrick-kvm` — run a real aarch64 Linux ELF under KVM through the FULL
//! `carrick-runtime` dispatcher (the Phase B real-dispatch driver).
//!
//! Usage: `carrick-kvm run-elf <aarch64-elf>`
//!
//! Unlike the thin `carrick-linux run-elf` shim (which services only
//! `write`/`writev`/`exit` directly, with no `carrick-runtime` dependency),
//! this drives `KvmTrapEngine` through the real `SyscallDispatcher` — the same
//! dispatch layer the macOS/HVF backend uses. Built only with
//! `--features platform-linux`; on any other configuration `main` is a stub.
#[cfg(all(target_os = "linux", feature = "platform-linux"))]
fn main() {
    use std::io::Write as _;

    let mut args = std::env::args().skip(1);
    match args.next().as_deref() {
        Some("run-elf") => {
            let Some(path) = args.next() else {
                eprintln!("usage: carrick-kvm run-elf <aarch64-elf>");
                std::process::exit(2);
            };
            match carrick_runtime::runtime::run_elf_real_dispatch(std::path::Path::new(&path)) {
                Ok(result) => {
                    // The dispatcher buffers the guest's fd 1/2; flush to the
                    // host now so the smoke harness sees the guest's output.
                    let mut out = std::io::stdout();
                    let _ = out.write_all(&result.stdout);
                    let _ = out.flush();
                    let mut err = std::io::stderr();
                    let _ = err.write_all(&result.stderr);
                    let _ = err.flush();
                    std::process::exit(result.exit_code);
                }
                Err(e) => {
                    eprintln!("carrick-kvm: {e}");
                    std::process::exit(127);
                }
            }
        }
        _ => {
            eprintln!("usage: carrick-kvm run-elf <aarch64-elf>");
            std::process::exit(2);
        }
    }
}

#[cfg(not(all(target_os = "linux", feature = "platform-linux")))]
fn main() {
    eprintln!("carrick-kvm requires a Linux host built with --features platform-linux");
    std::process::exit(1);
}
