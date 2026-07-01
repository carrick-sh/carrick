//! `carrick-kvm` — run a real aarch64 Linux ELF under KVM through the FULL
//! `carrick-runtime` dispatcher (the Phase B real-dispatch driver).
//!
//! Usage: `carrick-kvm run-elf <aarch64-elf>`
//!
//! Unlike the thin `carrick-vmm-kvm run-elf` shim (which services only
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
        Some("run-oci") => {
            // carrick-kvm run-oci <layer-tar[,layer-tar...]> <entrypoint> [args...]
            // The OCI container driver: extract the image layers onto a rootfs,
            // load the (full-path) entrypoint FROM the rootfs, run it under KVM.
            // A single flat rootfs tar (`docker export`) is one "layer".
            let (Some(layers_arg), Some(entrypoint)) = (args.next(), args.next()) else {
                eprintln!("usage: carrick-kvm run-oci <layer-tar[,tar...]> <entrypoint> [args...]");
                std::process::exit(2);
            };
            let rest: Vec<String> = args.collect();
            let layers: Vec<camino::Utf8PathBuf> = layers_arg
                .split(',')
                .filter(|s| !s.is_empty())
                .map(camino::Utf8PathBuf::from)
                .collect();
            let mut argv = vec![entrypoint.clone()];
            argv.extend(rest);
            let spec = carrick_spec::RunSpec {
                executable: entrypoint,
                argv,
                envp: vec![
                    "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin".to_string(),
                    "HOME=/root".to_string(),
                    "HOSTNAME=carrick".to_string(),
                ],
                cwd: None,
                rootfs_layers: layers,
                fs_backend: carrick_spec::FsBackendKind::Host,
                mounts: Vec::new(),
                tty: false,
                raw: false,
                interactive: false,
                max_traps: carrick_runtime::runtime::DEFAULT_MAX_TRAPS,
                debug_state_path: None,
                platform: carrick_spec::Platform::default(),
                pid: carrick_spec::PidMode::default(),
                hostname: None,
                network: carrick_spec::NetworkNamespaceSpec::default(),
                extra_hosts: Vec::new(),
                uid: 0,
                gid: 0,
            };
            match carrick_runtime::runtime::run_oci(&spec) {
                Ok(result) => {
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
            eprintln!(
                "usage: carrick-kvm (run-elf <aarch64-elf> | run-oci <layer-tar> <entrypoint> [args...])"
            );
            std::process::exit(2);
        }
    }
}

#[cfg(not(all(target_os = "linux", feature = "platform-linux")))]
fn main() {
    eprintln!("carrick-kvm requires a Linux host built with --features platform-linux");
    std::process::exit(1);
}
