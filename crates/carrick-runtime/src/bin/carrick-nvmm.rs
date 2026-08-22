//! `carrick-nvmm` — run a real x86_64 Linux ELF under NVMM through the FULL
//! `carrick-runtime` dispatcher.
//!
//! Usage: `carrick-nvmm run-elf <x86_64-elf>`
//!
//! NetBSD/**x86_64** only. `required-features = ["platform-netbsd"]` cannot
//! express an arch, and both entry points this driver calls
//! (`run_elf_real_dispatch`, `run_oci`) exist only under
//! `all(feature = "platform-netbsd", target_arch = "x86_64")` — NVMM is an
//! x86-only NetBSD subsystem. So the arch belongs in the `cfg` here, or a
//! NetBSD/aarch64 `cargo build`/`clippy --all-targets` picks this bin up and
//! fails on two unresolved names instead of taking the stub `main` below.

#[cfg(all(
    target_os = "netbsd",
    feature = "platform-netbsd",
    target_arch = "x86_64"
))]
fn main() {
    use std::io::Write as _;

    let mut args = std::env::args().skip(1);
    match args.next().as_deref() {
        Some("run-elf") => {
            let Some(path) = args.next() else {
                eprintln!("usage: carrick-nvmm run-elf <x86_64-elf>");
                std::process::exit(2);
            };
            match carrick_runtime::runtime::run_elf_real_dispatch(std::path::Path::new(&path)) {
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
                    eprintln!("carrick-nvmm: {e}");
                    std::process::exit(127);
                }
            }
        }
        Some("run-oci") => {
            let (Some(layers_arg), Some(entrypoint)) = (args.next(), args.next()) else {
                eprintln!(
                    "usage: carrick-nvmm run-oci <layer-tar[,tar...]> <entrypoint> [args...]"
                );
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
                cap_add: Vec::new(),
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
                // run-oci is a container-shaped dev driver: model docker's
                // launch-time default seccomp policy like `carrick run`.
                seccomp_policy: carrick_spec::SeccompPolicy::ContainerDefault,
                // This bin drives the NVMM VMM backend.
                exec_backend: carrick_spec::ExecBackendRequest::HvPatch,
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
                    eprintln!("carrick-nvmm: {e}");
                    std::process::exit(127);
                }
            }
        }
        _ => {
            eprintln!(
                "usage: carrick-nvmm (run-elf <x86_64-elf> | run-oci <layer-tar> <entrypoint> [args...])"
            );
            std::process::exit(2);
        }
    }
}

#[cfg(not(all(
    target_os = "netbsd",
    feature = "platform-netbsd",
    target_arch = "x86_64"
)))]
fn main() {
    eprintln!(
        "carrick-nvmm requires a NetBSD/x86_64 host built with --features platform-netbsd \
         (NVMM is an x86-only NetBSD subsystem)"
    );
    std::process::exit(1);
}
