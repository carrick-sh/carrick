// Dev-only standalone native-x86 ELF runner: `native_run <path>`.
// Lets a debugger (lldb/dtrace) attach to a single guest run without the
// test-harness threads. Not shipped; gated to the FreeBSD/amd64 lane.
fn main() {
    #[cfg(all(target_os = "freebsd", target_arch = "x86_64"))]
    {
        let Some(path) = std::env::args().nth(1) else {
            eprintln!("usage: native_run <elf>");
            std::process::exit(2);
        };
        match carrick_runtime::runtime::run_elf_native_dispatch(std::path::Path::new(&path)) {
            Ok(r) => {
                eprintln!(
                    "[native_run] exit={} traps={} stdout={:?}",
                    r.exit_code,
                    r.traps,
                    String::from_utf8_lossy(&r.stdout)
                );
                std::process::exit(r.exit_code);
            }
            Err(e) => {
                eprintln!("[native_run] stopped: {e:?}");
                std::process::exit(125);
            }
        }
    }
    #[cfg(not(all(target_os = "freebsd", target_arch = "x86_64")))]
    eprintln!("native_run is FreeBSD/amd64 only");
}
