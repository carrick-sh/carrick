// Dev-only standalone native-x86 ELF runner: `native_run <path>`.
// Lets a debugger (lldb/dtrace) attach to a single guest run without the
// test-harness threads. Not shipped; gated to the FreeBSD/amd64 lane.
fn main() {
    #[cfg(all(target_os = "freebsd", target_arch = "x86_64"))]
    {
        // Register the carrick USDT provider so the dispatcher's
        // `carrick:::syscall__entry` / `syscall__return` (and the dsr__*)
        // probes fire — trace a run with e.g.
        //   dtrace -n 'carrick*:::syscall__return { @[copyinstr(arg1)] = count(); }'
        // This is the real observability path (the CLI does the same); no
        // env-gated logging needed.
        if let Err(e) = carrick_runtime::probes::register_dtrace_probes() {
            eprintln!("[native_run] warning: USDT probe registration failed: {e}");
        }
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
