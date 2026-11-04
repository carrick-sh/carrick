fn main() {
    let mut args: Vec<_> = std::env::args_os().collect();
    // Agent clones admit a root-owned copy of this binary named `bpftrace`
    // through sudo (#1621). Under that name it is only the argument front,
    // never the general CLI: decided by the executing file's own path, which
    // the caller cannot redirect, as well as by argv[0].
    let front = |path: &std::path::Path| path.file_name().is_some_and(|n| n == "bpftrace");
    if std::env::current_exe().is_ok_and(|exe| front(&exe))
        || args
            .first()
            .is_some_and(|name| front(std::path::Path::new(name)))
    {
        std::process::exit(carrick_xtask::ci_scaler::bpftrace_front(
            args.get(1..).unwrap_or_default(),
        ));
    }
    if args.first().is_some_and(|name| {
        std::path::Path::new(name)
            .file_name()
            .is_some_and(|n| n == "dispatch-worker")
    }) {
        args.insert(1, "dispatch-worker".into());
    }
    if let Err(err) = carrick_xtask::cli::run(args) {
        eprintln!("carrick-xtask: {err}");
        std::process::exit(match err {
            carrick_xtask::cli::CliError::LoomRun { code, .. } => code,
            _ => 1,
        });
    }
}
