fn main() {
    let mut args: Vec<_> = std::env::args_os().collect();
    if args.first().is_some_and(|name| {
        std::path::Path::new(name)
            .file_name()
            .is_some_and(|n| n == "dispatch-worker")
    }) {
        args.insert(1, "dispatch-worker".into());
    }
    if let Err(err) = carrick_xtask::cli::run(args) {
        eprintln!("carrick-xtask: {err}");
        std::process::exit(1);
    }
}
