fn main() {
    let args: Vec<_> = std::env::args_os().collect();
    if let Err(err) = carrick_xtask::cli::run(args) {
        eprintln!("carrick-xtask: {err}");
        std::process::exit(match err {
            carrick_xtask::cli::CliError::LoomRun { code, .. } => code,
            _ => 1,
        });
    }
}
