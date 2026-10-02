fn main() {
    if let Err(err) = carrick_xtask::cli::run(std::env::args_os()) {
        eprintln!("carrick-xtask: {err}");
        std::process::exit(1);
    }
}
