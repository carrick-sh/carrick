//! `sudo carrick-capture <name> [--seconds N]`; see the library docs.
#![forbid(unsafe_code)]

fn main() {
    let args: Vec<_> = std::env::args_os().skip(1).collect();
    std::process::exit(carrick_capture::run(&args));
}
