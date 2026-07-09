#[path = "../native_exec_probe/mod.rs"]
mod native_exec_probe;

fn main() {
    let code = match native_exec_probe::run_from_env() {
        Ok(()) => 0,
        Err(err) => {
            eprintln!("native_exec_probe: {err}");
            2
        }
    };
    std::process::exit(code);
}
