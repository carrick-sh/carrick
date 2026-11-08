#![allow(dead_code)]

use std::process::Command;

/// Give a test child its own Cargo settings while retaining the installed cache.
pub fn clean_cargo_env(command: &mut Command) -> &mut Command {
    for (name, _) in std::env::vars_os() {
        let text = name.to_string_lossy();
        if (text.starts_with("CARGO_") && text != "CARGO_HOME")
            || text == "RUSTC"
            || text.starts_with("RUSTC_")
            || text == "RUSTDOC"
            || text == "RUSTFLAGS"
            || text == "RUSTDOCFLAGS"
        {
            command.env_remove(name);
        }
    }
    command
}

/// Re-execute a test whose production entry point checks its own environment.
#[allow(clippy::unwrap_used)]
pub fn in_clean_cargo_test() -> bool {
    const CHILD: &str = "CARRICK_XTASK_CLEAN_CARGO_TEST";
    let name = std::thread::current().name().unwrap().to_owned();
    if std::env::var(CHILD).as_deref() == Ok(name.as_str()) {
        return true;
    }
    let mut command = Command::new(std::env::current_exe().unwrap());
    clean_cargo_env(&mut command);
    let output = command
        .args(["--exact", &name, "--nocapture"])
        .env(CHILD, &name)
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success() && stdout.contains("test result: ok. 1 passed;"),
        "clean-environment test {name} failed: {}\n{stdout}\n{stderr}",
        output.status
    );
    false
}
