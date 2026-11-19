use std::path::Path;
use std::process::Command;

pub fn compile_static_fixture(source: &Path, output: &Path, flags: &[&str]) {
    let build = Command::new("timeout")
        .args(["15", "cc", "-static", "-no-pie", "-Wl,--build-id=none"])
        .args(flags)
        .arg(source)
        .arg("-o")
        .arg(output)
        .output()
        .expect("compile x86 process entry fixture");
    assert!(
        build.status.success(),
        "compile {}: {}",
        source.display(),
        String::from_utf8_lossy(&build.stderr)
    );
}
