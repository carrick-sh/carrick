use std::process::Command;

#[test]
fn classification_never_defaults_to_guest() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(2)
        .unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_investigate"))
        .current_dir(root)
        .args([
            "classify",
            "--id",
            "missing-decision",
            "--contract",
            "kernel.inotify.readiness",
        ])
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("exactly one explicit"));
}
