#![allow(clippy::unwrap_used)]

#[test]
fn thread_stress_harness_dry_run_describes_metrics_command() {
    let output = std::process::Command::new("scripts/run-thread-stress.sh")
        .arg("--dry-run")
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "dry run failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("carrick-linux-aarch64-thread-stress"));
    assert!(stdout.contains("wall_seconds"));
    assert!(stdout.contains("syscalls_per_second"));
    assert!(stdout.contains("cpu_utilization_percent"));
}
