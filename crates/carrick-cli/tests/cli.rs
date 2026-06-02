// Test code: gzip/tar helpers are plain `fn`s (not `#[test]`/`#[cfg(test)]`), so
// clippy's allow-unwrap-in-tests heuristic does not exempt them. The no-panic gate
// targets production code, so allow unwrap/expect across this integration test file.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use assert_cmd::Command;
use carrick_image::{ImageReference, ImageStore, LayerSummary, PullSummary};
use carrick_test_support::gzip_tar;
use predicates::prelude::PredicateBooleanExt;
use predicates::str::contains;

#[test]
fn inspect_elf_command_prints_json_metadata() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("hello");
    std::fs::write(&path, minimal_aarch64_elf()).unwrap();

    Command::cargo_bin("carrick")
        .unwrap()
        .args(["inspect-elf", path.to_str().unwrap()])
        .assert()
        .success()
        .stdout(contains("\"machine\": \"aarch64\""))
        .stdout(contains("\"entry\": 4194304"));
}

#[test]
fn plan_elf_load_command_prints_segment_plan() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("hello");
    std::fs::write(&path, minimal_aarch64_elf_with_load_segment()).unwrap();

    Command::cargo_bin("carrick")
        .unwrap()
        .args(["plan-elf-load", path.to_str().unwrap()])
        .assert()
        .success()
        .stdout(contains("\"virtual_address\": 4194304"))
        .stdout(contains("\"execute\": true"));
}

#[test]
fn rootfs_cli_lists_and_reads_composed_layers() {
    let dir = tempfile::tempdir().unwrap();
    let base = dir.path().join("base.tar.gz");
    let upper = dir.path().join("upper.tar.gz");
    std::fs::write(&base, gzip_tar([("etc/motd", b"base".as_slice())])).unwrap();
    std::fs::write(
        &upper,
        gzip_tar([
            ("etc/.wh.motd", b"".as_slice()),
            ("etc/os-release", b"NAME=upper\n".as_slice()),
        ]),
    )
    .unwrap();

    Command::cargo_bin("carrick")
        .unwrap()
        .args([
            "rootfs",
            "--layer",
            base.to_str().unwrap(),
            "--layer",
            upper.to_str().unwrap(),
            "ls",
            "/etc",
        ])
        .assert()
        .success()
        .stdout(contains("os-release"))
        .stdout(predicates::str::contains("motd").not());

    Command::cargo_bin("carrick")
        .unwrap()
        .args([
            "rootfs",
            "--layer",
            base.to_str().unwrap(),
            "--layer",
            upper.to_str().unwrap(),
            "cat",
            "/etc/os-release",
        ])
        .assert()
        .success()
        .stdout(contains("NAME=upper"));
}

#[test]
fn dispatch_syscall_cli_exercises_write_path() {
    Command::cargo_bin("carrick")
        .unwrap()
        .args([
            "dispatch-syscall",
            "64",
            "--args",
            "1,16384,5,0,0,0",
            "--memory-base",
            "16384",
            "--memory-text",
            "hello",
        ])
        .assert()
        .success()
        .stdout(contains("\"stdout\": \"hello\""))
        .stdout(contains("\"value\": 5"));
}

#[test]
fn load_elf_command_prints_address_space_summary() {
    let output = std::process::Command::new("scripts/build-linux-fixtures.sh")
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "fixture build failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    Command::cargo_bin("carrick")
        .unwrap()
        .args([
            "load-elf",
            "fixtures/linux-aarch64-hello/target/aarch64-unknown-linux-musl/release/carrick-linux-aarch64-hello",
            "--find-text",
            "hello from carrick\n",
        ])
        .assert()
        .success()
        .stdout(contains("\"region_count\""))
        .stdout(contains("\"found_address\""));
}

#[test]
fn run_elf_command_executes_or_reports_hvf_backend_error() {
    let output = std::process::Command::new("scripts/build-linux-fixtures.sh")
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "fixture build failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let output = Command::cargo_bin("carrick")
        .unwrap()
        .args([
            "run-elf",
            "fixtures/linux-aarch64-hello/target/aarch64-unknown-linux-musl/release/carrick-linux-aarch64-hello",
            "--max-traps",
            "8",
        ])
        .output()
        .unwrap();

    if output.status.success() {
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(stdout.contains("\"exit_code\": 0"));
        assert!(stdout.contains("hello from carrick"));
        assert!(stdout.contains("\"traps\": 2"));
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            stderr.contains("Hypervisor.framework"),
            "unexpected run-elf failure:\n{stderr}"
        );
    }
}

#[test]
fn run_elf_command_can_use_rootfs_layers_for_static_fixture() {
    let output = std::process::Command::new("scripts/build-linux-fixtures.sh")
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "fixture build failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let dir = tempfile::tempdir().unwrap();
    let layer = dir.path().join("rootfs.tar.gz");
    std::fs::write(
        &layer,
        gzip_tar([("etc/motd", b"rootfs says hello\n".as_slice())]),
    )
    .unwrap();

    let output = Command::cargo_bin("carrick")
        .unwrap()
        .args([
            "run-elf",
            "fixtures/linux-aarch64-hello/target/aarch64-unknown-linux-musl/release/carrick-linux-aarch64-cat-motd",
            "--rootfs-layer",
            layer.to_str().unwrap(),
            "--max-traps",
            "16",
        ])
        .output()
        .unwrap();

    if output.status.success() {
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(stdout.contains("\"exit_code\": 0"));
        assert!(stdout.contains("rootfs says hello"));
        assert!(stdout.contains("\"traps\": 5"));
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            stderr.contains("Hypervisor.framework"),
            "unexpected run-elf failure:\n{stderr}"
        );
    }
}

#[test]
fn run_elf_command_passes_guest_argv_stack_to_static_fixture() {
    let output = std::process::Command::new("scripts/build-linux-fixtures.sh")
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "fixture build failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let output = Command::cargo_bin("carrick")
        .unwrap()
        .args([
            "run-elf",
            "fixtures/linux-aarch64-hello/target/aarch64-unknown-linux-musl/release/carrick-linux-aarch64-argv-echo",
            "--max-traps",
            "8",
            "--",
            "from-argv",
        ])
        .output()
        .unwrap();

    if output.status.success() {
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(stdout.contains("\"exit_code\": 0"));
        assert!(stdout.contains("from-argv\\n"));
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            stderr.contains("Hypervisor.framework"),
            "unexpected run-elf failure:\n{stderr}"
        );
    }
}

#[test]
fn run_elf_command_drives_timerfd_epoll_static_fixture() {
    let output = std::process::Command::new("scripts/build-linux-fixtures.sh")
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "fixture build failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let output = Command::cargo_bin("carrick")
        .unwrap()
        .args([
            "run-elf",
            "fixtures/linux-aarch64-hello/target/aarch64-unknown-linux-musl/release/carrick-linux-aarch64-timerfd-epoll",
            "--max-traps",
            "16",
        ])
        .output()
        .unwrap();

    if output.status.success() {
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(stdout.contains("\"exit_code\": 0"));
        assert!(stdout.contains("timerfd ready\\n"));
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            stderr.contains("Hypervisor.framework"),
            "unexpected run-elf failure:\n{stderr}"
        );
    }
}

#[test]
fn run_elf_command_drives_ppoll_eventfd_static_fixture() {
    let output = std::process::Command::new("scripts/build-linux-fixtures.sh")
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "fixture build failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let output = Command::cargo_bin("carrick")
        .unwrap()
        .args([
            "run-elf",
            "fixtures/linux-aarch64-hello/target/aarch64-unknown-linux-musl/release/carrick-linux-aarch64-ppoll-eventfd",
            "--max-traps",
            "16",
        ])
        .output()
        .unwrap();

    if output.status.success() {
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(stdout.contains("\"exit_code\": 0"));
        assert!(stdout.contains("ppoll ready\\n"));
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            stderr.contains("Hypervisor.framework"),
            "unexpected run-elf failure:\n{stderr}"
        );
    }
}

#[test]
fn run_elf_command_drives_pselect_eventfd_static_fixture() {
    let output = std::process::Command::new("scripts/build-linux-fixtures.sh")
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "fixture build failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let output = Command::cargo_bin("carrick")
        .unwrap()
        .args([
            "run-elf",
            "fixtures/linux-aarch64-hello/target/aarch64-unknown-linux-musl/release/carrick-linux-aarch64-pselect-eventfd",
            "--max-traps",
            "16",
        ])
        .output()
        .unwrap();

    if output.status.success() {
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(stdout.contains("\"exit_code\": 0"));
        assert!(stdout.contains("pselect ready\\n"));
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            stderr.contains("Hypervisor.framework"),
            "unexpected run-elf failure:\n{stderr}"
        );
    }
}

#[test]
fn run_elf_command_drives_process_bootstrap_static_fixture() {
    let output = std::process::Command::new("scripts/build-linux-fixtures.sh")
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "fixture build failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let output = Command::cargo_bin("carrick")
        .unwrap()
        .args([
            "run-elf",
            "fixtures/linux-aarch64-hello/target/aarch64-unknown-linux-musl/release/carrick-linux-aarch64-process-bootstrap",
            "--max-traps",
            "16",
        ])
        .output()
        .unwrap();

    if output.status.success() {
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(stdout.contains("\"exit_code\": 0"));
        assert!(stdout.contains("process bootstrap\\n"));
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            stderr.contains("Hypervisor.framework"),
            "unexpected run-elf failure:\n{stderr}"
        );
    }
}

#[test]
fn run_elf_command_drives_futex_static_fixture() {
    let output = std::process::Command::new("scripts/build-linux-fixtures.sh")
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "fixture build failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let output = Command::cargo_bin("carrick")
        .unwrap()
        .args([
            "run-elf",
            "fixtures/linux-aarch64-hello/target/aarch64-unknown-linux-musl/release/carrick-linux-aarch64-futex",
            "--max-traps",
            "16",
        ])
        .output()
        .unwrap();

    if output.status.success() {
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(stdout.contains("\"exit_code\": 0"));
        assert!(stdout.contains("futex\\n"));
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            stderr.contains("Hypervisor.framework"),
            "unexpected run-elf failure:\n{stderr}"
        );
    }
}

#[test]
fn run_elf_command_drives_rseq_static_fixture() {
    let output = std::process::Command::new("scripts/build-linux-fixtures.sh")
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "fixture build failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let output = Command::cargo_bin("carrick")
        .unwrap()
        .args([
            "run-elf",
            "fixtures/linux-aarch64-hello/target/aarch64-unknown-linux-musl/release/carrick-linux-aarch64-rseq",
            "--max-traps",
            "16",
        ])
        .output()
        .unwrap();

    if output.status.success() {
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(stdout.contains("\"exit_code\": 0"));
        assert!(stdout.contains("rseq\\n"));
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            stderr.contains("Hypervisor.framework"),
            "unexpected run-elf failure:\n{stderr}"
        );
    }
}

#[test]
fn run_elf_command_drives_membarrier_static_fixture() {
    let output = std::process::Command::new("scripts/build-linux-fixtures.sh")
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "fixture build failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let output = Command::cargo_bin("carrick")
        .unwrap()
        .args([
            "run-elf",
            "fixtures/linux-aarch64-hello/target/aarch64-unknown-linux-musl/release/carrick-linux-aarch64-membarrier",
            "--max-traps",
            "16",
        ])
        .output()
        .unwrap();

    if output.status.success() {
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(stdout.contains("\"exit_code\": 0"));
        assert!(stdout.contains("membarrier\\n"));
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            stderr.contains("Hypervisor.framework"),
            "unexpected run-elf failure:\n{stderr}"
        );
    }
}

#[test]
fn run_elf_command_drives_scheduler_static_fixture() {
    let output = std::process::Command::new("scripts/build-linux-fixtures.sh")
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "fixture build failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let output = Command::cargo_bin("carrick")
        .unwrap()
        .args([
            "run-elf",
            "fixtures/linux-aarch64-hello/target/aarch64-unknown-linux-musl/release/carrick-linux-aarch64-scheduler",
            "--max-traps",
            "16",
        ])
        .output()
        .unwrap();

    if output.status.success() {
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(stdout.contains("\"exit_code\": 0"));
        assert!(stdout.contains("scheduler\\n"));
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            stderr.contains("Hypervisor.framework"),
            "unexpected run-elf failure:\n{stderr}"
        );
    }
}

#[test]
fn run_elf_command_drives_prctl_static_fixture() {
    let output = std::process::Command::new("scripts/build-linux-fixtures.sh")
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "fixture build failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let output = Command::cargo_bin("carrick")
        .unwrap()
        .args([
            "run-elf",
            "fixtures/linux-aarch64-hello/target/aarch64-unknown-linux-musl/release/carrick-linux-aarch64-prctl",
            "--max-traps",
            "16",
        ])
        .output()
        .unwrap();

    if output.status.success() {
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(stdout.contains("\"exit_code\": 0"));
        assert!(stdout.contains("prctl\\n"));
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            stderr.contains("Hypervisor.framework"),
            "unexpected run-elf failure:\n{stderr}"
        );
    }
}

#[test]
fn run_elf_command_drives_getcpu_static_fixture() {
    let output = std::process::Command::new("scripts/build-linux-fixtures.sh")
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "fixture build failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let output = Command::cargo_bin("carrick")
        .unwrap()
        .args([
            "run-elf",
            "fixtures/linux-aarch64-hello/target/aarch64-unknown-linux-musl/release/carrick-linux-aarch64-getcpu",
            "--max-traps",
            "16",
        ])
        .output()
        .unwrap();

    if output.status.success() {
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(stdout.contains("\"exit_code\": 0"));
        assert!(stdout.contains("getcpu\\n"));
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            stderr.contains("Hypervisor.framework"),
            "unexpected run-elf failure:\n{stderr}"
        );
    }
}

#[test]
fn run_elf_command_drives_flock_static_fixture() {
    let output = std::process::Command::new("scripts/build-linux-fixtures.sh")
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "fixture build failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let layer = tempfile::NamedTempFile::new().unwrap();
    std::fs::write(
        layer.path(),
        gzip_tar([("etc/motd", b"flock motd\n".as_slice())]),
    )
    .unwrap();
    let output = Command::cargo_bin("carrick")
        .unwrap()
        .args([
            "run-elf",
            "fixtures/linux-aarch64-hello/target/aarch64-unknown-linux-musl/release/carrick-linux-aarch64-flock-motd",
            "--rootfs-layer",
            layer.path().to_str().unwrap(),
            "--max-traps",
            "16",
        ])
        .output()
        .unwrap();

    if output.status.success() {
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(stdout.contains("\"exit_code\": 0"));
        assert!(stdout.contains("flock\\n"));
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            stderr.contains("Hypervisor.framework"),
            "unexpected run-elf failure:\n{stderr}"
        );
    }
}

#[test]
fn run_elf_command_drives_nanosleep_static_fixture() {
    let output = std::process::Command::new("scripts/build-linux-fixtures.sh")
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "fixture build failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let output = Command::cargo_bin("carrick")
        .unwrap()
        .args([
            "run-elf",
            "fixtures/linux-aarch64-hello/target/aarch64-unknown-linux-musl/release/carrick-linux-aarch64-nanosleep",
            "--max-traps",
            "16",
        ])
        .output()
        .unwrap();

    if output.status.success() {
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(stdout.contains("\"exit_code\": 0"));
        assert!(stdout.contains("nanosleep\\n"));
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            stderr.contains("Hypervisor.framework"),
            "unexpected run-elf failure:\n{stderr}"
        );
    }
}

#[test]
fn run_elf_command_drives_clock_nanosleep_static_fixture() {
    let output = std::process::Command::new("scripts/build-linux-fixtures.sh")
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "fixture build failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let output = Command::cargo_bin("carrick")
        .unwrap()
        .args([
            "run-elf",
            "fixtures/linux-aarch64-hello/target/aarch64-unknown-linux-musl/release/carrick-linux-aarch64-clock-nanosleep",
            "--max-traps",
            "16",
        ])
        .output()
        .unwrap();

    if output.status.success() {
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(stdout.contains("\"exit_code\": 0"));
        assert!(stdout.contains("clock nanosleep\\n"));
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            stderr.contains("Hypervisor.framework"),
            "unexpected run-elf failure:\n{stderr}"
        );
    }
}

#[test]
fn run_elf_command_drives_sendfile_static_fixture() {
    let output = std::process::Command::new("scripts/build-linux-fixtures.sh")
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "fixture build failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let layer = tempfile::NamedTempFile::new().unwrap();
    std::fs::write(
        layer.path(),
        gzip_tar([("etc/motd", b"sendfile motd\n".as_slice())]),
    )
    .unwrap();
    let output = Command::cargo_bin("carrick")
        .unwrap()
        .args([
            "run-elf",
            "fixtures/linux-aarch64-hello/target/aarch64-unknown-linux-musl/release/carrick-linux-aarch64-sendfile-motd",
            "--rootfs-layer",
            layer.path().to_str().unwrap(),
            "--max-traps",
            "16",
        ])
        .output()
        .unwrap();

    if output.status.success() {
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(stdout.contains("\"exit_code\": 0"));
        assert!(stdout.contains("sendfile motd\\n"));
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            stderr.contains("Hypervisor.framework"),
            "unexpected run-elf failure:\n{stderr}"
        );
    }
}

#[test]
fn run_elf_command_drives_splice_static_fixture() {
    let output = std::process::Command::new("scripts/build-linux-fixtures.sh")
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "fixture build failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let layer = tempfile::NamedTempFile::new().unwrap();
    std::fs::write(
        layer.path(),
        gzip_tar([("etc/motd", b"splice fixture\n".as_slice())]),
    )
    .unwrap();
    let output = Command::cargo_bin("carrick")
        .unwrap()
        .args([
            "run-elf",
            "fixtures/linux-aarch64-hello/target/aarch64-unknown-linux-musl/release/carrick-linux-aarch64-splice-motd",
            "--rootfs-layer",
            layer.path().to_str().unwrap(),
            "--max-traps",
            "16",
        ])
        .output()
        .unwrap();

    if output.status.success() {
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(stdout.contains("\"exit_code\": 0"));
        assert!(stdout.contains("splice fixture\\n"));
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            stderr.contains("Hypervisor.framework"),
            "unexpected run-elf failure:\n{stderr}"
        );
    }
}

#[test]
fn run_elf_command_drives_preadv_static_fixture() {
    let output = std::process::Command::new("scripts/build-linux-fixtures.sh")
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "fixture build failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let layer = tempfile::NamedTempFile::new().unwrap();
    std::fs::write(
        layer.path(),
        gzip_tar([("etc/motd", b"preadv fixture\n".as_slice())]),
    )
    .unwrap();
    let output = Command::cargo_bin("carrick")
        .unwrap()
        .args([
            "run-elf",
            "fixtures/linux-aarch64-hello/target/aarch64-unknown-linux-musl/release/carrick-linux-aarch64-preadv-motd",
            "--rootfs-layer",
            layer.path().to_str().unwrap(),
            "--max-traps",
            "16",
        ])
        .output()
        .unwrap();

    if output.status.success() {
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(stdout.contains("\"exit_code\": 0"));
        assert!(stdout.contains("fixture\\n"));
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            stderr.contains("Hypervisor.framework"),
            "unexpected run-elf failure:\n{stderr}"
        );
    }
}

#[test]
fn run_elf_command_drives_errno_matrix_static_fixture() {
    let output = std::process::Command::new("scripts/build-linux-fixtures.sh")
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "fixture build failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let layer = tempfile::NamedTempFile::new().unwrap();
    std::fs::write(
        layer.path(),
        gzip_tar([("etc/motd", b"errno matrix fixture\n".as_slice())]),
    )
    .unwrap();
    let output = Command::cargo_bin("carrick")
        .unwrap()
        .args([
            "run-elf",
            "fixtures/linux-aarch64-hello/target/aarch64-unknown-linux-musl/release/carrick-linux-aarch64-errno-matrix",
            "--rootfs-layer",
            layer.path().to_str().unwrap(),
            "--max-traps",
            "128",
        ])
        .output()
        .unwrap();

    if output.status.success() {
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(stdout.contains("\"exit_code\": 0"));
        assert!(stdout.contains("errno_matrix\\n"));
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            stderr.contains("Hypervisor.framework"),
            "unexpected run-elf failure:\n{stderr}"
        );
    }
}

#[test]
fn run_elf_command_drives_linkat_static_fixture() {
    let output = std::process::Command::new("scripts/build-linux-fixtures.sh")
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "fixture build failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let layer = tempfile::NamedTempFile::new().unwrap();
    std::fs::write(
        layer.path(),
        gzip_tar([("etc/motd", b"linkat fixture\n".as_slice())]),
    )
    .unwrap();
    let output = Command::cargo_bin("carrick")
        .unwrap()
        .args([
            "run-elf",
            "fixtures/linux-aarch64-hello/target/aarch64-unknown-linux-musl/release/carrick-linux-aarch64-linkat-motd",
            "--rootfs-layer",
            layer.path().to_str().unwrap(),
            "--max-traps",
            "16",
        ])
        .output()
        .unwrap();

    if output.status.success() {
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(stdout.contains("\"exit_code\": 0"));
        assert!(stdout.contains("linkat\\n"));
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            stderr.contains("Hypervisor.framework"),
            "unexpected run-elf failure:\n{stderr}"
        );
    }
}

#[test]
fn run_elf_command_drives_symlinkat_static_fixture() {
    let output = std::process::Command::new("scripts/build-linux-fixtures.sh")
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "fixture build failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let layer = tempfile::NamedTempFile::new().unwrap();
    std::fs::write(
        layer.path(),
        gzip_tar([("etc/motd", b"symlinkat fixture\n".as_slice())]),
    )
    .unwrap();
    let output = Command::cargo_bin("carrick")
        .unwrap()
        .args([
            "run-elf",
            "fixtures/linux-aarch64-hello/target/aarch64-unknown-linux-musl/release/carrick-linux-aarch64-symlinkat-motd",
            "--rootfs-layer",
            layer.path().to_str().unwrap(),
            "--max-traps",
            "16",
        ])
        .output()
        .unwrap();

    if output.status.success() {
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(stdout.contains("\"exit_code\": 0"));
        assert!(stdout.contains("symlinkat\\n"));
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            stderr.contains("Hypervisor.framework"),
            "unexpected run-elf failure:\n{stderr}"
        );
    }
}

#[test]
fn run_elf_command_drives_truncate_static_fixture() {
    let output = std::process::Command::new("scripts/build-linux-fixtures.sh")
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "fixture build failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let layer = tempfile::NamedTempFile::new().unwrap();
    std::fs::write(
        layer.path(),
        gzip_tar([("etc/motd", b"truncate fixture\n".as_slice())]),
    )
    .unwrap();
    let output = Command::cargo_bin("carrick")
        .unwrap()
        .args([
            "run-elf",
            "fixtures/linux-aarch64-hello/target/aarch64-unknown-linux-musl/release/carrick-linux-aarch64-truncate-motd",
            "--rootfs-layer",
            layer.path().to_str().unwrap(),
            "--max-traps",
            "16",
        ])
        .output()
        .unwrap();

    if output.status.success() {
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(stdout.contains("\"exit_code\": 0"));
        assert!(stdout.contains("truncate\\n"));
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            stderr.contains("Hypervisor.framework"),
            "unexpected run-elf failure:\n{stderr}"
        );
    }
}

#[test]
fn run_elf_command_drives_fchown_static_fixture() {
    let output = std::process::Command::new("scripts/build-linux-fixtures.sh")
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "fixture build failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let layer = tempfile::NamedTempFile::new().unwrap();
    std::fs::write(
        layer.path(),
        gzip_tar([("etc/motd", b"fchown fixture\n".as_slice())]),
    )
    .unwrap();
    let output = Command::cargo_bin("carrick")
        .unwrap()
        .args([
            "run-elf",
            "fixtures/linux-aarch64-hello/target/aarch64-unknown-linux-musl/release/carrick-linux-aarch64-fchown-motd",
            "--rootfs-layer",
            layer.path().to_str().unwrap(),
            "--max-traps",
            "16",
        ])
        .output()
        .unwrap();

    if output.status.success() {
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(stdout.contains("\"exit_code\": 0"));
        assert!(stdout.contains("fchown\\n"));
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            stderr.contains("Hypervisor.framework"),
            "unexpected run-elf failure:\n{stderr}"
        );
    }
}

#[test]
fn run_elf_command_drives_fchmod_static_fixture() {
    let output = std::process::Command::new("scripts/build-linux-fixtures.sh")
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "fixture build failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let layer = tempfile::NamedTempFile::new().unwrap();
    std::fs::write(
        layer.path(),
        gzip_tar([("etc/motd", b"fchmod fixture\n".as_slice())]),
    )
    .unwrap();
    let output = Command::cargo_bin("carrick")
        .unwrap()
        .args([
            "run-elf",
            "fixtures/linux-aarch64-hello/target/aarch64-unknown-linux-musl/release/carrick-linux-aarch64-fchmod-motd",
            "--rootfs-layer",
            layer.path().to_str().unwrap(),
            "--max-traps",
            "16",
        ])
        .output()
        .unwrap();

    if output.status.success() {
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(stdout.contains("\"exit_code\": 0"));
        assert!(stdout.contains("fchmod\\n"));
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            stderr.contains("Hypervisor.framework"),
            "unexpected run-elf failure:\n{stderr}"
        );
    }
}

#[test]
fn run_elf_command_drives_renameat_static_fixture() {
    let output = std::process::Command::new("scripts/build-linux-fixtures.sh")
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "fixture build failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let layer = tempfile::NamedTempFile::new().unwrap();
    std::fs::write(
        layer.path(),
        gzip_tar([("etc/motd", b"renameat fixture\n".as_slice())]),
    )
    .unwrap();
    let output = Command::cargo_bin("carrick")
        .unwrap()
        .args([
            "run-elf",
            "fixtures/linux-aarch64-hello/target/aarch64-unknown-linux-musl/release/carrick-linux-aarch64-renameat-motd",
            "--rootfs-layer",
            layer.path().to_str().unwrap(),
            "--max-traps",
            "16",
        ])
        .output()
        .unwrap();

    if output.status.success() {
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(stdout.contains("\"exit_code\": 0"));
        assert!(stdout.contains("renameat\\n"));
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            stderr.contains("Hypervisor.framework"),
            "unexpected run-elf failure:\n{stderr}"
        );
    }
}

#[test]
fn run_elf_command_drives_unlinkat_static_fixture() {
    let output = std::process::Command::new("scripts/build-linux-fixtures.sh")
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "fixture build failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let layer = tempfile::NamedTempFile::new().unwrap();
    std::fs::write(
        layer.path(),
        gzip_tar([
            ("etc/motd", b"unlinkat fixture\n".as_slice()),
            ("etc/conf.d/.gitkeep", b"".as_slice()),
        ]),
    )
    .unwrap();
    let output = Command::cargo_bin("carrick")
        .unwrap()
        .args([
            "run-elf",
            "fixtures/linux-aarch64-hello/target/aarch64-unknown-linux-musl/release/carrick-linux-aarch64-unlinkat-motd",
            "--rootfs-layer",
            layer.path().to_str().unwrap(),
            "--max-traps",
            "32",
        ])
        .output()
        .unwrap();

    if output.status.success() {
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(stdout.contains("\"exit_code\": 0"));
        assert!(stdout.contains("unlinkat\\n"));
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            stderr.contains("Hypervisor.framework"),
            "unexpected run-elf failure:\n{stderr}"
        );
    }
}

#[test]
fn run_elf_command_drives_mkdirat_static_fixture() {
    let output = std::process::Command::new("scripts/build-linux-fixtures.sh")
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "fixture build failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let layer = tempfile::NamedTempFile::new().unwrap();
    std::fs::write(
        layer.path(),
        gzip_tar([("etc/motd", b"mkdirat fixture\n".as_slice())]),
    )
    .unwrap();
    let output = Command::cargo_bin("carrick")
        .unwrap()
        .args([
            "run-elf",
            "fixtures/linux-aarch64-hello/target/aarch64-unknown-linux-musl/release/carrick-linux-aarch64-mkdirat-motd",
            "--rootfs-layer",
            layer.path().to_str().unwrap(),
            "--max-traps",
            "16",
        ])
        .output()
        .unwrap();

    if output.status.success() {
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(stdout.contains("\"exit_code\": 0"));
        assert!(stdout.contains("mkdirat\\n"));
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            stderr.contains("Hypervisor.framework"),
            "unexpected run-elf failure:\n{stderr}"
        );
    }
}

#[test]
fn run_elf_command_drives_utimensat_static_fixture() {
    let output = std::process::Command::new("scripts/build-linux-fixtures.sh")
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "fixture build failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let layer = tempfile::NamedTempFile::new().unwrap();
    std::fs::write(
        layer.path(),
        gzip_tar([("etc/motd", b"utimensat fixture\n".as_slice())]),
    )
    .unwrap();
    let output = Command::cargo_bin("carrick")
        .unwrap()
        .args([
            "run-elf",
            "fixtures/linux-aarch64-hello/target/aarch64-unknown-linux-musl/release/carrick-linux-aarch64-utimensat-motd",
            "--rootfs-layer",
            layer.path().to_str().unwrap(),
            "--max-traps",
            "32",
        ])
        .output()
        .unwrap();

    if output.status.success() {
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(stdout.contains("\"exit_code\": 0"));
        assert!(stdout.contains("utimensat\\n"));
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            stderr.contains("Hypervisor.framework"),
            "unexpected run-elf failure:\n{stderr}"
        );
    }
}

#[test]
fn run_elf_command_drives_ftruncate_static_fixture() {
    let output = std::process::Command::new("scripts/build-linux-fixtures.sh")
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "fixture build failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let layer = tempfile::NamedTempFile::new().unwrap();
    std::fs::write(
        layer.path(),
        gzip_tar([("etc/motd", b"ftruncate fixture\n".as_slice())]),
    )
    .unwrap();
    let output = Command::cargo_bin("carrick")
        .unwrap()
        .args([
            "run-elf",
            "fixtures/linux-aarch64-hello/target/aarch64-unknown-linux-musl/release/carrick-linux-aarch64-ftruncate-motd",
            "--rootfs-layer",
            layer.path().to_str().unwrap(),
            "--max-traps",
            "16",
        ])
        .output()
        .unwrap();

    if output.status.success() {
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(stdout.contains("\"exit_code\": 0"));
        assert!(stdout.contains("ftruncate\\n"));
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            stderr.contains("Hypervisor.framework"),
            "unexpected run-elf failure:\n{stderr}"
        );
    }
}

#[test]
fn run_elf_command_drives_pwritev_static_fixture() {
    let output = std::process::Command::new("scripts/build-linux-fixtures.sh")
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "fixture build failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let layer = tempfile::NamedTempFile::new().unwrap();
    std::fs::write(
        layer.path(),
        gzip_tar([("etc/motd", b"pwritev fixture\n".as_slice())]),
    )
    .unwrap();
    let output = Command::cargo_bin("carrick")
        .unwrap()
        .args([
            "run-elf",
            "fixtures/linux-aarch64-hello/target/aarch64-unknown-linux-musl/release/carrick-linux-aarch64-pwritev-motd",
            "--rootfs-layer",
            layer.path().to_str().unwrap(),
            "--max-traps",
            "16",
        ])
        .output()
        .unwrap();

    if output.status.success() {
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(stdout.contains("\"exit_code\": 0"));
        assert!(stdout.contains("pwritev\\n"));
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            stderr.contains("Hypervisor.framework"),
            "unexpected run-elf failure:\n{stderr}"
        );
    }
}

#[test]
fn run_elf_command_drives_pwrite64_static_fixture() {
    let output = std::process::Command::new("scripts/build-linux-fixtures.sh")
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "fixture build failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let layer = tempfile::NamedTempFile::new().unwrap();
    std::fs::write(
        layer.path(),
        gzip_tar([("etc/motd", b"pwrite fixture\n".as_slice())]),
    )
    .unwrap();
    let output = Command::cargo_bin("carrick")
        .unwrap()
        .args([
            "run-elf",
            "fixtures/linux-aarch64-hello/target/aarch64-unknown-linux-musl/release/carrick-linux-aarch64-pwrite64-motd",
            "--rootfs-layer",
            layer.path().to_str().unwrap(),
            "--max-traps",
            "16",
        ])
        .output()
        .unwrap();

    if output.status.success() {
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(stdout.contains("\"exit_code\": 0"));
        assert!(stdout.contains("pwrite\\n"));
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            stderr.contains("Hypervisor.framework"),
            "unexpected run-elf failure:\n{stderr}"
        );
    }
}

#[test]
fn run_elf_command_drives_sync_static_fixture() {
    let output = std::process::Command::new("scripts/build-linux-fixtures.sh")
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "fixture build failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let layer = tempfile::NamedTempFile::new().unwrap();
    std::fs::write(
        layer.path(),
        gzip_tar([("etc/motd", b"sync fixture\n".as_slice())]),
    )
    .unwrap();
    let output = Command::cargo_bin("carrick")
        .unwrap()
        .args([
            "run-elf",
            "fixtures/linux-aarch64-hello/target/aarch64-unknown-linux-musl/release/carrick-linux-aarch64-sync-motd",
            "--rootfs-layer",
            layer.path().to_str().unwrap(),
            "--max-traps",
            "16",
        ])
        .output()
        .unwrap();

    if output.status.success() {
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(stdout.contains("\"exit_code\": 0"));
        assert!(stdout.contains("sync\\n"));
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            stderr.contains("Hypervisor.framework"),
            "unexpected run-elf failure:\n{stderr}"
        );
    }
}

#[test]
fn run_elf_command_drives_madvise_static_fixture() {
    let output = std::process::Command::new("scripts/build-linux-fixtures.sh")
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "fixture build failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let output = Command::cargo_bin("carrick")
        .unwrap()
        .args([
            "run-elf",
            "fixtures/linux-aarch64-hello/target/aarch64-unknown-linux-musl/release/carrick-linux-aarch64-madvise",
            "--max-traps",
            "16",
        ])
        .output()
        .unwrap();

    if output.status.success() {
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(stdout.contains("\"exit_code\": 0"));
        assert!(stdout.contains("madvise\\n"));
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            stderr.contains("Hypervisor.framework"),
            "unexpected run-elf failure:\n{stderr}"
        );
    }
}

#[test]
fn run_elf_command_drives_mmap_v8_hint_static_fixture() {
    let output = std::process::Command::new("scripts/build-linux-fixtures.sh")
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "fixture build failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let output = Command::cargo_bin("carrick")
        .unwrap()
        .args([
            "run-elf",
            "fixtures/linux-aarch64-hello/target/aarch64-unknown-linux-musl/release/carrick-linux-aarch64-mmap-v8-hint",
            "--max-traps",
            "16",
        ])
        .output()
        .unwrap();

    if output.status.success() {
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(stdout.contains("\"exit_code\": 0"));
        assert!(stdout.contains("ok\\n"));
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            stderr.contains("Hypervisor.framework"),
            "unexpected run-elf failure:\n{stderr}"
        );
    }
}

#[test]
fn run_elf_command_drives_statx_static_fixture() {
    let output = std::process::Command::new("scripts/build-linux-fixtures.sh")
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "fixture build failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let layer = tempfile::NamedTempFile::new().unwrap();
    std::fs::write(
        layer.path(),
        gzip_tar([("etc/motd", b"statx fixture\n".as_slice())]),
    )
    .unwrap();
    let output = Command::cargo_bin("carrick")
        .unwrap()
        .args([
            "run-elf",
            "fixtures/linux-aarch64-hello/target/aarch64-unknown-linux-musl/release/carrick-linux-aarch64-statx-motd",
            "--rootfs-layer",
            layer.path().to_str().unwrap(),
            "--max-traps",
            "16",
        ])
        .output()
        .unwrap();

    if output.status.success() {
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(stdout.contains("\"exit_code\": 0"));
        assert!(stdout.contains("statx\\n"));
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            stderr.contains("Hypervisor.framework"),
            "unexpected run-elf failure:\n{stderr}"
        );
    }
}

#[test]
fn run_elf_command_drives_openat2_static_fixture() {
    let output = std::process::Command::new("scripts/build-linux-fixtures.sh")
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "fixture build failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let layer = tempfile::NamedTempFile::new().unwrap();
    std::fs::write(
        layer.path(),
        gzip_tar([("etc/motd", b"openat2 fixture\n".as_slice())]),
    )
    .unwrap();
    let output = Command::cargo_bin("carrick")
        .unwrap()
        .args([
            "run-elf",
            "fixtures/linux-aarch64-hello/target/aarch64-unknown-linux-musl/release/carrick-linux-aarch64-openat2-motd",
            "--rootfs-layer",
            layer.path().to_str().unwrap(),
            "--max-traps",
            "16",
        ])
        .output()
        .unwrap();

    if output.status.success() {
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(stdout.contains("\"exit_code\": 0"));
        assert!(stdout.contains("openat2 fixture\\n"));
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            stderr.contains("Hypervisor.framework"),
            "unexpected run-elf failure:\n{stderr}"
        );
    }
}

#[test]
fn run_elf_command_drives_faccessat2_static_fixture() {
    let output = std::process::Command::new("scripts/build-linux-fixtures.sh")
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "fixture build failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let layer = tempfile::NamedTempFile::new().unwrap();
    std::fs::write(
        layer.path(),
        gzip_tar([("etc/motd", b"faccessat2 fixture\n".as_slice())]),
    )
    .unwrap();
    let output = Command::cargo_bin("carrick")
        .unwrap()
        .args([
            "run-elf",
            "fixtures/linux-aarch64-hello/target/aarch64-unknown-linux-musl/release/carrick-linux-aarch64-faccessat2-motd",
            "--rootfs-layer",
            layer.path().to_str().unwrap(),
            "--max-traps",
            "16",
        ])
        .output()
        .unwrap();

    if output.status.success() {
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(stdout.contains("\"exit_code\": 0"));
        assert!(stdout.contains("faccessat2\\n"));
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            stderr.contains("Hypervisor.framework"),
            "unexpected run-elf failure:\n{stderr}"
        );
    }
}

#[test]
fn run_command_loads_static_elf_from_pulled_image_rootfs() {
    let output = std::process::Command::new("scripts/build-linux-fixtures.sh")
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "fixture build failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let dir = tempfile::tempdir().unwrap();
    let store = ImageStore::new(dir.path());
    let image = ImageReference::parse("registry.example.com/team/app:v1").unwrap();
    let executable = std::fs::read(
        "fixtures/linux-aarch64-hello/target/aarch64-unknown-linux-musl/release/carrick-linux-aarch64-cat-motd",
    )
    .unwrap();
    let layer_bytes = gzip_tar([
        ("bin/cat-motd", executable.as_slice()),
        ("etc/motd", b"rootfs says hello\n".as_slice()),
    ]);
    let layer_path = store.blob_path("sha256:abcdef").unwrap();
    std::fs::create_dir_all(layer_path.parent().unwrap()).unwrap();
    std::fs::write(&layer_path, &layer_bytes).unwrap();

    let summary = PullSummary {
        image: image.canonical(),
        digest: Some("sha256:manifest".to_owned()),
        image_dir: store.image_dir(&image),
        config_size: 0,
        layers: vec![LayerSummary {
            digest: "sha256:abcdef".to_owned(),
            media_type: "application/vnd.oci.image.layer.v1.tar+gzip".to_owned(),
            size: layer_bytes.len(),
            path: layer_path,
        }],
    };
    std::fs::create_dir_all(store.image_dir(&image)).unwrap();
    std::fs::write(
        store.image_summary_path(&image),
        serde_json::to_vec_pretty(&summary).unwrap(),
    )
    .unwrap();

    let output = Command::cargo_bin("carrick")
        .unwrap()
        .args([
            "--store",
            store.root().to_str().unwrap(),
            "run",
            // --pid host: this test exercises image→ELF loading, not pid
            // namespaces. The default (--pid private) forks an NsSupervisor, and
            // on the unsigned `cargo test` binary HVF init fails *inside* the
            // forked guest-init, whose post-fork error unwind trips a pre-existing
            // fd double-close abort instead of the clean "Hypervisor.framework"
            // error this test's HVF-unavailable branch expects. --pid host runs
            // without the fork, so the error surfaces cleanly.
            "--pid",
            "host",
            image.canonical().as_str(),
            "/bin/cat-motd",
        ])
        .output()
        .unwrap();

    if output.status.success() {
        let stdout = String::from_utf8_lossy(&output.stdout);
        // Default `run` is now docker-shaped: streamed stdout, no JSON envelope.
        assert!(
            !stdout.contains("\"exit_code\""),
            "default run must not emit the JSON envelope:\n{stdout}"
        );
        assert!(stdout.contains("rootfs says hello"));
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            stderr.contains("Hypervisor.framework"),
            "unexpected run failure:\n{stderr}"
        );
    }
}

#[test]
fn run_command_passes_guest_argv_stack_to_image_executable() {
    let output = std::process::Command::new("scripts/build-linux-fixtures.sh")
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "fixture build failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let dir = tempfile::tempdir().unwrap();
    let store = ImageStore::new(dir.path());
    let image = ImageReference::parse("registry.example.com/team/argv:v1").unwrap();
    let executable = std::fs::read(
        "fixtures/linux-aarch64-hello/target/aarch64-unknown-linux-musl/release/carrick-linux-aarch64-argv-echo",
    )
    .unwrap();
    let layer_bytes = gzip_tar([("bin/argv-echo", executable.as_slice())]);
    let layer_path = store.blob_path("sha256:1234").unwrap();
    std::fs::create_dir_all(layer_path.parent().unwrap()).unwrap();
    std::fs::write(&layer_path, &layer_bytes).unwrap();

    let summary = PullSummary {
        image: image.canonical(),
        digest: Some("sha256:manifest".to_owned()),
        image_dir: store.image_dir(&image),
        config_size: 0,
        layers: vec![LayerSummary {
            digest: "sha256:1234".to_owned(),
            media_type: "application/vnd.oci.image.layer.v1.tar+gzip".to_owned(),
            size: layer_bytes.len(),
            path: layer_path,
        }],
    };
    std::fs::create_dir_all(store.image_dir(&image)).unwrap();
    std::fs::write(
        store.image_summary_path(&image),
        serde_json::to_vec_pretty(&summary).unwrap(),
    )
    .unwrap();

    let output = Command::cargo_bin("carrick")
        .unwrap()
        .args([
            "--store",
            store.root().to_str().unwrap(),
            "run",
            // --pid host: see run_command_loads_static_elf_from_pulled_image_rootfs
            // — avoids the forked guest-init's HVF-init abort on the unsigned
            // test binary so the HVF-unavailable error surfaces cleanly.
            "--pid",
            "host",
            image.canonical().as_str(),
            "/bin/argv-echo",
            "from-image-argv",
        ])
        .output()
        .unwrap();

    if output.status.success() {
        let stdout = String::from_utf8_lossy(&output.stdout);
        // Default `run` is now docker-shaped: streamed stdout (a real newline,
        // not the JSON-escaped envelope), and no envelope keys.
        assert!(
            !stdout.contains("\"exit_code\""),
            "default run must not emit the JSON envelope:\n{stdout}"
        );
        assert!(stdout.contains("from-image-argv"));
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            stderr.contains("Hypervisor.framework"),
            "unexpected run failure:\n{stderr}"
        );
    }
}

#[test]
fn run_elf_command_drives_pie_hello_static_fixture() {
    let output = std::process::Command::new("scripts/build-linux-fixtures.sh")
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "fixture build failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let output = Command::cargo_bin("carrick")
        .unwrap()
        .args([
            "run-elf",
            "fixtures/linux-aarch64-hello/target/aarch64-unknown-linux-musl/release/carrick-linux-aarch64-pie-hello",
            "--max-traps",
            "8",
        ])
        .output()
        .unwrap();

    if output.status.success() {
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(stdout.contains("\"exit_code\": 0"));
        assert!(stdout.contains("hello from carrick pie"));
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            stderr.contains("Hypervisor.framework"),
            "unexpected run-elf failure for static-PIE fixture:\n{stderr}"
        );
    }
}

#[test]
fn run_accepts_tty_flag() {
    let out = std::process::Command::new(env!("CARGO_BIN_EXE_carrick"))
        .args(["run", "--help"])
        .output()
        .unwrap();
    let help = String::from_utf8_lossy(&out.stdout);
    assert!(
        help.contains("--tty"),
        "run --help should mention --tty:\n{help}"
    );
}

#[test]
fn logs_replays_captured_output_for_a_container() {
    // The registry root prefers the shared /Volumes/carrick volume when it
    // exists; only when it's absent does CARRICK_HOME redirect it. Self-skip on
    // a host with the shared volume so we never pollute (or depend on) it.
    if std::path::Path::new("/Volumes/carrick").is_dir() {
        eprintln!("SKIP logs_replays: shared /Volumes/carrick volume present");
        return;
    }
    let home = tempfile::tempdir().unwrap();
    // registry_root == <CARRICK_HOME>/scratch/containers/<id>/
    let id = "a".repeat(64);
    let cdir = home.path().join("scratch/containers").join(&id);
    std::fs::create_dir_all(&cdir).unwrap();
    let state = serde_json::json!({
        "id": id, "name": serde_json::Value::Null, "image": "img", "command": [],
        "status": "exited", "supervisor_pid": 0, "init_pid": 0,
        "created_secs": 0, "exit_code": 0, "auto_remove": false,
    });
    std::fs::write(cdir.join("state.json"), serde_json::to_vec(&state).unwrap()).unwrap();
    std::fs::write(cdir.join("output.log"), b"hello from logs\nsecond line\n").unwrap();

    // Full replay.
    Command::cargo_bin("carrick")
        .unwrap()
        .env("CARRICK_HOME", home.path())
        .args(["logs", &id])
        .assert()
        .success()
        .stdout(contains("hello from logs"))
        .stdout(contains("second line"));

    // `--tail 1` shows only the last line.
    Command::cargo_bin("carrick")
        .unwrap()
        .env("CARRICK_HOME", home.path())
        .args(["logs", "--tail", "1", &id])
        .assert()
        .success()
        .stdout(contains("second line"))
        .stdout(contains("hello from logs").not());
}

#[test]
fn logs_unknown_container_errors() {
    // A random id matches nothing in any registry → docker-style "no such
    // container". Hermetic regardless of registry location.
    Command::cargo_bin("carrick")
        .unwrap()
        .args(["logs", "definitely-not-a-real-container-id"])
        .assert()
        .failure()
        .stderr(contains("no such container"));
}

fn minimal_aarch64_elf() -> Vec<u8> {
    let mut elf = vec![0_u8; 64];
    elf[0..4].copy_from_slice(b"\x7fELF");
    elf[4] = 2;
    elf[5] = 1;
    elf[6] = 1;
    elf[16..18].copy_from_slice(&2_u16.to_le_bytes());
    elf[18..20].copy_from_slice(&183_u16.to_le_bytes());
    elf[20..24].copy_from_slice(&1_u32.to_le_bytes());
    elf[24..32].copy_from_slice(&0x400000_u64.to_le_bytes());
    elf[52..54].copy_from_slice(&64_u16.to_le_bytes());
    elf[54..56].copy_from_slice(&56_u16.to_le_bytes());
    elf
}

fn minimal_aarch64_elf_with_load_segment() -> Vec<u8> {
    let mut elf = vec![0_u8; 0x1004];
    elf[0..64].copy_from_slice(&minimal_aarch64_elf());
    elf[32..40].copy_from_slice(&64_u64.to_le_bytes());
    elf[56..58].copy_from_slice(&1_u16.to_le_bytes());

    let ph = 64;
    elf[ph..ph + 4].copy_from_slice(&1_u32.to_le_bytes());
    elf[ph + 4..ph + 8].copy_from_slice(&5_u32.to_le_bytes());
    elf[ph + 8..ph + 16].copy_from_slice(&0x1000_u64.to_le_bytes());
    elf[ph + 16..ph + 24].copy_from_slice(&0x400000_u64.to_le_bytes());
    elf[ph + 32..ph + 40].copy_from_slice(&4_u64.to_le_bytes());
    elf[ph + 40..ph + 48].copy_from_slice(&0x1000_u64.to_le_bytes());
    elf[ph + 48..ph + 56].copy_from_slice(&0x1000_u64.to_le_bytes());
    elf[0x1000..0x1004].copy_from_slice(b"\x1f\x20\x03\xd5");
    elf
}
