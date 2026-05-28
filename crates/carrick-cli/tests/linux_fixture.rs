use carrick_runtime::elf::{ElfType, LINUX_PIE_DEFAULT_BASE, Machine, inspect_elf, plan_elf_load};
use std::sync::Mutex;

static LINUX_FIXTURE_LOCK: Mutex<()> = Mutex::new(());

#[test]
fn builds_static_linux_aarch64_hello_fixture() {
    let _serial = LINUX_FIXTURE_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let output = std::process::Command::new("scripts/build-linux-fixtures.sh")
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "fixture build failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    const STATIC_FIXTURES: &[&str] = &[
        "fixtures/linux-aarch64-hello/target/aarch64-unknown-linux-musl/release/carrick-linux-aarch64-hello",
        "fixtures/linux-aarch64-hello/target/aarch64-unknown-linux-musl/release/carrick-linux-aarch64-cat-motd",
        "fixtures/linux-aarch64-hello/target/aarch64-unknown-linux-musl/release/carrick-linux-aarch64-argv-echo",
        "fixtures/linux-aarch64-hello/target/aarch64-unknown-linux-musl/release/carrick-linux-aarch64-timerfd-epoll",
        "fixtures/linux-aarch64-hello/target/aarch64-unknown-linux-musl/release/carrick-linux-aarch64-ppoll-eventfd",
        "fixtures/linux-aarch64-hello/target/aarch64-unknown-linux-musl/release/carrick-linux-aarch64-pselect-eventfd",
        "fixtures/linux-aarch64-hello/target/aarch64-unknown-linux-musl/release/carrick-linux-aarch64-process-bootstrap",
        "fixtures/linux-aarch64-hello/target/aarch64-unknown-linux-musl/release/carrick-linux-aarch64-futex",
        "fixtures/linux-aarch64-hello/target/aarch64-unknown-linux-musl/release/carrick-linux-aarch64-rseq",
        "fixtures/linux-aarch64-hello/target/aarch64-unknown-linux-musl/release/carrick-linux-aarch64-membarrier",
        "fixtures/linux-aarch64-hello/target/aarch64-unknown-linux-musl/release/carrick-linux-aarch64-scheduler",
        "fixtures/linux-aarch64-hello/target/aarch64-unknown-linux-musl/release/carrick-linux-aarch64-prctl",
        "fixtures/linux-aarch64-hello/target/aarch64-unknown-linux-musl/release/carrick-linux-aarch64-getcpu",
        "fixtures/linux-aarch64-hello/target/aarch64-unknown-linux-musl/release/carrick-linux-aarch64-flock-motd",
        "fixtures/linux-aarch64-hello/target/aarch64-unknown-linux-musl/release/carrick-linux-aarch64-nanosleep",
        "fixtures/linux-aarch64-hello/target/aarch64-unknown-linux-musl/release/carrick-linux-aarch64-clock-nanosleep",
        "fixtures/linux-aarch64-hello/target/aarch64-unknown-linux-musl/release/carrick-linux-aarch64-madvise",
        "fixtures/linux-aarch64-hello/target/aarch64-unknown-linux-musl/release/carrick-linux-aarch64-statx-motd",
        "fixtures/linux-aarch64-hello/target/aarch64-unknown-linux-musl/release/carrick-linux-aarch64-openat2-motd",
        "fixtures/linux-aarch64-hello/target/aarch64-unknown-linux-musl/release/carrick-linux-aarch64-faccessat2-motd",
        "fixtures/linux-aarch64-hello/target/aarch64-unknown-linux-musl/release/carrick-linux-aarch64-sendfile-motd",
        "fixtures/linux-aarch64-hello/target/aarch64-unknown-linux-musl/release/carrick-linux-aarch64-preadv-motd",
        "fixtures/linux-aarch64-hello/target/aarch64-unknown-linux-musl/release/carrick-linux-aarch64-splice-motd",
        "fixtures/linux-aarch64-hello/target/aarch64-unknown-linux-musl/release/carrick-linux-aarch64-sync-motd",
        "fixtures/linux-aarch64-hello/target/aarch64-unknown-linux-musl/release/carrick-linux-aarch64-pwrite64-motd",
        "fixtures/linux-aarch64-hello/target/aarch64-unknown-linux-musl/release/carrick-linux-aarch64-pwritev-motd",
        "fixtures/linux-aarch64-hello/target/aarch64-unknown-linux-musl/release/carrick-linux-aarch64-ftruncate-motd",
        "fixtures/linux-aarch64-hello/target/aarch64-unknown-linux-musl/release/carrick-linux-aarch64-utimensat-motd",
        "fixtures/linux-aarch64-hello/target/aarch64-unknown-linux-musl/release/carrick-linux-aarch64-mkdirat-motd",
        "fixtures/linux-aarch64-hello/target/aarch64-unknown-linux-musl/release/carrick-linux-aarch64-unlinkat-motd",
        "fixtures/linux-aarch64-hello/target/aarch64-unknown-linux-musl/release/carrick-linux-aarch64-renameat-motd",
        "fixtures/linux-aarch64-hello/target/aarch64-unknown-linux-musl/release/carrick-linux-aarch64-fchmod-motd",
        "fixtures/linux-aarch64-hello/target/aarch64-unknown-linux-musl/release/carrick-linux-aarch64-fchown-motd",
        "fixtures/linux-aarch64-hello/target/aarch64-unknown-linux-musl/release/carrick-linux-aarch64-truncate-motd",
        "fixtures/linux-aarch64-hello/target/aarch64-unknown-linux-musl/release/carrick-linux-aarch64-symlinkat-motd",
        "fixtures/linux-aarch64-hello/target/aarch64-unknown-linux-musl/release/carrick-linux-aarch64-linkat-motd",
        "fixtures/linux-aarch64-hello/target/aarch64-unknown-linux-musl/release/carrick-linux-aarch64-errno-matrix",
    ];

    for artifact in STATIC_FIXTURES {
        let metadata = inspect_elf(artifact).unwrap();
        assert_eq!(metadata.machine, Machine::Aarch64, "{artifact}");

        let plan = plan_elf_load(artifact).unwrap();
        assert!(!plan.segments.is_empty(), "{artifact}");
        assert!(
            plan.segments.iter().any(|segment| {
                segment.perms.execute
                    && plan.entry >= segment.virtual_address
                    && plan.entry < segment.virtual_address + segment.memory_size
            }),
            "{artifact}"
        );
    }

    // Existing ET_EXEC fixtures must keep load_bias == 0 and not be rebased.
    let hello_artifact = STATIC_FIXTURES[0];
    let plan = plan_elf_load(hello_artifact).unwrap();
    assert_eq!(plan.e_type, ElfType::Exec);
    assert_eq!(plan.load_bias, 0);

    let pie_artifact = "fixtures/linux-aarch64-hello/target/aarch64-unknown-linux-musl/release/carrick-linux-aarch64-pie-hello";
    let metadata = inspect_elf(pie_artifact).unwrap();
    assert_eq!(metadata.machine, Machine::Aarch64);
    assert_eq!(metadata.e_type, ElfType::Dyn);
    assert!(
        metadata.interpreter.is_none(),
        "static-PIE fixture must not carry a PT_INTERP"
    );

    let plan = plan_elf_load(pie_artifact).unwrap();
    assert_eq!(plan.e_type, ElfType::Dyn);
    assert_eq!(plan.load_bias, LINUX_PIE_DEFAULT_BASE);
    assert!(!plan.segments.is_empty());
    assert!(
        plan.segments
            .iter()
            .all(|segment| segment.virtual_address >= LINUX_PIE_DEFAULT_BASE),
        "every PIE segment vaddr must live above the load bias"
    );
    assert!(
        plan.entry >= LINUX_PIE_DEFAULT_BASE,
        "PIE entry point must be rebased above the load bias"
    );
    assert!(plan.segments.iter().any(|segment| {
        segment.perms.execute
            && plan.entry >= segment.virtual_address
            && plan.entry < segment.virtual_address + segment.memory_size
    }));
}

#[test]
fn builds_static_linux_aarch64_go_hello_fixture() {
    let _serial = LINUX_FIXTURE_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let output = std::process::Command::new("scripts/build-go-fixtures.sh")
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "Go fixture build failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let go_artifact = "fixtures/go-aarch64-hello/target/release/carrick-linux-aarch64-go-hello";
    let metadata = inspect_elf(go_artifact).unwrap();
    assert_eq!(metadata.machine, Machine::Aarch64);
    assert_eq!(metadata.e_type, ElfType::Dyn);

    let plan = plan_elf_load(go_artifact).unwrap();
    assert!(!plan.segments.is_empty());
}

#[test]
fn run_static_go_hello_under_carrick() {
    let _serial = LINUX_FIXTURE_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let output = std::process::Command::new("scripts/build-go-fixtures.sh")
        .output()
        .unwrap();
    assert!(output.status.success(), "Go fixture build failed");

    let go_artifact = "fixtures/go-aarch64-hello/target/release/carrick-linux-aarch64-go-hello";

    let output = assert_cmd::Command::cargo_bin("carrick")
        .unwrap()
        .args(["run-elf", go_artifact])
        .output()
        .unwrap();

    if output.status.success() {
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(
            stdout.contains("\"exit_code\": 0")
                || stdout.contains("Graceful shutdown completed successfully"),
            "unexpected run-elf success output: {}",
            stdout
        );
        assert!(
            stdout.contains("Client received status: success"),
            "expected client status: {}",
            stdout
        );
        assert!(
            stdout.contains("Client received runtime: carrick"),
            "expected client runtime: {}",
            stdout
        );
        assert!(
            stdout.contains("Client received concurrency: enabled"),
            "expected client concurrency: {}",
            stdout
        );
        assert!(
            stdout.contains("Graceful shutdown completed successfully"),
            "expected graceful shutdown: {}",
            stdout
        );
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            stderr.contains("Hypervisor.framework"),
            "unexpected run-elf failure:\n{stderr}"
        );
    }
}
