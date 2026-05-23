use carrick::elf::{ElfType, LINUX_PIE_DEFAULT_BASE, Machine, inspect_elf, plan_elf_load};

#[test]
fn builds_static_linux_aarch64_hello_fixture() {
    let output = std::process::Command::new("scripts/build-linux-fixtures.sh")
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "fixture build failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let hello_artifact = "fixtures/linux-aarch64-hello/target/aarch64-unknown-linux-musl/release/carrick-linux-aarch64-hello";
    let cat_artifact = "fixtures/linux-aarch64-hello/target/aarch64-unknown-linux-musl/release/carrick-linux-aarch64-cat-motd";
    let argv_artifact = "fixtures/linux-aarch64-hello/target/aarch64-unknown-linux-musl/release/carrick-linux-aarch64-argv-echo";
    let timerfd_artifact = "fixtures/linux-aarch64-hello/target/aarch64-unknown-linux-musl/release/carrick-linux-aarch64-timerfd-epoll";
    let ppoll_artifact = "fixtures/linux-aarch64-hello/target/aarch64-unknown-linux-musl/release/carrick-linux-aarch64-ppoll-eventfd";
    let pselect_artifact = "fixtures/linux-aarch64-hello/target/aarch64-unknown-linux-musl/release/carrick-linux-aarch64-pselect-eventfd";
    let process_artifact = "fixtures/linux-aarch64-hello/target/aarch64-unknown-linux-musl/release/carrick-linux-aarch64-process-bootstrap";
    let futex_artifact = "fixtures/linux-aarch64-hello/target/aarch64-unknown-linux-musl/release/carrick-linux-aarch64-futex";
    let rseq_artifact = "fixtures/linux-aarch64-hello/target/aarch64-unknown-linux-musl/release/carrick-linux-aarch64-rseq";
    let membarrier_artifact = "fixtures/linux-aarch64-hello/target/aarch64-unknown-linux-musl/release/carrick-linux-aarch64-membarrier";
    let scheduler_artifact = "fixtures/linux-aarch64-hello/target/aarch64-unknown-linux-musl/release/carrick-linux-aarch64-scheduler";
    let prctl_artifact = "fixtures/linux-aarch64-hello/target/aarch64-unknown-linux-musl/release/carrick-linux-aarch64-prctl";
    let getcpu_artifact = "fixtures/linux-aarch64-hello/target/aarch64-unknown-linux-musl/release/carrick-linux-aarch64-getcpu";
    let flock_artifact = "fixtures/linux-aarch64-hello/target/aarch64-unknown-linux-musl/release/carrick-linux-aarch64-flock-motd";
    let nanosleep_artifact = "fixtures/linux-aarch64-hello/target/aarch64-unknown-linux-musl/release/carrick-linux-aarch64-nanosleep";
    let clock_nanosleep_artifact = "fixtures/linux-aarch64-hello/target/aarch64-unknown-linux-musl/release/carrick-linux-aarch64-clock-nanosleep";
    let madvise_artifact = "fixtures/linux-aarch64-hello/target/aarch64-unknown-linux-musl/release/carrick-linux-aarch64-madvise";
    let statx_artifact = "fixtures/linux-aarch64-hello/target/aarch64-unknown-linux-musl/release/carrick-linux-aarch64-statx-motd";
    let openat2_artifact = "fixtures/linux-aarch64-hello/target/aarch64-unknown-linux-musl/release/carrick-linux-aarch64-openat2-motd";
    let faccessat2_artifact = "fixtures/linux-aarch64-hello/target/aarch64-unknown-linux-musl/release/carrick-linux-aarch64-faccessat2-motd";
    let sendfile_artifact = "fixtures/linux-aarch64-hello/target/aarch64-unknown-linux-musl/release/carrick-linux-aarch64-sendfile-motd";
    let preadv_artifact = "fixtures/linux-aarch64-hello/target/aarch64-unknown-linux-musl/release/carrick-linux-aarch64-preadv-motd";
    let splice_artifact = "fixtures/linux-aarch64-hello/target/aarch64-unknown-linux-musl/release/carrick-linux-aarch64-splice-motd";
    let sync_artifact = "fixtures/linux-aarch64-hello/target/aarch64-unknown-linux-musl/release/carrick-linux-aarch64-sync-motd";
    let pwrite64_artifact = "fixtures/linux-aarch64-hello/target/aarch64-unknown-linux-musl/release/carrick-linux-aarch64-pwrite64-motd";
    let pwritev_artifact = "fixtures/linux-aarch64-hello/target/aarch64-unknown-linux-musl/release/carrick-linux-aarch64-pwritev-motd";
    let ftruncate_artifact = "fixtures/linux-aarch64-hello/target/aarch64-unknown-linux-musl/release/carrick-linux-aarch64-ftruncate-motd";
    let utimensat_artifact = "fixtures/linux-aarch64-hello/target/aarch64-unknown-linux-musl/release/carrick-linux-aarch64-utimensat-motd";
    let mkdirat_artifact = "fixtures/linux-aarch64-hello/target/aarch64-unknown-linux-musl/release/carrick-linux-aarch64-mkdirat-motd";
    let unlinkat_artifact = "fixtures/linux-aarch64-hello/target/aarch64-unknown-linux-musl/release/carrick-linux-aarch64-unlinkat-motd";
    let renameat_artifact = "fixtures/linux-aarch64-hello/target/aarch64-unknown-linux-musl/release/carrick-linux-aarch64-renameat-motd";
    let fchmod_artifact = "fixtures/linux-aarch64-hello/target/aarch64-unknown-linux-musl/release/carrick-linux-aarch64-fchmod-motd";
    let fchown_artifact = "fixtures/linux-aarch64-hello/target/aarch64-unknown-linux-musl/release/carrick-linux-aarch64-fchown-motd";
    let truncate_artifact = "fixtures/linux-aarch64-hello/target/aarch64-unknown-linux-musl/release/carrick-linux-aarch64-truncate-motd";
    let symlinkat_artifact = "fixtures/linux-aarch64-hello/target/aarch64-unknown-linux-musl/release/carrick-linux-aarch64-symlinkat-motd";
    let linkat_artifact = "fixtures/linux-aarch64-hello/target/aarch64-unknown-linux-musl/release/carrick-linux-aarch64-linkat-motd";
    let errno_matrix_artifact = "fixtures/linux-aarch64-hello/target/aarch64-unknown-linux-musl/release/carrick-linux-aarch64-errno-matrix";
    let metadata = inspect_elf(hello_artifact).unwrap();
    assert_eq!(metadata.machine, Machine::Aarch64);
    let metadata = inspect_elf(cat_artifact).unwrap();
    assert_eq!(metadata.machine, Machine::Aarch64);
    let metadata = inspect_elf(argv_artifact).unwrap();
    assert_eq!(metadata.machine, Machine::Aarch64);
    let metadata = inspect_elf(timerfd_artifact).unwrap();
    assert_eq!(metadata.machine, Machine::Aarch64);
    let metadata = inspect_elf(ppoll_artifact).unwrap();
    assert_eq!(metadata.machine, Machine::Aarch64);
    let metadata = inspect_elf(pselect_artifact).unwrap();
    assert_eq!(metadata.machine, Machine::Aarch64);
    let metadata = inspect_elf(process_artifact).unwrap();
    assert_eq!(metadata.machine, Machine::Aarch64);
    let metadata = inspect_elf(futex_artifact).unwrap();
    assert_eq!(metadata.machine, Machine::Aarch64);
    let metadata = inspect_elf(rseq_artifact).unwrap();
    assert_eq!(metadata.machine, Machine::Aarch64);
    let metadata = inspect_elf(membarrier_artifact).unwrap();
    assert_eq!(metadata.machine, Machine::Aarch64);
    let metadata = inspect_elf(scheduler_artifact).unwrap();
    assert_eq!(metadata.machine, Machine::Aarch64);
    let metadata = inspect_elf(prctl_artifact).unwrap();
    assert_eq!(metadata.machine, Machine::Aarch64);
    let metadata = inspect_elf(getcpu_artifact).unwrap();
    assert_eq!(metadata.machine, Machine::Aarch64);
    let metadata = inspect_elf(flock_artifact).unwrap();
    assert_eq!(metadata.machine, Machine::Aarch64);
    let metadata = inspect_elf(nanosleep_artifact).unwrap();
    assert_eq!(metadata.machine, Machine::Aarch64);
    let metadata = inspect_elf(clock_nanosleep_artifact).unwrap();
    assert_eq!(metadata.machine, Machine::Aarch64);
    let metadata = inspect_elf(madvise_artifact).unwrap();
    assert_eq!(metadata.machine, Machine::Aarch64);
    let metadata = inspect_elf(statx_artifact).unwrap();
    assert_eq!(metadata.machine, Machine::Aarch64);
    let metadata = inspect_elf(openat2_artifact).unwrap();
    assert_eq!(metadata.machine, Machine::Aarch64);
    let metadata = inspect_elf(faccessat2_artifact).unwrap();
    assert_eq!(metadata.machine, Machine::Aarch64);
    let metadata = inspect_elf(sendfile_artifact).unwrap();
    assert_eq!(metadata.machine, Machine::Aarch64);
    let metadata = inspect_elf(preadv_artifact).unwrap();
    assert_eq!(metadata.machine, Machine::Aarch64);
    let metadata = inspect_elf(splice_artifact).unwrap();
    assert_eq!(metadata.machine, Machine::Aarch64);
    let metadata = inspect_elf(sync_artifact).unwrap();
    assert_eq!(metadata.machine, Machine::Aarch64);
    let metadata = inspect_elf(pwrite64_artifact).unwrap();
    assert_eq!(metadata.machine, Machine::Aarch64);
    let metadata = inspect_elf(pwritev_artifact).unwrap();
    assert_eq!(metadata.machine, Machine::Aarch64);
    let metadata = inspect_elf(ftruncate_artifact).unwrap();
    assert_eq!(metadata.machine, Machine::Aarch64);
    let metadata = inspect_elf(utimensat_artifact).unwrap();
    assert_eq!(metadata.machine, Machine::Aarch64);
    let metadata = inspect_elf(mkdirat_artifact).unwrap();
    assert_eq!(metadata.machine, Machine::Aarch64);
    let metadata = inspect_elf(unlinkat_artifact).unwrap();
    assert_eq!(metadata.machine, Machine::Aarch64);
    let metadata = inspect_elf(renameat_artifact).unwrap();
    assert_eq!(metadata.machine, Machine::Aarch64);
    let metadata = inspect_elf(fchmod_artifact).unwrap();
    assert_eq!(metadata.machine, Machine::Aarch64);
    let metadata = inspect_elf(fchown_artifact).unwrap();
    assert_eq!(metadata.machine, Machine::Aarch64);
    let metadata = inspect_elf(truncate_artifact).unwrap();
    assert_eq!(metadata.machine, Machine::Aarch64);
    let metadata = inspect_elf(symlinkat_artifact).unwrap();
    assert_eq!(metadata.machine, Machine::Aarch64);
    let metadata = inspect_elf(linkat_artifact).unwrap();
    assert_eq!(metadata.machine, Machine::Aarch64);
    let metadata = inspect_elf(errno_matrix_artifact).unwrap();
    assert_eq!(metadata.machine, Machine::Aarch64);

    let plan = plan_elf_load(hello_artifact).unwrap();
    assert!(!plan.segments.is_empty());
    assert!(plan.segments.iter().any(|segment| {
        segment.perms.execute
            && plan.entry >= segment.virtual_address
            && plan.entry < segment.virtual_address + segment.memory_size
    }));

    let plan = plan_elf_load(cat_artifact).unwrap();
    assert!(!plan.segments.is_empty());
    assert!(plan.segments.iter().any(|segment| {
        segment.perms.execute
            && plan.entry >= segment.virtual_address
            && plan.entry < segment.virtual_address + segment.memory_size
    }));

    let plan = plan_elf_load(argv_artifact).unwrap();
    assert!(!plan.segments.is_empty());
    assert!(plan.segments.iter().any(|segment| {
        segment.perms.execute
            && plan.entry >= segment.virtual_address
            && plan.entry < segment.virtual_address + segment.memory_size
    }));

    let plan = plan_elf_load(timerfd_artifact).unwrap();
    assert!(!plan.segments.is_empty());
    assert!(plan.segments.iter().any(|segment| {
        segment.perms.execute
            && plan.entry >= segment.virtual_address
            && plan.entry < segment.virtual_address + segment.memory_size
    }));

    let plan = plan_elf_load(ppoll_artifact).unwrap();
    assert!(!plan.segments.is_empty());
    assert!(plan.segments.iter().any(|segment| {
        segment.perms.execute
            && plan.entry >= segment.virtual_address
            && plan.entry < segment.virtual_address + segment.memory_size
    }));

    let plan = plan_elf_load(pselect_artifact).unwrap();
    assert!(!plan.segments.is_empty());
    assert!(plan.segments.iter().any(|segment| {
        segment.perms.execute
            && plan.entry >= segment.virtual_address
            && plan.entry < segment.virtual_address + segment.memory_size
    }));

    let plan = plan_elf_load(process_artifact).unwrap();
    assert!(!plan.segments.is_empty());
    assert!(plan.segments.iter().any(|segment| {
        segment.perms.execute
            && plan.entry >= segment.virtual_address
            && plan.entry < segment.virtual_address + segment.memory_size
    }));

    let plan = plan_elf_load(futex_artifact).unwrap();
    assert!(!plan.segments.is_empty());
    assert!(plan.segments.iter().any(|segment| {
        segment.perms.execute
            && plan.entry >= segment.virtual_address
            && plan.entry < segment.virtual_address + segment.memory_size
    }));

    let plan = plan_elf_load(rseq_artifact).unwrap();
    assert!(!plan.segments.is_empty());
    assert!(plan.segments.iter().any(|segment| {
        segment.perms.execute
            && plan.entry >= segment.virtual_address
            && plan.entry < segment.virtual_address + segment.memory_size
    }));

    let plan = plan_elf_load(membarrier_artifact).unwrap();
    assert!(!plan.segments.is_empty());
    assert!(plan.segments.iter().any(|segment| {
        segment.perms.execute
            && plan.entry >= segment.virtual_address
            && plan.entry < segment.virtual_address + segment.memory_size
    }));

    let plan = plan_elf_load(scheduler_artifact).unwrap();
    assert!(!plan.segments.is_empty());
    assert!(plan.segments.iter().any(|segment| {
        segment.perms.execute
            && plan.entry >= segment.virtual_address
            && plan.entry < segment.virtual_address + segment.memory_size
    }));

    let plan = plan_elf_load(prctl_artifact).unwrap();
    assert!(!plan.segments.is_empty());
    assert!(plan.segments.iter().any(|segment| {
        segment.perms.execute
            && plan.entry >= segment.virtual_address
            && plan.entry < segment.virtual_address + segment.memory_size
    }));

    let plan = plan_elf_load(getcpu_artifact).unwrap();
    assert!(!plan.segments.is_empty());
    assert!(plan.segments.iter().any(|segment| {
        segment.perms.execute
            && plan.entry >= segment.virtual_address
            && plan.entry < segment.virtual_address + segment.memory_size
    }));

    let plan = plan_elf_load(flock_artifact).unwrap();
    assert!(!plan.segments.is_empty());
    assert!(plan.segments.iter().any(|segment| {
        segment.perms.execute
            && plan.entry >= segment.virtual_address
            && plan.entry < segment.virtual_address + segment.memory_size
    }));

    let plan = plan_elf_load(nanosleep_artifact).unwrap();
    assert!(!plan.segments.is_empty());
    assert!(plan.segments.iter().any(|segment| {
        segment.perms.execute
            && plan.entry >= segment.virtual_address
            && plan.entry < segment.virtual_address + segment.memory_size
    }));

    let plan = plan_elf_load(clock_nanosleep_artifact).unwrap();
    assert!(!plan.segments.is_empty());
    assert!(plan.segments.iter().any(|segment| {
        segment.perms.execute
            && plan.entry >= segment.virtual_address
            && plan.entry < segment.virtual_address + segment.memory_size
    }));

    let plan = plan_elf_load(madvise_artifact).unwrap();
    assert!(!plan.segments.is_empty());
    assert!(plan.segments.iter().any(|segment| {
        segment.perms.execute
            && plan.entry >= segment.virtual_address
            && plan.entry < segment.virtual_address + segment.memory_size
    }));

    let plan = plan_elf_load(statx_artifact).unwrap();
    assert!(!plan.segments.is_empty());
    assert!(plan.segments.iter().any(|segment| {
        segment.perms.execute
            && plan.entry >= segment.virtual_address
            && plan.entry < segment.virtual_address + segment.memory_size
    }));

    let plan = plan_elf_load(openat2_artifact).unwrap();
    assert!(!plan.segments.is_empty());
    assert!(plan.segments.iter().any(|segment| {
        segment.perms.execute
            && plan.entry >= segment.virtual_address
            && plan.entry < segment.virtual_address + segment.memory_size
    }));

    let plan = plan_elf_load(faccessat2_artifact).unwrap();
    assert!(!plan.segments.is_empty());
    assert!(plan.segments.iter().any(|segment| {
        segment.perms.execute
            && plan.entry >= segment.virtual_address
            && plan.entry < segment.virtual_address + segment.memory_size
    }));

    let plan = plan_elf_load(sendfile_artifact).unwrap();
    assert!(!plan.segments.is_empty());
    assert!(plan.segments.iter().any(|segment| {
        segment.perms.execute
            && plan.entry >= segment.virtual_address
            && plan.entry < segment.virtual_address + segment.memory_size
    }));

    let plan = plan_elf_load(preadv_artifact).unwrap();
    assert!(!plan.segments.is_empty());
    assert!(plan.segments.iter().any(|segment| {
        segment.perms.execute
            && plan.entry >= segment.virtual_address
            && plan.entry < segment.virtual_address + segment.memory_size
    }));

    let plan = plan_elf_load(splice_artifact).unwrap();
    assert!(!plan.segments.is_empty());
    assert!(plan.segments.iter().any(|segment| {
        segment.perms.execute
            && plan.entry >= segment.virtual_address
            && plan.entry < segment.virtual_address + segment.memory_size
    }));

    let plan = plan_elf_load(sync_artifact).unwrap();
    assert!(!plan.segments.is_empty());
    assert!(plan.segments.iter().any(|segment| {
        segment.perms.execute
            && plan.entry >= segment.virtual_address
            && plan.entry < segment.virtual_address + segment.memory_size
    }));

    let plan = plan_elf_load(pwrite64_artifact).unwrap();
    assert!(!plan.segments.is_empty());
    assert!(plan.segments.iter().any(|segment| {
        segment.perms.execute
            && plan.entry >= segment.virtual_address
            && plan.entry < segment.virtual_address + segment.memory_size
    }));

    let plan = plan_elf_load(pwritev_artifact).unwrap();
    assert!(!plan.segments.is_empty());
    assert!(plan.segments.iter().any(|segment| {
        segment.perms.execute
            && plan.entry >= segment.virtual_address
            && plan.entry < segment.virtual_address + segment.memory_size
    }));

    let plan = plan_elf_load(ftruncate_artifact).unwrap();
    assert!(!plan.segments.is_empty());
    assert!(plan.segments.iter().any(|segment| {
        segment.perms.execute
            && plan.entry >= segment.virtual_address
            && plan.entry < segment.virtual_address + segment.memory_size
    }));

    let plan = plan_elf_load(utimensat_artifact).unwrap();
    assert!(!plan.segments.is_empty());
    assert!(plan.segments.iter().any(|segment| {
        segment.perms.execute
            && plan.entry >= segment.virtual_address
            && plan.entry < segment.virtual_address + segment.memory_size
    }));

    let plan = plan_elf_load(mkdirat_artifact).unwrap();
    assert!(!plan.segments.is_empty());
    assert!(plan.segments.iter().any(|segment| {
        segment.perms.execute
            && plan.entry >= segment.virtual_address
            && plan.entry < segment.virtual_address + segment.memory_size
    }));

    let plan = plan_elf_load(unlinkat_artifact).unwrap();
    assert!(!plan.segments.is_empty());
    assert!(plan.segments.iter().any(|segment| {
        segment.perms.execute
            && plan.entry >= segment.virtual_address
            && plan.entry < segment.virtual_address + segment.memory_size
    }));

    let plan = plan_elf_load(renameat_artifact).unwrap();
    assert!(!plan.segments.is_empty());
    assert!(plan.segments.iter().any(|segment| {
        segment.perms.execute
            && plan.entry >= segment.virtual_address
            && plan.entry < segment.virtual_address + segment.memory_size
    }));

    let plan = plan_elf_load(fchmod_artifact).unwrap();
    assert!(!plan.segments.is_empty());
    assert!(plan.segments.iter().any(|segment| {
        segment.perms.execute
            && plan.entry >= segment.virtual_address
            && plan.entry < segment.virtual_address + segment.memory_size
    }));

    let plan = plan_elf_load(fchown_artifact).unwrap();
    assert!(!plan.segments.is_empty());
    assert!(plan.segments.iter().any(|segment| {
        segment.perms.execute
            && plan.entry >= segment.virtual_address
            && plan.entry < segment.virtual_address + segment.memory_size
    }));

    let plan = plan_elf_load(truncate_artifact).unwrap();
    assert!(!plan.segments.is_empty());
    assert!(plan.segments.iter().any(|segment| {
        segment.perms.execute
            && plan.entry >= segment.virtual_address
            && plan.entry < segment.virtual_address + segment.memory_size
    }));

    let plan = plan_elf_load(symlinkat_artifact).unwrap();
    assert!(!plan.segments.is_empty());
    assert!(plan.segments.iter().any(|segment| {
        segment.perms.execute
            && plan.entry >= segment.virtual_address
            && plan.entry < segment.virtual_address + segment.memory_size
    }));

    let plan = plan_elf_load(linkat_artifact).unwrap();
    assert!(!plan.segments.is_empty());
    assert!(plan.segments.iter().any(|segment| {
        segment.perms.execute
            && plan.entry >= segment.virtual_address
            && plan.entry < segment.virtual_address + segment.memory_size
    }));

    let plan = plan_elf_load(errno_matrix_artifact).unwrap();
    assert!(!plan.segments.is_empty());
    assert!(plan.segments.iter().any(|segment| {
        segment.perms.execute
            && plan.entry >= segment.virtual_address
            && plan.entry < segment.virtual_address + segment.memory_size
    }));

    // Existing ET_EXEC fixtures must keep load_bias == 0 and not be rebased.
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
    let output = std::process::Command::new("scripts/build-go-fixtures.sh")
        .output()
        .unwrap();
    assert!(output.status.success(), "Go fixture build failed");

    let go_artifact = "fixtures/go-aarch64-hello/target/release/carrick-linux-aarch64-go-hello";

    let output = assert_cmd::Command::cargo_bin("carrick")
        .unwrap()
        .args([
            "run-elf",
            go_artifact,
            "--max-traps",
            "1000",
        ])
        .output()
        .unwrap();

    if output.status.success() {
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(stdout.contains("\"exit_code\": 0"), "unexpected exit code in json: {}", stdout);
        assert!(stdout.contains("hello from Go under carrick"), "expected Go greeting: {}", stdout);
        assert!(stdout.contains("Worker"), "expected worker concurrency output: {}", stdout);
        assert!(stdout.contains("Map lookup: first=10, second=20"), "expected map output: {}", stdout);
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            stderr.contains("Hypervisor.framework"),
            "unexpected run-elf failure:\n{stderr}"
        );
    }
}

