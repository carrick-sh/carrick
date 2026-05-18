use carrick::elf::{Machine, inspect_elf, plan_elf_load};

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
    let sendfile_artifact = "fixtures/linux-aarch64-hello/target/aarch64-unknown-linux-musl/release/carrick-linux-aarch64-sendfile-motd";
    let preadv_artifact = "fixtures/linux-aarch64-hello/target/aarch64-unknown-linux-musl/release/carrick-linux-aarch64-preadv-motd";
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
    let metadata = inspect_elf(sendfile_artifact).unwrap();
    assert_eq!(metadata.machine, Machine::Aarch64);
    let metadata = inspect_elf(preadv_artifact).unwrap();
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
}
