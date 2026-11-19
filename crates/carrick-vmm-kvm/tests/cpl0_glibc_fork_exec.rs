//! KVM comparison for the production CPL0 soft-carrier fork/exec witness.

#![cfg(all(target_os = "linux", target_arch = "x86_64"))]
#![allow(clippy::expect_used)]

#[allow(dead_code)]
#[path = "common/kvm_pool_fixture.rs"]
mod kvm_pool_fixture;
#[path = "../../carrick-cli/tests/fixtures/x86_process_entry.rs"]
mod x86_process_entry;

#[test]
fn production_ring_runs_glibc_fork_exec_wait_on_kvm() {
    let sources =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../carrick-vmm-soft/tests/fixtures");
    let dir = tempfile::tempdir().expect("fixture root");
    let parent = dir.path().join("parent");
    x86_process_entry::compile_static_fixture(&sources.join("x86_glibc_fork_exec.c"), &parent, &[]);
    x86_process_entry::compile_static_fixture(
        &sources.join("x86_fork_exec_child.S"),
        &dir.path().join("fork-exec-child"),
        &["-nostdlib"],
    );

    let elf = std::fs::read(parent).expect("compiled parent");
    let program =
        carrick_mem::elf::ElfProgram::load(&elf, 62, &|_| None).expect("static glibc ELF");
    let mut dispatcher = carrick_kernel::dispatch::SyscallDispatcher::default();
    dispatcher.set_fs_backend(Box::new(
        carrick_vfs::fs_backend::HostFsBackend::from_path(dir.path()).expect("fixture filesystem"),
    ));
    let outcome = kvm_pool_fixture::try_run_program_with_dispatcher(
        &program,
        256,
        1, // Match the soft carrier's single scheduling lane.
        |_| {},
        dispatcher,
    )
    .map_err(|failure| failure.error)
    .expect("production CPL0 fork/exec/wait");
    assert!(
        outcome.run.stderr.is_empty(),
        "guest stderr: {:?}",
        String::from_utf8_lossy(&outcome.run.stderr)
    );
    assert_eq!(
        (outcome.run.exit_code, outcome.run.stdout.as_slice()),
        (
            0,
            b"child ran after exec\nparent reaped exit 7\n".as_slice()
        )
    );
}
