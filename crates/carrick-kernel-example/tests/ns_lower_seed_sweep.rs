//! Deterministic scenario schedule sweep for the lower copy-up and whiteout scenario.
//!
//! Observed once on a cloudmac gate: intermittent `WaitTimedOut("read")` in
//! `two_live_process_lower_copy_up_and_whiteout_matrix` for n=32 population=128 same_parent=true.
//!
//! As documented in `crates/carrick-kernel-example/README.md` ("Deterministic scenario schedules")
//! and enforced by `crates/carrick-kernel-example/src/driver.rs`, scheduled scenario exploration
//! (`Schedule::explore(seed)`) admits only untimed private futex waits.
//! This scenario synchronizes actors via inter-process pipes (`pipe2` / `read`), which require
//! external descriptor wait enrollment on the host reactor. External readiness waits fail closed
//! with `external readiness: scheduled runs support only untimed private futex waits`.
//!
//! Consequently, scheduled exploration aborts on all seeds before any scheduling variation occurs,
//! and no scheduler receipt can be generated for this pipe-synchronized scenario.

use carrick_abi::{
    LINUX_AT_FDCWD, LINUX_EEXIST, LINUX_ENOENT, LINUX_O_RDONLY, LINUX_RENAME_NOREPLACE,
};
use carrick_kernel_example::{
    Schedule, ScriptedBackend, Step, await_parked, last_child, slot, sys,
};
use carrick_vfs::fs_backend::HostFsBackend;

fn run_case_with_schedule(seed: u64) -> Result<(), String> {
    let n = 32;
    let population = 128;
    let same_parent = true;

    let lower = tempfile::TempDir::new().map_err(|e| e.to_string())?;
    let upper = tempfile::TempDir::new().map_err(|e| e.to_string())?;
    for parent in ["shared", "unrelated"] {
        std::fs::create_dir(lower.path().join(parent)).map_err(|e| e.to_string())?;
    }
    for i in 0..population {
        std::fs::create_dir(lower.path().join(format!("population_{i}")))
            .map_err(|e| e.to_string())?;
    }
    let parents = ["shared", if same_parent { "shared" } else { "unrelated" }];
    let mut actors = [Vec::new(), Vec::new()];
    for (id, parent) in parents.iter().enumerate() {
        for i in 0..n {
            let src = format!("/{parent}/{id}_{i}_src");
            let dst = format!("/{parent}/{id}_{i}_dst");
            let alias = format!("/{parent}/{id}_{i}_alias");
            let deleted = format!("/{parent}/{id}_{i}_deleted");
            std::fs::write(lower.path().join(src.trim_start_matches('/')), b"lower")
                .map_err(|e| e.to_string())?;
            std::fs::write(
                lower.path().join(deleted.trim_start_matches('/')),
                b"deleted",
            )
            .map_err(|e| e.to_string())?;
            actors[id].extend([
                Step::Sys(
                    sys::linkat(
                        LINUX_AT_FDCWD,
                        src.clone(),
                        LINUX_AT_FDCWD,
                        alias.clone(),
                        0,
                    )
                    .ret(0),
                ),
                Step::Sys(
                    sys::renameat2(
                        LINUX_AT_FDCWD,
                        src.clone(),
                        LINUX_AT_FDCWD,
                        alias.clone(),
                        0,
                    )
                    .ret(0),
                ),
                Step::Sys(
                    sys::renameat2(
                        LINUX_AT_FDCWD,
                        src.clone(),
                        LINUX_AT_FDCWD,
                        alias,
                        LINUX_RENAME_NOREPLACE as u32,
                    )
                    .errno(LINUX_EEXIST),
                ),
                Step::Sys(
                    sys::renameat2(LINUX_AT_FDCWD, src.clone(), LINUX_AT_FDCWD, dst.clone(), 0)
                        .ret(0),
                ),
                Step::Sys(carrick_kernel_example::Syscall {
                    label: "openat-after-rename-whiteout",
                    ..sys::openat(LINUX_AT_FDCWD, src, LINUX_O_RDONLY as i32, 0).errno(LINUX_ENOENT)
                }),
                Step::Sys(sys::openat(LINUX_AT_FDCWD, dst, LINUX_O_RDONLY as i32, 0).save(4)),
                Step::Sys(sys::read(slot(4), 5).ret(5)),
                Step::Sys(sys::close(slot(4)).ret(0)),
                Step::Sys(sys::unlinkat(LINUX_AT_FDCWD, deleted.clone(), 0).ret(0)),
                Step::Sys(carrick_kernel_example::Syscall {
                    label: "openat-after-unlink-whiteout",
                    ..sys::openat(LINUX_AT_FDCWD, deleted, LINUX_O_RDONLY as i32, 0)
                        .errno(LINUX_ENOENT)
                }),
            ]);
            if id == 1 {
                actors[id].push(Step::Sys(sys::write(slot(3), b"c").ret(1)));
            }
        }
    }
    let mut script = vec![
        Step::Sys(
            sys::pipe2(0)
                .ret(0)
                .save_out_i32(0, 0, 0)
                .save_out_i32(0, 1, 1),
        ),
        Step::Sys(
            sys::pipe2(0)
                .ret(0)
                .save_out_i32(0, 0, 2)
                .save_out_i32(0, 1, 3),
        ),
        Step::Sys(sys::fork()),
    ];
    let mut child = vec![Step::Sys(sys::read(slot(0), 1).ret(1))];
    child.append(&mut actors[1]);
    child.extend([
        Step::Sys(sys::read(slot(0), 1).ret(1)),
        Step::Sys(sys::exit_group(0)),
    ]);
    script.push(Step::ChildMarker(child));
    script.push(await_parked(last_child(), "read"));
    script.push(Step::Sys(sys::write(slot(1), b"s").ret(1)));
    script.append(&mut actors[0]);
    for _ in 0..n {
        script.push(Step::Sys(sys::read(slot(2), 1).ret(1)));
    }
    script.extend([
        Step::Sys(sys::write(slot(1), b"f").ret(1)),
        Step::Sys(sys::wait4(last_child(), 0)),
        Step::Sys(sys::exit_group(0)),
    ]);

    let mut backend = HostFsBackend::from_path(upper.path()).map_err(|e| e.to_string())?;
    backend.enable_sparse_upper_fast_miss();
    let schedule = Schedule::explore(seed);
    let run_backend = ScriptedBackend::new()
        .with_fs_backend(Box::new(backend))
        .with_rootfs_layer(
            carrick_vfs::rootfs::RootFs::from_immutable_host_dir(lower.path())
                .map_err(|e| e.to_string())?,
        )
        .with_schedule(schedule);

    match run_backend.run_root(script) {
        Ok(_) => Ok(()),
        Err(e) => Err(format!("{e:?}")),
    }
}

/// Sweeps seeds 0..=200 under Schedule::explore.
///
/// Each seed fails immediately because the scenario's pipe-wait synchronization
/// is an external readiness wait, which driver.rs rejects under scheduled runs.
#[test]
#[ignore = "fails closed with external readiness on scheduled exploration; run with --ignored"]
fn sweep_seeds_0_to_200_lower_flake_scenario() {
    for seed in 0..=200 {
        let res = run_case_with_schedule(seed);
        assert!(
            res.is_err(),
            "expected seed {seed} to fail due to external readiness"
        );
        let err = match res {
            Ok(()) => String::new(),
            Err(e) => e,
        };
        assert!(
            err.contains(
                "external readiness: scheduled runs support only untimed private futex waits"
            ),
            "seed {seed} failed with unexpected error: {err}"
        );
    }
}
