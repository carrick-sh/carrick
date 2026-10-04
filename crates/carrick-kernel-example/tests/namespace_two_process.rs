//! Namespace publication through two live Linux tasks sharing one host backend.
//! Linux references: rename(2), renameat2(2), linkat(2), unlinkat(2), openat(2).
//! The pipes bound task lifetime, not individual namespace operations: after
//! release both actors run independently, including when they share a parent.

use std::os::unix::fs::MetadataExt;

use carrick_abi::{
    LINUX_AT_FDCWD, LINUX_EEXIST, LINUX_ENOENT, LINUX_O_RDONLY, LINUX_RENAME_EXCHANGE,
    LINUX_RENAME_NOREPLACE,
};
use carrick_kernel_example::{
    Schedule, ScriptedBackend, Step, await_parked, last_child, slot, sys,
};
use carrick_vfs::fs_backend::{HostFsBackend, LowerEntryPublishHook};

fn failing_archive(name: &str) -> std::io::Result<Vec<u8>> {
    let mut builder = tar::Builder::new(Vec::new());
    for (path, contents) in [
        (name.to_owned(), b"changed".as_slice()),
        ("x".repeat(300), b"late".as_slice()),
    ] {
        let mut header = tar::Header::new_gnu();
        header.set_size(contents.len() as u64);
        header.set_mode(0o600);
        header.set_entry_type(tar::EntryType::Regular);
        header.set_cksum();
        builder.append_data(&mut header, path, contents)?;
    }
    builder.into_inner()
}

fn actor(parent: &str, actor: usize, n: usize) -> std::io::Result<Vec<Step>> {
    let mut script = Vec::new();
    for i in 0..n {
        let prefix = format!("/{parent}/{actor}_{i}");
        let src = format!("{prefix}_src");
        let alias = format!("{prefix}_alias");
        let other = format!("{prefix}_other");
        let moved = format!("{prefix}_moved");
        // Both physical names must survive same-inode rename, including the
        // failed NOREPLACE. Subsequent opens exercise the published lookup.
        script.extend([
            Step::Sys(sys::openat(LINUX_AT_FDCWD, src.clone(), LINUX_O_RDONLY as i32, 0).save(4)),
            Step::Sys(sys::read(slot(4), 1).ret(1)),
            Step::Sys(sys::close(slot(4)).ret(0)),
            Step::ArchiveImportRollback {
                destination: format!("/{parent}"),
                bytes: failing_archive(&format!("{actor}_{i}_src"))?,
            },
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
                    alias.clone(),
                    LINUX_RENAME_NOREPLACE as u32,
                )
                .errno(LINUX_EEXIST),
            ),
            Step::Sys(sys::openat(LINUX_AT_FDCWD, src.clone(), LINUX_O_RDONLY as i32, 0).save(4)),
            Step::Sys(sys::read(slot(4), 1).ret(1)),
            Step::Sys(sys::close(slot(4)).ret(0)),
            Step::Sys(
                sys::renameat2(
                    LINUX_AT_FDCWD,
                    src.clone(),
                    LINUX_AT_FDCWD,
                    other.clone(),
                    LINUX_RENAME_EXCHANGE as u32,
                )
                .ret(0),
            ),
            // A description remains usable after unlink; a new open fails.
            Step::Sys(sys::openat(LINUX_AT_FDCWD, src.clone(), LINUX_O_RDONLY as i32, 0).save(4)),
            Step::Sys(sys::unlinkat(LINUX_AT_FDCWD, src.clone(), 0).ret(0)),
            Step::Sys(sys::read(slot(4), 1).ret(1)),
            Step::Sys(sys::close(slot(4)).ret(0)),
            Step::Sys(
                sys::openat(LINUX_AT_FDCWD, src, LINUX_O_RDONLY as i32, 0).errno(LINUX_ENOENT),
            ),
            Step::Sys(sys::renameat2(LINUX_AT_FDCWD, other, LINUX_AT_FDCWD, moved, 0).ret(0)),
            Step::Sys(
                sys::renameat2(
                    LINUX_AT_FDCWD,
                    format!("{prefix}_dir"),
                    LINUX_AT_FDCWD,
                    format!("{prefix}_dir_moved"),
                    0,
                )
                .ret(0),
            ),
            Step::Sys(
                sys::openat(
                    LINUX_AT_FDCWD,
                    format!("{prefix}_dir_moved/leaf"),
                    LINUX_O_RDONLY as i32,
                    0,
                )
                .save(4),
            ),
            Step::Sys(sys::read(slot(4), 1).ret(1)),
            Step::Sys(sys::close(slot(4)).ret(0)),
        ]);
        if actor == 1 {
            // Keep the actors independent: the parent drains progress only
            // after its own namespace batch has finished.
            script.push(Step::Sys(sys::write(slot(3), b"c").ret(1)));
        }
    }
    Ok(script)
}

#[test]
fn two_live_process_namespace_publication_matrix() {
    for n in [1, 8, 32, 128] {
        for population in [0, 128] {
            for same_parent in [true, false] {
                let root = tempfile::TempDir::new().unwrap();
                for parent in ["shared", "unrelated"] {
                    std::fs::create_dir(root.path().join(parent)).unwrap();
                }
                for i in 0..population {
                    std::fs::create_dir(root.path().join(format!("population_{i}"))).unwrap();
                }
                let parents = ["shared", if same_parent { "shared" } else { "unrelated" }];
                for (id, parent) in parents.iter().enumerate() {
                    for i in 0..n {
                        let prefix = root.path().join(parent).join(format!("{id}_{i}"));
                        std::fs::write(prefix.with_file_name(format!("{id}_{i}_src")), b"a")
                            .unwrap();
                        std::fs::write(prefix.with_file_name(format!("{id}_{i}_other")), b"b")
                            .unwrap();
                        let dir = prefix.with_file_name(format!("{id}_{i}_dir"));
                        std::fs::create_dir(&dir).unwrap();
                        std::fs::write(dir.join("leaf"), b"d").unwrap();
                    }
                }
                let backend = HostFsBackend::from_path(root.path()).unwrap();
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
                child.extend(actor(parents[1], 1, n).unwrap());
                child.extend([
                    Step::Sys(sys::read(slot(0), 1).ret(1)),
                    Step::Sys(sys::exit_group(0)),
                ]);
                script.push(Step::ChildMarker(child));
                script.push(await_parked(last_child(), "read"));
                script.push(Step::Sys(sys::write(slot(1), b"s").ret(1)));
                script.extend(actor(parents[0], 0, n).unwrap());
                for _ in 0..n {
                    script.push(Step::Sys(sys::read(slot(2), 1).ret(1)));
                }
                script.extend([
                    Step::Sys(sys::write(slot(1), b"f").ret(1)),
                    Step::Sys(sys::wait4(last_child(), 0)),
                    Step::Sys(sys::exit_group(0)),
                ]);
                let result = ScriptedBackend::new()
                    .with_fs_backend(Box::new(backend))
                    .run_root(script);
                let run = match result {
                    Ok(run) => run,
                    Err(error) => {
                        let evidence = root.keep();
                        panic!(
                            "namespace n={n} population={population} same_parent={same_parent}: {error:?}; physical evidence {}",
                            evidence.display()
                        );
                    }
                };
                assert_eq!(run.tasks_started(), 2);
                assert_eq!(run.exit_code(), 0);
                for (id, parent) in parents.iter().enumerate() {
                    for i in 0..n {
                        let base = root.path().join(parent);
                        assert!(!base.join(format!("{id}_{i}_src")).exists());
                        assert_eq!(
                            std::fs::read(base.join(format!("{id}_{i}_alias"))).unwrap(),
                            b"a"
                        );
                        assert_eq!(
                            std::fs::read(base.join(format!("{id}_{i}_moved"))).unwrap(),
                            b"a"
                        );
                        let alias =
                            std::fs::metadata(base.join(format!("{id}_{i}_alias"))).unwrap();
                        let moved =
                            std::fs::metadata(base.join(format!("{id}_{i}_moved"))).unwrap();
                        assert_eq!((alias.dev(), alias.ino()), (moved.dev(), moved.ino()));
                        assert_eq!(alias.nlink(), 2);
                        assert_eq!(
                            std::fs::read(base.join(format!("{id}_{i}_dir_moved/leaf"))).unwrap(),
                            b"d"
                        );
                    }
                }
                // Each actor's read stream is ordered, but inter-task outputs
                // can interleave. Count each payload rather than sorting tasks.
                let reads = run
                    .outputs()
                    .iter()
                    .filter(|output| output.label == "read")
                    .flat_map(|output| output.bytes.iter())
                    .copied()
                    .collect::<Vec<_>>();
                assert_eq!(reads.iter().filter(|&&b| b == b'a').count(), 4 * n);
                assert_eq!(reads.iter().filter(|&&b| b == b'b').count(), 2 * n);
                assert_eq!(reads.iter().filter(|&&b| b == b'd').count(), 2 * n);
                assert_eq!(reads.iter().filter(|&&b| b == b'c').count(), n);
            }
        }
    }
}

#[test]
fn two_live_process_lower_copy_up_and_whiteout_matrix() {
    let scheduled_seed = std::env::var("VMFREE_SEED")
        .ok()
        .and_then(|seed| seed.parse::<u64>().ok());
    for n in [1, 8, 32, 128] {
        for population in [0, 128] {
            for same_parent in [true, false] {
                if scheduled_seed.is_some() && (n != 32 || population != 128 || !same_parent) {
                    continue;
                }
                let lower = tempfile::TempDir::new().unwrap();
                let upper = tempfile::TempDir::new().unwrap();
                for parent in ["shared", "unrelated"] {
                    std::fs::create_dir(lower.path().join(parent)).unwrap();
                }
                for i in 0..population {
                    std::fs::create_dir(lower.path().join(format!("population_{i}"))).unwrap();
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
                            .unwrap();
                        std::fs::write(
                            lower.path().join(deleted.trim_start_matches('/')),
                            b"deleted",
                        )
                        .unwrap();
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
                                sys::renameat2(
                                    LINUX_AT_FDCWD,
                                    src.clone(),
                                    LINUX_AT_FDCWD,
                                    dst.clone(),
                                    0,
                                )
                                .ret(0),
                            ),
                            Step::Sys(carrick_kernel_example::Syscall {
                                label: "openat-after-rename-whiteout",
                                ..sys::openat(LINUX_AT_FDCWD, src, LINUX_O_RDONLY as i32, 0)
                                    .errno(LINUX_ENOENT)
                            }),
                            Step::Sys(
                                sys::openat(LINUX_AT_FDCWD, dst, LINUX_O_RDONLY as i32, 0).save(4),
                            ),
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
                            // Report one completed unit of child work. The parent
                            // drains these only after its own batch, so the two
                            // namespace actors still run independently. Each
                            // bounded read now measures one iteration's progress
                            // instead of total host-FS time for the whole batch.
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
                let mut backend = HostFsBackend::from_path(upper.path()).unwrap();
                backend.enable_sparse_upper_fast_miss();
                let schedule = scheduled_seed.map(Schedule::explore);
                let mut run_backend = ScriptedBackend::new()
                    .with_fs_backend(Box::new(backend))
                    .with_rootfs_layer(
                        carrick_vfs::rootfs::RootFs::from_immutable_host_dir(lower.path()).unwrap(),
                    );
                if let Some(schedule) = &schedule {
                    run_backend = run_backend.with_schedule(schedule.clone());
                }
                let result = run_backend.run_root(script);
                if let Some(schedule) = &schedule {
                    let summary = result
                        .as_ref()
                        .map(|_| "completed".to_owned())
                        .unwrap_or_else(|error| error.to_string());
                    let work = result.as_ref().ok().map(|run| run.work_snapshot().clone());
                    if let Ok(receipt) = schedule.receipt(summary, work) {
                        if let Ok(path) = std::env::var("VMFREE_TRACE") {
                            std::fs::write(path, serde_json::to_vec_pretty(&receipt).unwrap())
                                .unwrap();
                        }
                    }
                }
                let run = match result {
                    Ok(run) => run,
                    Err(error) => {
                        let lower_evidence = lower.keep();
                        let upper_evidence = upper.keep();
                        panic!(
                            "lower n={n} population={population} same_parent={same_parent} seed={:?}: {error:?}; lower evidence {}; upper evidence {}",
                            scheduled_seed,
                            lower_evidence.display(),
                            upper_evidence.display()
                        );
                    }
                };
                assert_eq!(run.tasks_started(), 2);
                assert_eq!(run.exit_code(), 0);
                for (id, parent) in parents.iter().enumerate() {
                    for i in 0..n {
                        let base = lower.path().join(parent);
                        assert_eq!(
                            std::fs::read(base.join(format!("{id}_{i}_src"))).unwrap(),
                            b"lower"
                        );
                        assert_eq!(
                            std::fs::read(base.join(format!("{id}_{i}_deleted"))).unwrap(),
                            b"deleted"
                        );
                        assert!(!base.join(format!("{id}_{i}_dst")).exists());
                        let copied = std::fs::metadata(
                            upper.path().join(parent).join(format!("{id}_{i}_dst")),
                        )
                        .unwrap();
                        let alias = std::fs::metadata(
                            upper.path().join(parent).join(format!("{id}_{i}_alias")),
                        )
                        .unwrap();
                        assert_eq!(
                            (copied.dev(), copied.ino(), copied.nlink()),
                            (alias.dev(), alias.ino(), 2)
                        );
                        assert_eq!(
                            std::fs::read(upper.path().join(parent).join(format!("{id}_{i}_dst")))
                                .unwrap(),
                            b"lower"
                        );
                    }
                }
                assert_eq!(
                    run.outputs()
                        .iter()
                        .filter(|o| o.label == "read" && o.bytes == b"lower")
                        .count(),
                    2 * n
                );
                assert_eq!(
                    run.outputs()
                        .iter()
                        .filter(|o| o.label == "read" && o.bytes == b"c")
                        .count(),
                    n
                );
            }
        }
    }
}

/// A lower file refill paused after its host identity check must not publish
/// its earlier observation into the cache after another live task's whiteout.
#[test]
fn two_live_process_late_lower_refill_cannot_resurrect_whiteout() {
    use carrick_kernel_example::operand::ScriptCheckpoint;
    use std::sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    };
    let lower = tempfile::TempDir::new().unwrap();
    let upper = tempfile::TempDir::new().unwrap();
    std::fs::create_dir(lower.path().join("parent")).unwrap();
    std::fs::write(lower.path().join("parent/victim"), b"lower").unwrap();
    let arrived = ScriptCheckpoint::default();
    let release = ScriptCheckpoint::default();
    let once = AtomicBool::new(false);
    let mut backend = HostFsBackend::from_path(upper.path()).unwrap();
    let hook_arrived = arrived.clone();
    let hook_release = release.clone();
    let hook: LowerEntryPublishHook = Arc::new(move |path| {
        if path == "/parent/victim" && !once.swap(true, Ordering::SeqCst) {
            hook_arrived.signal();
            assert!(hook_release.wait(), "writer did not release lower refill");
        }
    });
    backend.set_lower_entry_publish_hook(hook);
    let finished = ScriptCheckpoint::default();
    let script = vec![
        Step::Sys(sys::fork()),
        Step::ChildMarker(vec![
            Step::AwaitCheckpoint(arrived),
            Step::Sys(
                sys::linkat(
                    LINUX_AT_FDCWD,
                    "/parent/victim",
                    LINUX_AT_FDCWD,
                    "/parent/alias",
                    0,
                )
                .ret(0),
            ),
            Step::Sys(
                sys::renameat2(
                    LINUX_AT_FDCWD,
                    "/parent/victim",
                    LINUX_AT_FDCWD,
                    "/parent/moved",
                    0,
                )
                .ret(0),
            ),
            Step::SignalCheckpoint(release),
            Step::AwaitCheckpoint(finished.clone()),
            Step::Sys(sys::exit_group(0)),
        ]),
        // This read overlaps the mutation and may retain the earlier file.
        Step::Sys(sys::openat(LINUX_AT_FDCWD, "/parent/victim", LINUX_O_RDONLY as i32, 0).save(4)),
        Step::Sys(sys::close(slot(4)).ret(0)),
        // The writer completed before the previous open returned, so this
        // distinct open has no overlap and must see the published whiteout.
        Step::Sys(
            sys::openat(LINUX_AT_FDCWD, "/parent/victim", LINUX_O_RDONLY as i32, 0)
                .errno(LINUX_ENOENT),
        ),
        Step::SignalCheckpoint(finished),
        Step::Sys(sys::wait4(last_child(), 0)),
        Step::Sys(sys::exit_group(0)),
    ];
    let run = ScriptedBackend::new()
        .with_fs_backend(Box::new(backend))
        .with_rootfs_layer(
            carrick_vfs::rootfs::RootFs::from_immutable_host_dir(lower.path()).unwrap(),
        )
        .run_root(script)
        .unwrap();
    assert_eq!(run.tasks_started(), 2);
    assert_eq!(run.exit_code(), 0);
    assert!(!upper.path().join("parent/victim").exists());
    assert_eq!(
        std::fs::read(upper.path().join("parent/moved")).unwrap(),
        b"lower"
    );
}
