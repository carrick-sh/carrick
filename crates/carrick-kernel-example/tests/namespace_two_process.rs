//! Namespace publication through two live Linux tasks sharing one host backend.
//! Linux references: rename(2), renameat2(2), linkat(2), unlinkat(2), openat(2).
//! The pipes bound task lifetime, not individual namespace operations: after
//! release both actors run independently, including when they share a parent.

use carrick_abi::{
    LINUX_AT_FDCWD, LINUX_EEXIST, LINUX_ENOENT, LINUX_O_RDONLY, LINUX_RENAME_EXCHANGE,
    LINUX_RENAME_NOREPLACE,
};
use carrick_kernel_example::{ScriptedBackend, Step, await_parked, last_child, slot, sys};
use carrick_vfs::fs_backend::HostFsBackend;

fn actor(parent: &str, actor: usize, n: usize) -> Vec<Step> {
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
    }
    script
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
                child.extend(actor(parents[1], 1, n));
                child.extend([
                    Step::Sys(sys::write(slot(3), b"c").ret(1)),
                    Step::Sys(sys::read(slot(0), 1).ret(1)),
                    Step::Sys(sys::exit_group(0)),
                ]);
                script.push(Step::ChildMarker(child));
                script.push(await_parked(last_child(), "read"));
                script.push(Step::Sys(sys::write(slot(1), b"s").ret(1)));
                script.extend(actor(parents[0], 0, n));
                script.extend([
                    Step::Sys(sys::read(slot(2), 1).ret(1)),
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
                assert_eq!(reads.iter().filter(|&&b| b == b'a').count(), 2 * n);
                assert_eq!(reads.iter().filter(|&&b| b == b'b').count(), 2 * n);
                assert_eq!(reads.iter().filter(|&&b| b == b'd').count(), 2 * n);
            }
        }
    }
}
