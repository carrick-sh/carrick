        fn test_namespace_mutation_work() {
            use crate::fs_backend::host::{
                reset_test_host_openat_count, reset_test_host_parent_fstat_count,
                reset_test_host_stat_count, test_host_openat_count, test_host_parent_fstat_count,
                test_host_stat_count,
            };
            use crate::vfs::Vfs as _;

            let workspace_root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .parent()
                .unwrap()
                .parent()
                .unwrap();
            let log_dir = workspace_root.join("target/el1-host-namespace");
            std::fs::create_dir_all(&log_dir).unwrap();
            let log_path = log_dir.join("green-candidate.log");

            let mut records = Vec::new();

            for &n in &[1usize, 8, 32, 128] {
                // 1. Warm Rename under same directory
                {
                    let upper = tempfile::TempDir::new().unwrap();
                    let overlay = HostFsBackend::from_path(upper.path()).unwrap();
                    let mut vfs = RootFsVfs::new();
                    vfs.set_overlay(Box::new(overlay));

                    vfs.mkdir("/deep", 0o755).unwrap();
                    vfs.mkdir("/deep/nested", 0o755).unwrap();
                    vfs.mkdir("/deep/nested/dir", 0o755).unwrap();

                    for i in 0..n {
                        vfs.create_file(&format!("/deep/nested/dir/src_{i}"))
                            .unwrap();
                    }

                    // Warm parent resolution
                    let _ = vfs.resolved_parent("/deep/nested/dir/dummy").unwrap();

                    reset_test_host_openat_count();
                    reset_test_host_stat_count();
                    reset_test_host_parent_fstat_count();
                    vfs.dentry_cache.reset_host_open_count();

                    for i in 0..n {
                        let from = format!("/deep/nested/dir/src_{i}");
                        let to = format!("/deep/nested/dir/dst_{i}");
                        vfs.rename_with_flags(&from, &to, false).unwrap();
                    }

                    let opens = test_host_openat_count();
                    let backend_stats = test_host_stat_count();
                    let parent_fstats = test_host_parent_fstat_count();
                    let total_metadata = backend_stats + parent_fstats;
                    let dentry_opens = vfs.dentry_cache.host_open_count();

                    records.push(format!(
                        "scale_point={n} op=rename_same_dir opens={opens} dentry_opens={dentry_opens} backend_stats={backend_stats} parent_fstats={parent_fstats} total_metadata={total_metadata}"
                    ));

                    // Verify semantics
                    for i in 0..n {
                        assert_eq!(
                            vfs.lookup_nofollow(&format!("/deep/nested/dir/src_{i}")),
                            Err(LINUX_ENOENT)
                        );
                        assert!(
                            vfs.lookup_nofollow(&format!("/deep/nested/dir/dst_{i}"))
                                .is_ok()
                        );
                    }
                }

                // 2. Warm Rename across directories
                {
                    let upper = tempfile::TempDir::new().unwrap();
                    let overlay = HostFsBackend::from_path(upper.path()).unwrap();
                    let mut vfs = RootFsVfs::new();
                    vfs.set_overlay(Box::new(overlay));

                    vfs.mkdir("/a", 0o755).unwrap();
                    vfs.mkdir("/a/src_dir", 0o755).unwrap();
                    vfs.mkdir("/b", 0o755).unwrap();
                    vfs.mkdir("/b/dst_dir", 0o755).unwrap();

                    for i in 0..n {
                        vfs.create_file(&format!("/a/src_dir/file_{i}")).unwrap();
                    }

                    // Warm both parent directories
                    let _ = vfs.resolved_parent("/a/src_dir/dummy").unwrap();
                    let _ = vfs.resolved_parent("/b/dst_dir/dummy").unwrap();

                    reset_test_host_openat_count();
                    reset_test_host_stat_count();
                    reset_test_host_parent_fstat_count();
                    vfs.dentry_cache.reset_host_open_count();

                    for i in 0..n {
                        let from = format!("/a/src_dir/file_{i}");
                        let to = format!("/b/dst_dir/file_{i}");
                        vfs.rename_with_flags(&from, &to, false).unwrap();
                    }

                    let opens = test_host_openat_count();
                    let backend_stats = test_host_stat_count();
                    let parent_fstats = test_host_parent_fstat_count();
                    let total_metadata = backend_stats + parent_fstats;
                    let dentry_opens = vfs.dentry_cache.host_open_count();

                    records.push(format!(
                        "scale_point={n} op=rename_cross_dir opens={opens} dentry_opens={dentry_opens} backend_stats={backend_stats} parent_fstats={parent_fstats} total_metadata={total_metadata}"
                    ));

                    for i in 0..n {
                        assert_eq!(
                            vfs.lookup_nofollow(&format!("/a/src_dir/file_{i}")),
                            Err(LINUX_ENOENT)
                        );
                        assert!(vfs.lookup_nofollow(&format!("/b/dst_dir/file_{i}")).is_ok());
                    }
                }

                // 3. Warm Unlink under deep directory
                {
                    let upper = tempfile::TempDir::new().unwrap();
                    let overlay = HostFsBackend::from_path(upper.path()).unwrap();
                    let mut vfs = RootFsVfs::new();
                    vfs.set_overlay(Box::new(overlay));

                    vfs.mkdir("/deep", 0o755).unwrap();
                    vfs.mkdir("/deep/nested", 0o755).unwrap();
                    vfs.mkdir("/deep/nested/dir", 0o755).unwrap();

                    for i in 0..n {
                        vfs.create_file(&format!("/deep/nested/dir/file_{i}"))
                            .unwrap();
                    }

                    // Warm parent resolution
                    let _ = vfs.resolved_parent("/deep/nested/dir/dummy").unwrap();

                    reset_test_host_openat_count();
                    reset_test_host_stat_count();
                    reset_test_host_parent_fstat_count();
                    vfs.dentry_cache.reset_host_open_count();

                    for i in 0..n {
                        let path = format!("/deep/nested/dir/file_{i}");
                        vfs.unlink(&path).unwrap();
                    }

                    let opens = test_host_openat_count();
                    let backend_stats = test_host_stat_count();
                    let parent_fstats = test_host_parent_fstat_count();
                    let total_metadata = backend_stats + parent_fstats;
                    let dentry_opens = vfs.dentry_cache.host_open_count();

                    records.push(format!(
                        "scale_point={n} op=unlink opens={opens} dentry_opens={dentry_opens} backend_stats={backend_stats} parent_fstats={parent_fstats} total_metadata={total_metadata}"
                    ));

                    for i in 0..n {
                        assert_eq!(
                            vfs.lookup_nofollow(&format!("/deep/nested/dir/file_{i}")),
                            Err(LINUX_ENOENT)
                        );
                    }
                }

                // 4. Cold vs Warm Rename (Scale 1)
                if n == 1 {
                    let upper = tempfile::TempDir::new().unwrap();
                    std::fs::create_dir_all(upper.path().join("cold/sub")).unwrap();
                    std::fs::write(upper.path().join("cold/sub/first"), b"data").unwrap();
                    std::fs::write(upper.path().join("cold/sub/second"), b"data").unwrap();

                    let overlay = HostFsBackend::from_path(upper.path()).unwrap();
                    let mut vfs = RootFsVfs::new();
                    vfs.set_overlay(Box::new(overlay));

                    // Cold rename: parent directory fd not yet opened in dentry_cache
                    reset_test_host_openat_count();
                    reset_test_host_stat_count();
                    reset_test_host_parent_fstat_count();
                    vfs.dentry_cache.reset_host_open_count();

                    vfs.rename_with_flags("/cold/sub/first", "/cold/sub/first_renamed", false)
                        .unwrap();
                    let cold_opens = test_host_openat_count();
                    let cold_backend_stats = test_host_stat_count();
                    let cold_parent_fstats = test_host_parent_fstat_count();
                    let cold_total_metadata = cold_backend_stats + cold_parent_fstats;
                    let cold_dentry_opens = vfs.dentry_cache.host_open_count();

                    records.push(format!(
                        "scale_point=1 op=rename_cold opens={cold_opens} dentry_opens={cold_dentry_opens} backend_stats={cold_backend_stats} parent_fstats={cold_parent_fstats} total_metadata={cold_total_metadata}"
                    ));

                    // Warm rename: parent directory fd already cached
                    reset_test_host_openat_count();
                    reset_test_host_stat_count();
                    reset_test_host_parent_fstat_count();
                    vfs.dentry_cache.reset_host_open_count();

                    vfs.rename_with_flags("/cold/sub/second", "/cold/sub/second_renamed", false)
                        .unwrap();
                    let warm_opens = test_host_openat_count();
                    let warm_backend_stats = test_host_stat_count();
                    let warm_parent_fstats = test_host_parent_fstat_count();
                    let warm_total_metadata = warm_backend_stats + warm_parent_fstats;
                    let warm_dentry_opens = vfs.dentry_cache.host_open_count();

                    records.push(format!(
                        "scale_point=1 op=rename_warm_after_cold opens={warm_opens} dentry_opens={warm_dentry_opens} backend_stats={warm_backend_stats} parent_fstats={warm_parent_fstats} total_metadata={warm_total_metadata}"
                    ));


                }

                // 5. Cold vs Warm Unlink (Scale 1)
                if n == 1 {
                    let upper = tempfile::TempDir::new().unwrap();
                    std::fs::create_dir_all(upper.path().join("cold_unlink/sub")).unwrap();
                    std::fs::write(upper.path().join("cold_unlink/sub/first"), b"data").unwrap();
                    std::fs::write(upper.path().join("cold_unlink/sub/second"), b"data").unwrap();

                    let overlay = HostFsBackend::from_path(upper.path()).unwrap();
                    let mut vfs = RootFsVfs::new();
                    vfs.set_overlay(Box::new(overlay));

                    // Cold unlink: parent directory fd not yet opened in dentry_cache
                    reset_test_host_openat_count();
                    reset_test_host_stat_count();
                    reset_test_host_parent_fstat_count();
                    vfs.dentry_cache.reset_host_open_count();

                    vfs.unlink("/cold_unlink/sub/first").unwrap();
                    let cold_opens = test_host_openat_count();
                    let cold_backend_stats = test_host_stat_count();
                    let cold_parent_fstats = test_host_parent_fstat_count();
                    let cold_total_metadata = cold_backend_stats + cold_parent_fstats;
                    let cold_dentry_opens = vfs.dentry_cache.host_open_count();

                    records.push(format!(
                        "scale_point=1 op=unlink_cold opens={cold_opens} dentry_opens={cold_dentry_opens} backend_stats={cold_backend_stats} parent_fstats={cold_parent_fstats} total_metadata={cold_total_metadata}"
                    ));

                    // Warm unlink: parent directory fd already cached
                    reset_test_host_openat_count();
                    reset_test_host_stat_count();
                    reset_test_host_parent_fstat_count();
                    vfs.dentry_cache.reset_host_open_count();

                    vfs.unlink("/cold_unlink/sub/second").unwrap();
                    let warm_opens = test_host_openat_count();
                    let warm_backend_stats = test_host_stat_count();
                    let warm_parent_fstats = test_host_parent_fstat_count();
                    let warm_total_metadata = warm_backend_stats + warm_parent_fstats;
                    let warm_dentry_opens = vfs.dentry_cache.host_open_count();

                    records.push(format!(
                        "scale_point=1 op=unlink_warm_after_cold opens={warm_opens} dentry_opens={warm_dentry_opens} backend_stats={warm_backend_stats} parent_fstats={warm_parent_fstats} total_metadata={warm_total_metadata}"
                    ));


                }
            }

            let log_content = records.join("\n") + "\n";
            std::fs::write(&log_path, &log_content).unwrap();
            let baseline_path = log_dir.join("baseline-measurements.log");
            std::fs::write(&baseline_path, &log_content).unwrap();
            eprintln!("MEASUREMENTS:\n{log_content}");

            // Now assert structural budgets
            for line in &records {
                let parts: std::collections::HashMap<&str, &str> = line
                    .split_whitespace()
                    .filter_map(|pair| pair.split_once('='))
                    .collect();
                let n: usize = parts.get("scale_point").unwrap().parse().unwrap();
                let op = *parts.get("op").unwrap();
                let opens: u64 = parts.get("opens").unwrap().parse().unwrap();
                let dentry_opens: u64 = parts.get("dentry_opens").unwrap().parse().unwrap();
                let total_metadata: u64 = parts.get("total_metadata").unwrap().parse().unwrap();

                if op.starts_with("rename_cold") || op.starts_with("unlink_cold") {
                    assert_eq!(opens, 0, "cold backend opens");
                    assert_eq!(dentry_opens, 2, "cold two-directory traversal");
                    continue;
                }

                assert_eq!(
                    opens, 0,
                    "{op} at scale {n} issued {opens} host openat calls (budget 0)"
                );
                assert_eq!(
                    dentry_opens, 0,
                    "{op} at scale {n} issued {dentry_opens} dentry host opens (budget 0)"
                );
                let budget = match op {
                    "rename_same_dir" | "rename_cross_dir" | "rename_warm_after_cold" => {
                        (8 * n) as u64
                    }
                    "unlink" | "unlink_warm_after_cold" => (4 * n) as u64,
                    _ => unreachable!(),
                };
                assert!(
                    total_metadata <= budget,
                    "{op} at scale {n} issued {total_metadata} total metadata calls (budget <= {budget})"
                );
            }
        }
