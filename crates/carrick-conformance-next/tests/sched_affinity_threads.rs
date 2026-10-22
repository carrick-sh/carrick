//! In-process conformance probe for sched_setaffinity and sched_getaffinity
//! mask reflection across main thread and a spawned thread.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod common;

use std::path::{Path, PathBuf};

use carrick_conformance_next::ResultAssert;

fn find_probe_binary_dir(repo_root: &Path, target: &str) -> Option<PathBuf> {
    let candidate1 = repo_root
        .join("conformance-probes/target")
        .join(target)
        .join("release");
    if candidate1.is_dir() {
        return Some(candidate1);
    }
    let candidate2 = repo_root.join("target").join(target).join("release");
    if candidate2.is_dir() {
        return Some(candidate2);
    }
    None
}

#[test]
fn case_sched_affinity_threads_mask_reflection() {
    let _guard = common::guest_lock();
    let root = common::repo_root();
    for target in ["aarch64-unknown-linux-musl", "aarch64-unknown-linux-gnu"] {
        let dir = find_probe_binary_dir(&root, target).unwrap_or_else(|| {
            panic!(
                "missing probe binaries directory for target {target}; \
                 expected either conformance-probes/target/{target}/release or target/{target}/release — \
                 run scripts/build-probes.sh"
            )
        });
        let binary = dir.join("schedaffinitythreads");
        let init = dir.join("probeinit");
        assert!(
            binary.is_file() && init.is_file(),
            "missing exact-bundle {target} affinity probe: {} — run scripts/build-probes.sh",
            binary.display()
        );
        let container = common::generic_probe_container("schedaffinitythreads", &binary, &init);
        let (result, _) = common::run_or_fail(common::with_empty_stdin_pipe(|| {
            container.run_with_audit(["/tmp/carrick-init"])
        }));
        result.assert_success();
        result.assert_exit_code(0);
        assert_eq!(result.signal, None);
        assert!(!result.trap_limit_hit);
        assert_eq!(result.terminal_reason, None);
        assert_eq!(
            result.stdout_utf8(),
            concat!(
                "main_setaffinity_res=0\n",
                "main_setaffinity_errno=0\n",
                "main_getaffinity_size_rule=true\n",
                "main_getaffinity_errno=0\n",
                "main_mask_reflected=true\n",
                "thread_setaffinity_res=0\n",
                "thread_setaffinity_errno=0\n",
                "thread_getaffinity_size_rule=true\n",
                "thread_getaffinity_errno=0\n",
                "thread_mask_reflected=true\n",
                "threads_independent=true\n",
                "clone_mask_inherited=true\n",
            )
        );
        let diagnostics = result.stderr_utf8();
        let raw: Vec<_> = diagnostics.lines().collect();
        assert_eq!(raw.len(), 2, "{diagnostics}");
        for (line, prefix) in raw
            .iter()
            .zip(["main_getaffinity_raw=", "thread_getaffinity_raw="])
        {
            let bytes: usize = line.strip_prefix(prefix).unwrap().parse().unwrap();
            assert!(
                bytes > 0 && bytes <= 128 && bytes.is_multiple_of(8),
                "{line}"
            );
        }
    }
}
