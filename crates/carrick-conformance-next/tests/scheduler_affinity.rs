//! Exact-target affinity semantics, run through the retained generic probe's
//! in-process topology. The generic shards separately compare both libcs with
//! the director's source-validated Docker oracle.
#![allow(clippy::unwrap_used, clippy::expect_used)]
mod common;

#[test]
fn cross_thread_affinity_changes_only_the_named_thread() {
    let _guard = common::guest_lock();
    let root = common::repo_root();
    for target in ["aarch64-unknown-linux-musl", "aarch64-unknown-linux-gnu"] {
        let dir = root
            .join("conformance-probes/target")
            .join(target)
            .join("release");
        let binary = dir.join("schedaffinitysibling");
        let init = dir.join("probeinit");
        assert!(
            binary.is_file() && init.is_file(),
            "missing exact-bundle {target} affinity probe"
        );
        let container = common::generic_probe_container("schedaffinitysibling", &binary, &init);
        let result = common::run_named_or_fail(
            "cross-thread affinity",
            common::with_empty_stdin_pipe(|| container.run(["/tmp/carrick-init"])),
        );
        assert_eq!(result.exit_code, 0, "{target}: {}", result.stderr_utf8());
        let output = result.stdout_utf8();
        println!("{target}:\n{output}");
        for line in [
            "sibling_affinity_ok=true",
            "distinct_masks_exercised=true",
            "caller_mask_unchanged=true",
            "sibling_mask_from_caller=true",
            "sibling_mask_from_sibling=true",
            "leader_mask_from_sibling=true",
            "caller_get_errno=0",
            "sibling_get_errno=0",
            "same_mask_set_errno=0",
            "changed_set_errno=0",
            "caller_after_errno=0",
            "sibling_after_errno=0",
            "worker_get_errno=0",
            "worker_initial_errno=0",
            "leader_get_errno=0",
        ] {
            assert!(
                output.lines().any(|actual| actual == line),
                "{target}: missing {line}:\n{output}"
            );
        }
    }
}
