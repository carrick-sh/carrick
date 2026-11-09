//! Signed guest witness for the ARM native prefix-completion path (#1954).
//! A fork child (a ring-owned native task) writes through regular-file
//! descriptors its parent opened on a host-backed mount, from buffers that
//! stop being readable part-way. Linux returns the readable prefix, EFAULT
//! only when nothing transferred, and supplies untouched anonymous pages.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod common;

use carrick_conformance_next::ResultAssert;

fn selected_probe_target() -> &'static str {
    let closure_mode = std::env::var("CARRICK_PROBE_MODE").as_deref() == Ok("closure");
    let libc = std::env::var("CARRICK_PROBE_SCENARIO_LIBC").ok();
    if !closure_mode {
        return "aarch64-unknown-linux-musl";
    }
    match libc.as_deref() {
        Some("musl") => "aarch64-unknown-linux-musl",
        Some("gnu") => "aarch64-unknown-linux-gnu",
        Some(value) => {
            panic!("invalid CARRICK_PROBE_SCENARIO_LIBC={value:?}; expected musl or gnu")
        }
        None => panic!("closure native prefix scenario requires CARRICK_PROBE_SCENARIO_LIBC"),
    }
}

#[test]
fn case_native_prefix_write_child_inherited_file() {
    let _guard = common::guest_lock();
    let root = common::repo_root();
    let dir = root
        .join("conformance-probes/target")
        .join(selected_probe_target())
        .join("release");
    let binary = dir.join("nativeprefixwrite");
    let init = dir.join("probeinit");
    assert!(
        binary.is_file() && init.is_file(),
        "missing native prefix probe: {} — run scripts/build-probes.sh",
        binary.display()
    );
    let output = tempfile::TempDir::new().unwrap();
    let container = common::generic_probe_container("nativeprefixwrite", &binary, &init)
        .mount(output.path().display().to_string(), "/out");
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
            "prefix_write_ret=16\n",
            "prefix_write_errno=0\n",
            "prefix_writev_ret=5\n",
            "prefix_writev_errno=0\n",
            "unreadable_write_ret=-1\n",
            "unreadable_write_errno=14\n",
            "untouched_write_ret=4096\n",
            "untouched_write_errno=0\n",
            "child_exit=0\n",
            "child_signal=none\n",
            "child_timeout=false\n",
            "prefix_write_size=16\n",
            "prefix_writev_size=5\n",
            "unreadable_write_size=0\n",
            "untouched_write_size=4096\n",
        ),
        "stderr:\n{}",
        result.stderr_utf8()
    );
    assert!(result.stderr.is_empty(), "{}", result.stderr_utf8());

    let read = |name: &str| std::fs::read(output.path().join(name)).unwrap();
    assert_eq!(read("prefix_write"), b"0123456789abcdef");
    assert_eq!(read("prefix_writev"), b"hello");
    assert_eq!(read("unreadable_write"), b"");
    assert_eq!(read("untouched_write"), vec![0u8; 4096]);
}
