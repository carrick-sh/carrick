//! Signed execution binding for kernel.fs.write-seek alias ownership.
//! Oracle: native ARM64 Docker, writeseek lease-alias, same executable.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use carrick_conformance_next::{PullPolicy, TestContainer};

#[test]
fn write_seek_lease_alias_preserves_shared_offset() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(2)
        .unwrap();
    let binary =
        root.join("conformance-probes/target/aarch64-unknown-linux-musl/release/writeseek");
    assert!(binary.is_file(), "fresh writeseek executable required");
    let result = TestContainer::new(
        "localhost:5050/ltp@sha256:bc75ded40c5827f2ec9e1891edc23b988beae3f428f5be2c8fd7e3ee52fee80b")
        .pull_policy(PullPolicy::Missing)
        .mount_readonly(binary.display().to_string(), "/probe")
        .run(["/bin/sh", "-c", "/probe lease-alias"])
        .expect("signed lease alias execution")
        .ensure_success().expect("lease alias probe exit status");
    assert_eq!(
        result.stdout_utf8().trim(),
        "alias_write=1\nshared_offset=1\nread=1\nbyte=120",
        "Linux shared-offset authority; stderr={}",
        result.stderr_utf8()
    );
}
