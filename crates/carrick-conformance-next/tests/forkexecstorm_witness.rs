//! Gate the probe harness's ready-child-before-deadline contract in-process.
//! scripts/test-signed.sh builds and identifies the Linux Rust test executable.
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use carrick_abi::{NsGid, NsUid};
use carrick_conformance_next::{PullPolicy, ResultAssert, TestContainer};
use carrick_embed::InMemoryFileVfs;
use sha2::{Digest, Sha256};

const WITNESS: &str = "tests::test_bounded_reap_attempts_ready_child_at_expired_deadline";

#[test]
fn case_forkexecstorm_ready_child_at_expired_deadline() {
    let _guard = common::guest_lock();
    let fixture = common::repo_root().join("target/embed-fixtures/forkexecstorm-witness-aarch64");
    let bytes = std::fs::read(&fixture).expect("signed runner must build the witness executable");
    let identity: serde_json::Value = serde_json::from_slice(
        &std::fs::read(fixture.with_extension("json"))
            .expect("signed runner must identify the witness executable"),
    )
    .expect("witness identity must be JSON");
    assert_eq!(identity["schema"], "forkexecstorm-witness-v1");
    assert_eq!(identity["target"], "aarch64-unknown-linux-musl");
    assert_eq!(
        identity["elf_sha256"],
        format!("{:x}", Sha256::digest(&bytes))
    );
    for (path, source) in [
        (
            "src/bin/forkexecstorm.rs",
            include_bytes!("../../../conformance-probes/src/bin/forkexecstorm.rs").as_slice(),
        ),
        (
            "src/lib.rs",
            include_bytes!("../../../conformance-probes/src/lib.rs").as_slice(),
        ),
        (
            "Cargo.toml",
            include_bytes!("../../../conformance-probes/Cargo.toml").as_slice(),
        ),
        (
            "Cargo.lock",
            include_bytes!("../../../conformance-probes/Cargo.lock").as_slice(),
        ),
    ] {
        assert_eq!(
            identity["sources"][path],
            format!("{:x}", Sha256::digest(source)),
            "witness source identity mismatch: {path}"
        );
    }
    eprintln!("forkexecstorm witness identity: {identity}; test={WITNESS}");
    // Execute exactly the bytes whose digest was checked, not a mutable bind.
    let vfs = InMemoryFileVfs::new();
    vfs.add_file_with_metadata(
        "/opt/carrick/forkexecstorm-witness",
        bytes,
        0o755,
        NsUid::ROOT,
        NsGid::ROOT,
        0,
    )
    .expect("install identified witness");
    let container = TestContainer::new(common::SMOKE_IMAGE).pull_policy(PullPolicy::Missing);
    let command = format!(
        "/opt/carrick/forkexecstorm-witness --exact {WITNESS} --nocapture --test-threads=1"
    );
    let result = common::run_or_fail(
        container
            .builder(["/bin/sh", "-c", &command])
            .vfs_mount("/opt/carrick", Box::new(vfs))
            .run_blocking(),
    );
    result.assert_success();
    assert!(
        result
            .stdout_utf8()
            .contains(&format!("test {WITNESS} ... ok"))
    );
    assert!(result.stdout_utf8().contains("1 passed; 0 failed;"));
}
