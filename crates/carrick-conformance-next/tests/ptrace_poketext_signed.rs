//! Entitled HVPatch acceptance for warm RX PTRACE_POKETEXT publication.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use carrick_conformance_next::{PullPolicy, TestContainer};

#[test]
#[ignore = "requires a signed HVF test executable and prebuilt aarch64-musl probes"]
fn production_rx_poketext_executes_warm_patched_instruction() {
    let _guard = common::guest_lock();
    let root = common::repo_root();
    let probe_dir = root.join("conformance-probes/target/aarch64-unknown-linux-musl/release");
    let probe = probe_dir.join("ptracepoketext");
    assert!(probe.is_file(), "build probes first: {}", probe.display());

    // Start from the image's ordinary shell (the already-shipped signed embed
    // acceptance path), then copy the read-only payload into the guest tmpfs.
    // This avoids depending on the separately-known generic-probe direct host-
    // executable mount startup failure while still executing the exact static
    // probe under the production HVPatch carrier.
    let container = TestContainer::new(common::SMOKE_IMAGE)
        .pull_policy(PullPolicy::Missing)
        .mount_readonly(probe.display().to_string(), "/tmp/ptracepoketext.payload");
    let outcome = common::with_empty_stdin_pipe(|| {
        container.run([
            "/bin/sh",
            "-c",
            "cp /tmp/ptracepoketext.payload /tmp/ptracepoketext && chmod 755 /tmp/ptracepoketext && exec /tmp/ptracepoketext",
        ])
    });
    let result = common::run_named_or_fail("warm RX PTRACE_POKETEXT", outcome);
    assert_eq!(result.exit_code, 0);
    let mut output = String::from_utf8_lossy(&result.stdout).into_owned();
    output.push_str(&String::from_utf8_lossy(&result.stderr));
    for proof in [
        "warm_42=true",
        "patch_43_ok=true",
        "executed_43=true",
        "patch_44_ok=true",
        "executed_44=true",
        "peer_remains_42=true",
        "guest_store_faulted=true",
    ] {
        assert!(output.contains(proof), "missing {proof:?} in:\n{output}");
    }
}
