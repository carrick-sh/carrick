//! Negative control for the signed test recipe: on an executable WITHOUT the
//! hypervisor entitlement, the first guest launch must surface as
//! `EmbedError::Entitlement`.
//!
//! `#[ignore]`d so the signed test pass skips it. scripts/test-signed.sh looks
//! this test up by name and runs it with `--ignored --exact` on the unentitled copy.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use carrick_conformance_next::{ContainerBuilder, EmbedError, PullPolicy};

#[test]
#[ignore = "negative control: scripts/test-signed.sh runs it on an UNENTITLED copy of this executable"]
fn unsigned_executable_maps_hv_denied_to_entitlement() {
    let _guard = common::guest_lock();
    let outcome = ContainerBuilder::from_image(common::SMOKE_IMAGE)
        .pull_policy(PullPolicy::Missing)
        .command(["/bin/true"])
        .run_blocking();
    match outcome {
        Err(EmbedError::Entitlement) => {}
        Err(other) => {
            panic!("expected EmbedError::Entitlement from an unentitled executable, got: {other}")
        }
        Ok(result) => panic!(
            "an unentitled executable ran a guest (exit {}): this process IS entitled, \
             so the negative control proves nothing",
            result.exit_code
        ),
    }
}
