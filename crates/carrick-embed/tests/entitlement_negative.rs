//! Negative control for the signed test recipe: on an executable WITHOUT the
//! hypervisor entitlement (a bare `cargo test` binary, or the ad-hoc-resigned
//! copy scripts/test-signed.sh makes), the first guest launch must surface as
//! `EmbedError::Entitlement` — never as a generic runtime failure, and never
//! as a skip.
//!
//! `#[ignore]`d so the SIGNED pass skips it (there it would fail: the guest
//! simply runs). scripts/test-signed.sh looks this test up by name and runs it
//! with `--ignored --exact` on the unentitled copy.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use carrick_embed::{ContainerBuilder, EmbedError};
use carrick_image::PullPolicy;

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
