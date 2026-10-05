//! Signed lifecycle proof for the watchdog's current-carrier scope provider.
#![cfg(feature = "test-support")]
mod common;

use std::time::Duration;

use carrick_embed::Carrier;
use carrick_image::PullPolicy;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[allow(clippy::await_holding_lock)]
async fn successive_live_carriers_publish_and_retire_their_capture_scope() {
    let _guest = common::guest_lock();
    let mut previous_generation = None;
    for _ in 0..2 {
        let carrier = Carrier::new().expect("new carrier");
        let generation = carrick_embed::testing::carrier_snapshot(&carrier)
            .expect("new generation snapshot")
            .generation;
        assert_ne!(previous_generation, Some(generation));
        let scope = carrick_runtime::carrier::active_carrier_scope().expect("active scope");
        let result = tokio::time::timeout(
            Duration::from_secs(30),
            carrier
                .container(common::SMOKE_IMAGE)
                .pull_policy(PullPolicy::Missing)
                .command(["/bin/true"])
                .run(),
        )
        .await
        .expect("bounded guest completion")
        .expect("guest runtime");
        assert_eq!(result.exit_code, 0);
        assert_eq!(
            carrick_runtime::carrier::active_carrier_scope(),
            Some(scope)
        );
        tokio::time::timeout(Duration::from_secs(30), carrier.shutdown())
            .await
            .expect("bounded carrier teardown")
            .expect("complete carrier teardown");
        assert!(carrick_runtime::carrier::active_carrier_scope().is_none());
        previous_generation = Some(generation);
    }
}
