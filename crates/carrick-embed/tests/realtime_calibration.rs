//! Signed binding for kernel.time.realtime-calibration. Run through
//! scripts/test-signed.sh with CARRICK_INSECURE_REGISTRIES=localhost:5050.
//! The immutable LTP image contains clock_gettime04 (LTP 20260529), executable
//! SHA-256 11f6edf3c9f5f08215658f8b0f128896114210045ed71e497f3e1cfcaededb6f.
#![allow(clippy::expect_used)]

use carrick_embed::{ContainerBuilder, StdioConfig};
use carrick_image::PullPolicy;

const IMAGE: &str =
    "localhost:5050/ltp@sha256:bc75ded40c5827f2ec9e1891edc23b988beae3f428f5be2c8fd7e3ee52fee80b";

#[test]
fn realtime_calibration_survives_sibling_exec() {
    for scale in [1, 8, 32, 128] {
        let script = format!(
            "(i=0; while test \"$i\" -lt {scale}; do /bin/true || exit 1; i=$((i+1)); done) & \
             churn=$!; status=0; i=0; while test \"$i\" -lt 10; do \
             /opt/ltp/testcases/bin/clock_gettime04 || status=1; i=$((i+1)); done; \
             wait \"$churn\" || status=1; exit \"$status\""
        );
        let result = ContainerBuilder::from_image(IMAGE)
            .pull_policy(PullPolicy::Missing)
            .command(["/bin/sh", "-c", &script])
            .stdout(StdioConfig::Captured)
            .stderr(StdioConfig::Captured)
            .run_blocking()
            .expect("signed LTP fixture must execute; entitlement/setup errors are failures");
        let transcript = format!("{}{}", result.stdout_utf8(), result.stderr_utf8());
        assert!(result.success(), "scale={scale}: {transcript}");
        assert_eq!(
            transcript.matches("TPASS:").count(),
            60,
            "scale={scale}: {transcript}"
        );
        assert!(
            !transcript.contains("TFAIL:"),
            "scale={scale}: {transcript}"
        );
        assert!(
            !transcript.contains("TBROK:"),
            "scale={scale}: {transcript}"
        );
        assert!(
            !transcript.contains("TCONF:"),
            "scale={scale}: {transcript}"
        );
    }
}
