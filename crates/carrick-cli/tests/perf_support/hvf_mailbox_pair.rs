use super::backend_pair::ArtifactIdentity;
use super::provenance::HostFacts;
use super::stats::{RatioInterval, Summary, bootstrap_median_ratio, summarize};
use serde::Serialize;
use std::io::Write;
use std::path::Path;
use std::time::Duration;

pub const BOOTSTRAP_SEED: u64 = 5_634_344_305_327_363_654;
pub const BOOTSTRAP_RESAMPLES: usize = 10_000;
pub const FULL_WARMUP_BLOCKS: usize = 10;
pub const FULL_SAMPLE_BLOCKS: usize = 30;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum HvfSyscallTransport {
    Legacy,
    Mailbox,
}

impl HvfSyscallTransport {
    pub const fn env_value(self) -> &'static str {
        match self {
            Self::Legacy => "legacy",
            Self::Mailbox => "mailbox",
        }
    }
}

pub const TRANSPORT_PAIR_ORDER: [HvfSyscallTransport; 4] = [
    HvfSyscallTransport::Legacy,
    HvfSyscallTransport::Mailbox,
    HvfSyscallTransport::Mailbox,
    HvfSyscallTransport::Legacy,
];

#[derive(Debug, PartialEq)]
pub struct TransportPairSamples {
    pub legacy: Vec<f64>,
    pub mailbox: Vec<f64>,
}

pub fn collect_transport_pair<F>(
    blocks: usize,
    cooldown: Duration,
    mut run: F,
) -> Result<TransportPairSamples, String>
where
    F: FnMut(HvfSyscallTransport) -> Result<f64, String>,
{
    let mut samples = TransportPairSamples {
        legacy: Vec::with_capacity(blocks.saturating_mul(2)),
        mailbox: Vec::with_capacity(blocks.saturating_mul(2)),
    };
    for _ in 0..blocks {
        for transport in TRANSPORT_PAIR_ORDER {
            let result = run(transport);
            std::thread::sleep(cooldown);
            let value = result?;
            match transport {
                HvfSyscallTransport::Legacy => samples.legacy.push(value),
                HvfSyscallTransport::Mailbox => samples.mailbox.push(value),
            }
        }
    }
    if samples.legacy.len() < 2 || samples.mailbox.len() < 2 {
        return Err(format!(
            "too few samples: legacy={} mailbox={} (need at least 2 each)",
            samples.legacy.len(),
            samples.mailbox.len()
        ));
    }
    Ok(samples)
}

#[derive(Debug, Clone, Copy, PartialEq, Serialize)]
pub struct Threshold {
    pub max_estimate: Option<f64>,
    pub max_upper: f64,
    pub upper_must_be_strict: bool,
}

pub fn threshold_for(workload: &str) -> Option<Threshold> {
    match workload {
        "trap_floor" => Some(Threshold {
            max_estimate: Some(0.90),
            max_upper: 1.0,
            upper_must_be_strict: true,
        }),
        "stdio_burst" | "writev_burst" => Some(Threshold {
            max_estimate: None,
            max_upper: 1.0,
            upper_must_be_strict: true,
        }),
        "wait_pipe_pingpong" | "epoll_pipe_loop" | "direct_compute" => Some(Threshold {
            max_estimate: None,
            max_upper: 1.02,
            upper_must_be_strict: false,
        }),
        "fork" | "fork_exec" => Some(Threshold {
            max_estimate: None,
            max_upper: 1.05,
            upper_must_be_strict: false,
        }),
        _ => None,
    }
}

pub const SELECTED_WORKLOADS: &[&str] = &[
    "trap_floor",
    "stdio_burst",
    "writev_burst",
    "wait_pipe_pingpong",
    "epoll_pipe_loop",
    "direct_compute",
    "fork",
    "fork_exec",
];

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ThresholdVerdict {
    Pass,
    Fail,
}

pub fn threshold_verdict(ratio: RatioInterval, threshold: Threshold) -> ThresholdVerdict {
    let estimate_ok = threshold
        .max_estimate
        .is_none_or(|maximum| ratio.estimate <= maximum);
    let upper_ok = if threshold.upper_must_be_strict {
        ratio.upper < threshold.max_upper
    } else {
        ratio.upper <= threshold.max_upper
    };
    if estimate_ok && upper_ok {
        ThresholdVerdict::Pass
    } else {
        ThresholdVerdict::Fail
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct TransportRun {
    pub schema: u32,
    pub epoch_secs: u64,
    pub schedule: [HvfSyscallTransport; 4],
    pub warmup_blocks: usize,
    pub sample_blocks: usize,
    pub samples_per_transport: usize,
    pub cooldown_secs: u64,
    pub bootstrap_seed: u64,
    pub bootstrap_resamples: usize,
    pub git_sha: Option<String>,
    pub git_dirty: bool,
    pub carrick: ArtifactIdentity,
    pub codesign: Option<String>,
    pub power_source: Option<String>,
    pub host: HostFacts,
}

#[derive(Debug, Clone, Serialize)]
pub struct TransportMeasurement {
    pub workload: String,
    pub transport: HvfSyscallTransport,
    pub artifact: ArtifactIdentity,
    pub metric: String,
    pub unit: String,
    pub samples: Vec<f64>,
    pub summary: Summary,
}

#[derive(Debug, Clone, Serialize)]
pub struct TransportComparison {
    pub workload: String,
    pub metric: String,
    pub unit: String,
    pub ratio_numerator: &'static str,
    pub ratio_denominator: &'static str,
    pub legacy: Summary,
    pub mailbox: Summary,
    pub ratio: RatioInterval,
    pub threshold: Threshold,
    pub verdict: ThresholdVerdict,
}

pub fn comparison_row(
    workload: &str,
    metric: &str,
    unit: &str,
    legacy: &[f64],
    mailbox: &[f64],
) -> Option<TransportComparison> {
    let threshold = threshold_for(workload)?;
    let ratio = bootstrap_median_ratio(legacy, mailbox, BOOTSTRAP_SEED, BOOTSTRAP_RESAMPLES)?;
    Some(TransportComparison {
        workload: workload.to_owned(),
        metric: metric.to_owned(),
        unit: unit.to_owned(),
        ratio_numerator: "mailbox",
        ratio_denominator: "legacy",
        legacy: summarize(legacy)?,
        mailbox: summarize(mailbox)?,
        ratio,
        threshold,
        verdict: threshold_verdict(ratio, threshold),
    })
}

#[derive(Debug, Clone, Serialize)]
pub struct TransportInvalid {
    pub workload: String,
    pub reason: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum TransportEvidenceRow {
    Run(TransportRun),
    BoundaryMeasurement(TransportMeasurement),
    EndToEndMeasurement(TransportMeasurement),
    Comparison(TransportComparison),
    Invalid(TransportInvalid),
}

pub fn write_transport_rows_atomic(
    path: &Path,
    rows: &[TransportEvidenceRow],
) -> std::io::Result<()> {
    let tmp = path.with_extension("jsonl.tmp");
    let mut file = std::fs::File::create(&tmp)?;
    for row in rows {
        serde_json::to_writer(&mut file, row).map_err(std::io::Error::other)?;
        writeln!(file)?;
    }
    file.sync_all()?;
    std::fs::rename(tmp, path)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn transport_pair_schedule_is_fixed_abba() {
        assert_eq!(
            TRANSPORT_PAIR_ORDER,
            [
                HvfSyscallTransport::Legacy,
                HvfSyscallTransport::Mailbox,
                HvfSyscallTransport::Mailbox,
                HvfSyscallTransport::Legacy,
            ]
        );
    }

    #[test]
    fn full_profile_has_twenty_warmups_and_sixty_samples_per_mode() {
        assert_eq!(FULL_WARMUP_BLOCKS * 2, 20);
        assert_eq!(FULL_SAMPLE_BLOCKS * 2, 60);
        assert_eq!(BOOTSTRAP_SEED, 5_634_344_305_327_363_654);
        assert_eq!(BOOTSTRAP_RESAMPLES, 10_000);
    }

    #[test]
    fn collector_balances_complete_blocks() {
        let mut seen = Vec::new();
        let samples = collect_transport_pair(2, Duration::ZERO, |transport| {
            seen.push(transport);
            Ok(1.0)
        })
        .expect("samples");
        assert_eq!(seen, TRANSPORT_PAIR_ORDER.repeat(2));
        assert_eq!(samples.legacy.len(), 4);
        assert_eq!(samples.mailbox.len(), 4);
    }

    #[test]
    fn collector_rejects_incomplete_evidence() {
        assert!(collect_transport_pair(0, Duration::ZERO, |_| Ok(1.0)).is_err());
        let mut legs = 0;
        let error = collect_transport_pair(2, Duration::ZERO, |_| {
            legs += 1;
            if legs == 3 {
                Err("sample crashed".to_owned())
            } else {
                Ok(1.0)
            }
        })
        .expect_err("a crashed leg invalidates the campaign");
        assert!(error.contains("sample crashed"));
    }

    #[test]
    fn thresholds_are_frozen_by_workload_shape() {
        let clear_win = RatioInterval {
            estimate: 0.85,
            lower: 0.82,
            upper: 0.92,
            resamples: BOOTSTRAP_RESAMPLES,
        };
        let ambiguous = RatioInterval {
            estimate: 0.89,
            lower: 0.82,
            upper: 1.0,
            resamples: BOOTSTRAP_RESAMPLES,
        };
        assert_eq!(
            threshold_verdict(clear_win, threshold_for("trap_floor").expect("threshold")),
            ThresholdVerdict::Pass
        );
        assert_eq!(
            threshold_verdict(ambiguous, threshold_for("trap_floor").expect("threshold")),
            ThresholdVerdict::Fail
        );
        assert_eq!(threshold_for("fork").expect("fork").max_upper, 1.05);
    }

    #[test]
    fn comparison_is_mailbox_over_legacy() {
        let row = comparison_row(
            "trap_floor",
            "trap_p50_us",
            "us",
            &[2.0, 2.1, 2.2],
            &[1.0, 1.1, 1.2],
        )
        .expect("comparison");
        assert!(row.ratio.estimate < 0.90);
        assert_eq!(row.ratio_numerator, "mailbox");
        assert_eq!(row.ratio_denominator, "legacy");
        assert_eq!(row.verdict, ThresholdVerdict::Pass);
    }

    #[test]
    fn selected_cases_cover_boundary_bursts_waits_compute_and_processes() {
        for workload in [
            "trap_floor",
            "stdio_burst",
            "writev_burst",
            "wait_pipe_pingpong",
            "epoll_pipe_loop",
            "direct_compute",
            "fork",
            "fork_exec",
        ] {
            assert!(SELECTED_WORKLOADS.contains(&workload));
        }
    }

    #[test]
    fn evidence_schema_names_boundary_and_end_to_end_rows() {
        let measurement = TransportMeasurement {
            workload: "trap_floor".to_owned(),
            transport: HvfSyscallTransport::Mailbox,
            artifact: ArtifactIdentity::file("probe", "abc"),
            metric: "trap_p50_us".to_owned(),
            unit: "us".to_owned(),
            samples: vec![1.0],
            summary: summarize(&[1.0]).expect("summary"),
        };
        let boundary = serde_json::to_string(&TransportEvidenceRow::BoundaryMeasurement(
            measurement.clone(),
        ))
        .expect("serialize");
        let end_to_end =
            serde_json::to_string(&TransportEvidenceRow::EndToEndMeasurement(measurement))
                .expect("serialize");
        assert!(boundary.contains("\"kind\":\"boundary_measurement\""));
        assert!(end_to_end.contains("\"kind\":\"end_to_end_measurement\""));
    }
}
