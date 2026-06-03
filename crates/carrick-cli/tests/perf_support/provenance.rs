//! Provenance capture and the append-only JSONL result row. Every row stamps
//! enough host/build/image context to make runs comparable across machines and
//! over time (the reusable-baseline requirement). Capture functions shell out to
//! `sysctl`/`sw_vers`/`git`/`docker`; all are best-effort (None on failure) so a
//! row is still written when an optional fact is unavailable.
use std::process::Command;
use super::stats::Summary;

fn cmd_stdout(program: &str, args: &[&str]) -> Option<String> {
    let out = Command::new(program).args(args).output().ok()?;
    if !out.status.success() {
        return None;
    }
    let s = String::from_utf8_lossy(&out.stdout).trim().to_string();
    if s.is_empty() { None } else { Some(s) }
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct HostFacts {
    pub model: Option<String>,
    pub perf_cores: Option<String>,
    pub eff_cores: Option<String>,
    pub macos: Option<String>,
    pub docker_version: Option<String>,
}

impl HostFacts {
    pub fn capture() -> Self {
        HostFacts {
            model: cmd_stdout("sysctl", &["-n", "hw.model"]),
            perf_cores: cmd_stdout("sysctl", &["-n", "hw.perflevel0.logicalcpu"]),
            eff_cores: cmd_stdout("sysctl", &["-n", "hw.perflevel1.logicalcpu"]),
            macos: cmd_stdout("sw_vers", &["-productVersion"]),
            docker_version: cmd_stdout("docker", &["version", "--format", "{{.Server.Version}}"]),
        }
    }
}

/// OCI digest of the pinned image, e.g. ubuntu:24.04 -> sha256:...
pub fn image_digest(image: &str) -> Option<String> {
    cmd_stdout("docker", &["image", "inspect", "--format", "{{index .RepoDigests 0}}", image])
}

pub fn git_sha() -> Option<String> {
    cmd_stdout("git", &["rev-parse", "HEAD"])
}

/// Seconds since the Unix epoch (avoids a chrono dep; the date is enough to
/// order rows and the filename carries the calendar day).
pub fn epoch_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// One appended line of the result store. `engine` is "carrick"|"docker";
/// `lane` is the carrick timing lane ("cold"|"warm"|"docker"); for Phase 0 the
/// carrick lane is "cold".
#[derive(Debug, Clone, serde::Serialize)]
pub struct ResultRow {
    pub schema: u32,
    pub epoch_secs: u64,
    pub dimension: String,
    pub workload: String,
    pub engine: String,
    pub lane: String,
    pub metric: String,
    pub unit: String,
    pub summary: Summary,
    pub samples: Vec<f64>,
    pub noisy: bool,
    pub nproc: Option<u64>,
    pub cpu_pin: u32,
    pub fs_mode: String,
    pub image: String,
    pub image_digest: Option<String>,
    pub git_sha: Option<String>,
    pub run_id: String,
    pub host: HostFacts,
}

/// Append a row as one JSON line to `docs/perf-results/<date>-<dim>.jsonl`.
pub fn append_row(repo_root: &std::path::Path, date: &str, row: &ResultRow) -> std::io::Result<()> {
    use std::io::Write;
    let dir = repo_root.join("docs/perf-results");
    std::fs::create_dir_all(&dir)?;
    let path = dir.join(format!("{date}-{}.jsonl", row.dimension));
    let mut f = std::fs::OpenOptions::new().create(true).append(true).open(path)?;
    let line = serde_json::to_string(row).map_err(std::io::Error::other)?;
    writeln!(f, "{line}")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fake_row() -> ResultRow {
        ResultRow {
            schema: 1,
            epoch_secs: 1_700_000_000,
            dimension: "network".into(),
            workload: "tcp_rr".into(),
            engine: "carrick".into(),
            lane: "cold".into(),
            metric: "tcp_rr_p50_us".into(),
            unit: "us".into(),
            summary: Summary { p50: 8.4, p95: 14.0, min: 6.1, iqr: 1.2, n: 8 },
            samples: vec![8.4, 8.5, 8.3],
            noisy: false,
            nproc: Some(4),
            cpu_pin: 4,
            fs_mode: "host".into(),
            image: "ubuntu:24.04".into(),
            image_digest: Some("sha256:deadbeef".into()),
            git_sha: Some("abc123".into()),
            run_id: "cr-perf-1-0".into(),
            host: HostFacts {
                model: Some("Mac16,12".into()),
                perf_cores: Some("4".into()),
                eff_cores: Some("6".into()),
                macos: Some("26.6".into()),
                docker_version: Some("29.5.2".into()),
            },
        }
    }

    #[test]
    fn row_serializes_to_one_json_line() {
        let s = serde_json::to_string(&fake_row()).unwrap();
        assert!(!s.contains('\n'));
        assert!(s.contains("\"workload\":\"tcp_rr\""));
        assert!(s.contains("\"p50\":8.4"));
        assert!(s.contains("\"nproc\":4"));
    }

    #[test]
    fn append_writes_a_line() {
        let tmp = std::env::temp_dir().join(format!("perf-prov-{}", std::process::id()));
        std::fs::create_dir_all(&tmp).unwrap();
        append_row(&tmp, "2026-06-02", &fake_row()).unwrap();
        let body = std::fs::read_to_string(tmp.join("docs/perf-results/2026-06-02-network.jsonl")).unwrap();
        assert_eq!(body.lines().count(), 1);
        std::fs::remove_dir_all(&tmp).ok();
    }
}
