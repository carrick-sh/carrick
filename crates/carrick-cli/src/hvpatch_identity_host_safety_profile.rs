//! Strict reader for the HVPatch guest-identity host-safety DTrace protocol.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::Path;

use anyhow::{Context, Result, anyhow, bail};

use crate::trace_profile::ProfileCaptureStatus;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct HvpatchIdentityHostSafetySummary {
    pub(crate) guest_kills: u64,
    pub(crate) stop_signals: u64,
    pub(crate) continue_signals: u64,
    pub(crate) host_low_kills: u64,
}

impl HvpatchIdentityHostSafetySummary {
    pub(crate) fn from_path(path: &Path, status: ProfileCaptureStatus) -> Result<Self> {
        let contents = fs::read_to_string(path)
            .with_context(|| format!("read HVPatch identity safety stream {}", path.display()))?;
        Self::from_lines(contents.lines(), status)
    }

    fn from_lines<I, S>(lines: I, status: ProfileCaptureStatus) -> Result<Self>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        require_lossless(status)?;
        let mut header_seen = false;
        let mut summary = None;
        for raw in lines {
            let line = raw.as_ref();
            if line.is_empty() {
                continue;
            }
            let record = Record::parse(line)?;
            match record.tag.as_str() {
                "header" => {
                    record.exact_fields(&["version"])?;
                    if header_seen || record.u64("version")? != 1 {
                        bail!("duplicate or unsupported HVPATCHIDENTITY1 header");
                    }
                    header_seen = true;
                }
                "host-kill" => {
                    bail!("HVPatch guest selector reached Darwin kill: {line}");
                }
                "summary" => {
                    if !header_seen || summary.is_some() {
                        bail!("missing header or duplicate HVPATCHIDENTITY1 summary");
                    }
                    summary = Some(record);
                }
                other => bail!("unknown HVPATCHIDENTITY1 record tag {other:?}"),
            }
        }
        if !header_seen {
            bail!("HVPATCHIDENTITY1 stream has no header");
        }
        let record = summary.ok_or_else(|| anyhow!("HVPATCHIDENTITY1 stream has no summary"))?;
        record.exact_fields(&[
            "status",
            "guest_kills",
            "positive_one",
            "zero",
            "broadcast",
            "negative_group",
            "tgkills",
            "xsig_shapes",
            "stop_signals",
            "continue_signals",
            "host_low_kills",
            "bounded",
            "errors",
            "drops",
            "target_exited",
            "target_exit_seen",
            "target_exit_code",
            "target_exit_reason",
        ])?;
        let guest_kills = record.u64("guest_kills")?;
        let stop_signals = record.u64("stop_signals")?;
        let continue_signals = record.u64("continue_signals")?;
        let host_low_kills = record.u64("host_low_kills")?;
        let valid = record.value("status")? == "ok"
            && guest_kills > 0
            && record.u64("positive_one")? > 0
            && record.u64("zero")? > 0
            && record.u64("broadcast")? > 0
            && record.u64("negative_group")? > 0
            && record.u64("tgkills")? > 0
            && record.u64("xsig_shapes")? > 0
            && stop_signals >= 3
            && continue_signals > 0
            && host_low_kills == 0
            && record.u64("bounded")? == 0
            && record.u64("errors")? == 0
            && record.u64("drops")? == 0
            && record.u64("target_exited")? == 1
            && record.u64("target_exit_seen")? == 1
            && record.u64("target_exit_code")? == 0;
        let _ = record.u64("target_exit_reason")?;
        if !valid {
            bail!("HVPATCHIDENTITY1 summary is incomplete or unsafe");
        }
        Ok(Self {
            guest_kills,
            stop_signals,
            continue_signals,
            host_low_kills,
        })
    }

    pub(crate) fn render_human(self) -> String {
        format!(
            "HVPatch identity host safety: guest_kills={}, guest_sigstops={}, guest_sigconts={}, low_guest_id_host_kills={}",
            self.guest_kills, self.stop_signals, self.continue_signals, self.host_low_kills
        )
    }
}

#[derive(Debug)]
struct Record {
    tag: String,
    fields: BTreeMap<String, String>,
}

impl Record {
    fn parse(line: &str) -> Result<Self> {
        let mut parts = line.split('|');
        if parts.next() != Some("HVPATCHIDENTITY1") {
            bail!("unknown HVPATCHIDENTITY1 protocol prefix in {line:?}");
        }
        let tag = parts
            .next()
            .filter(|tag| !tag.is_empty())
            .ok_or_else(|| anyhow!("truncated HVPATCHIDENTITY1 record"))?
            .to_owned();
        let mut fields = BTreeMap::new();
        for raw in parts {
            let (key, value) = raw
                .split_once('=')
                .ok_or_else(|| anyhow!("HVPATCHIDENTITY1 field lacks '=': {raw:?}"))?;
            if key.is_empty()
                || value.is_empty()
                || fields.insert(key.to_owned(), value.to_owned()).is_some()
            {
                bail!("empty or duplicate HVPATCHIDENTITY1 field {key:?}");
            }
        }
        Ok(Self { tag, fields })
    }

    fn exact_fields(&self, expected: &[&str]) -> Result<()> {
        let actual = self
            .fields
            .keys()
            .map(String::as_str)
            .collect::<BTreeSet<_>>();
        let expected = expected.iter().copied().collect::<BTreeSet<_>>();
        if actual != expected {
            bail!("HVPATCHIDENTITY1 {:?} field contract mismatch", self.tag);
        }
        Ok(())
    }

    fn value(&self, name: &str) -> Result<&str> {
        self.fields
            .get(name)
            .map(String::as_str)
            .ok_or_else(|| anyhow!("HVPATCHIDENTITY1 {:?} lacks {name:?}", self.tag))
    }

    fn u64(&self, name: &str) -> Result<u64> {
        let value = self.value(name)?;
        if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) {
            bail!("HVPATCHIDENTITY1 {name:?} is not unsigned decimal");
        }
        value
            .parse()
            .with_context(|| format!("HVPATCHIDENTITY1 {name:?} exceeds u64"))
    }
}

fn require_lossless(status: ProfileCaptureStatus) -> Result<()> {
    if status.principal_drops != 0
        || status.aggregation_drops != 0
        || status.dynamic_drops != 0
        || status.dynamic_rinse_drops != 0
        || status.dynamic_dirty_drops != 0
        || status.other_drops != 0
        || status.interrupted
    {
        bail!("HVPATCHIDENTITY1 capture is lossy or interrupted");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::HvpatchIdentityHostSafetySummary;
    use crate::trace_profile::ProfileCaptureStatus;

    const HEADER: &str = "HVPATCHIDENTITY1|header|version=1";
    const VALID: &str = "HVPATCHIDENTITY1|summary|status=ok|guest_kills=10|positive_one=1|zero=1|broadcast=2|negative_group=1|tgkills=2|xsig_shapes=1|stop_signals=3|continue_signals=1|host_low_kills=0|bounded=0|errors=0|drops=0|target_exited=1|target_exit_seen=1|target_exit_code=0|target_exit_reason=1";

    #[test]
    fn accepts_complete_lossless_host_safe_stream() {
        let summary = HvpatchIdentityHostSafetySummary::from_lines(
            [HEADER, VALID],
            ProfileCaptureStatus::default(),
        )
        .expect("complete host-safety stream");
        assert_eq!(summary.guest_kills, 10);
        assert_eq!(summary.stop_signals, 3);
        assert_eq!(summary.continue_signals, 1);
        assert_eq!(summary.host_low_kills, 0);
    }

    #[test]
    fn rejects_host_escape_missing_selector_and_lossy_capture() {
        for line in [
            VALID.replace("host_low_kills=0", "host_low_kills=1"),
            VALID.replace("negative_group=1", "negative_group=0"),
            VALID.replace("stop_signals=3", "stop_signals=2"),
            VALID.replace("continue_signals=1", "continue_signals=0"),
        ] {
            assert!(
                HvpatchIdentityHostSafetySummary::from_lines(
                    [HEADER, line.as_str()],
                    ProfileCaptureStatus::default(),
                )
                .is_err()
            );
        }
        assert!(
            HvpatchIdentityHostSafetySummary::from_lines(
                [HEADER, VALID],
                ProfileCaptureStatus {
                    principal_drops: 1,
                    ..ProfileCaptureStatus::default()
                },
            )
            .is_err()
        );
    }
}
