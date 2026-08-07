use std::collections::{BTreeMap, BTreeSet};

use anyhow::{Context as _, bail};

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct NativePerfEpochAuthority {
    pub(crate) process_epochs: BTreeSet<(i32, u64)>,
    pub(crate) pids: BTreeSet<i32>,
    pub(crate) threads: u64,
    pub(crate) all_thread_translations: u64,
    pub(crate) supervisor_total_cpu_ns: u64,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct ThreadKey {
    pid: i32,
    tid: i32,
    era: u64,
}

#[derive(Clone, Copy, Debug)]
struct CoreFrame {
    exec_epoch: u64,
}

#[derive(Default)]
struct ThreadGroup {
    frames: BTreeSet<String>,
    core: Option<CoreFrame>,
    translations: Option<u64>,
}

const RECOGNIZED_THREAD_FRAMES: &[&str] = &[
    "core",
    "exits",
    "sensitive",
    "fusion-exec-a",
    "fusion-exec-b",
    "fusion-sites-a",
    "fusion-sites-b",
    "phases-a",
    "phases-b",
    "resolver-thread",
    "resolver-process",
    "resolver-times",
    "resolver-shared",
    "resolver-metadata",
    "resolve-class",
    "direct-binding-gauge",
    "cache-gauge",
    "process",
];

impl NativePerfEpochAuthority {
    pub(crate) fn parse(text: &str) -> anyhow::Result<Self> {
        let mut groups = BTreeMap::<ThreadKey, ThreadGroup>::new();
        let mut supervisor = None;

        for (index, line) in text.lines().enumerate() {
            let line_number = index + 1;
            if !line.starts_with("NATIVEPERF1|") {
                continue;
            }
            let mut parts = line.split('|');
            if parts.next() != Some("NATIVEPERF1") {
                bail!("NATIVEPERF line {line_number}: invalid prefix");
            }
            match parts.next() {
                Some("invalid") => bail!("NATIVEPERF line {line_number}: invalid frame"),
                Some("supervisor") => {
                    if supervisor.is_some() {
                        bail!("NATIVEPERF line {line_number}: duplicate supervisor");
                    }
                    let fields = parse_fields(parts, line_number)?;
                    require_only_fields(
                        &fields,
                        &["self_cpu_ns", "children_cpu_ns"],
                        line_number,
                        "supervisor",
                    )?;
                    let self_cpu_ns = parse_u64(&fields, "self_cpu_ns", line_number)?;
                    let children_cpu_ns = parse_u64(&fields, "children_cpu_ns", line_number)?;
                    supervisor =
                        Some(self_cpu_ns.checked_add(children_cpu_ns).with_context(|| {
                            format!("NATIVEPERF line {line_number}: supervisor CPU overflow")
                        })?);
                }
                Some("thread") => {
                    let fields = parse_fields(parts, line_number)?;
                    if parse_u64(&fields, "complete", line_number)? != 1 {
                        bail!("NATIVEPERF line {line_number}: complete must be 1");
                    }
                    let key = ThreadKey {
                        pid: parse_i32(&fields, "pid", line_number)?,
                        tid: parse_i32(&fields, "tid", line_number)?,
                        era: parse_u64(&fields, "era", line_number)?,
                    };
                    let frame = required(&fields, "frame", line_number)?;
                    if !RECOGNIZED_THREAD_FRAMES.contains(&frame) {
                        bail!("NATIVEPERF line {line_number}: unknown thread frame {frame}");
                    }
                    let group = groups.entry(key).or_default();
                    if !group.frames.insert(frame.to_owned()) {
                        bail!("NATIVEPERF line {line_number}: duplicate {frame} frame");
                    }
                    match frame {
                        "core" => {
                            let gateway_entries =
                                parse_u64(&fields, "gateway_entries", line_number)?;
                            let reconciled_exits =
                                parse_u64(&fields, "reconciled_exits", line_number)?;
                            if gateway_entries != reconciled_exits {
                                bail!(
                                    "NATIVEPERF line {line_number}: gateway_entries does not match reconciled_exits"
                                );
                            }
                            if parse_u64(&fields, "overflowed", line_number)? != 0 {
                                bail!("NATIVEPERF line {line_number}: overflowed core");
                            }
                            let _thread_cpu_ns = parse_u64(&fields, "thread_cpu_ns", line_number)?;
                            group.core = Some(CoreFrame {
                                exec_epoch: parse_u64(&fields, "exec_epoch", line_number)?,
                            });
                        }
                        "resolver-process" => {
                            group.translations =
                                Some(parse_u64(&fields, "translations", line_number)?);
                        }
                        _ => {}
                    }
                }
                Some(kind) => bail!("NATIVEPERF line {line_number}: unknown record kind {kind}"),
                None => bail!("NATIVEPERF line {line_number}: missing record kind"),
            }
        }

        let supervisor_total_cpu_ns =
            supervisor.context("NATIVEPERF authority is missing supervisor")?;
        if groups.is_empty() {
            bail!("NATIVEPERF authority contains no thread groups");
        }
        let mut process_epochs = BTreeSet::new();
        let mut all_thread_translations = 0_u64;
        let mut threads = 0_u64;
        let mut group_epochs = Vec::with_capacity(groups.len());
        for (key, group) in groups {
            let core = group.core.with_context(|| {
                format!(
                    "NATIVEPERF group ({},{},{}) is missing core",
                    key.pid, key.tid, key.era
                )
            })?;
            let translations = group.translations.with_context(|| {
                format!(
                    "NATIVEPERF group ({},{},{}) is missing resolver-process",
                    key.pid, key.tid, key.era
                )
            })?;
            threads = threads
                .checked_add(1)
                .context("NATIVEPERF thread count overflow")?;
            all_thread_translations = all_thread_translations
                .checked_add(translations)
                .context("NATIVEPERF translations overflow")?;
            if key.tid == key.pid && !process_epochs.insert((key.pid, core.exec_epoch)) {
                bail!(
                    "NATIVEPERF duplicate main-thread process epoch ({},{})",
                    key.pid,
                    core.exec_epoch
                );
            }
            group_epochs.push((key.pid, core.exec_epoch));
        }
        let pids = process_epochs.iter().map(|(pid, _)| *pid).collect();
        validate_contiguous_epochs(&process_epochs, &pids)?;
        for group_epoch in group_epochs {
            if !process_epochs.contains(&group_epoch) {
                bail!(
                    "NATIVEPERF worker thread refers to missing process epoch ({},{})",
                    group_epoch.0,
                    group_epoch.1
                );
            }
        }

        Ok(Self {
            process_epochs,
            pids,
            threads,
            all_thread_translations,
            supervisor_total_cpu_ns,
        })
    }
}

fn validate_contiguous_epochs(
    process_epochs: &BTreeSet<(i32, u64)>,
    pids: &BTreeSet<i32>,
) -> anyhow::Result<()> {
    for pid in pids {
        let epochs = process_epochs
            .range((*pid, 0)..=(*pid, u64::MAX))
            .map(|(_, epoch)| *epoch);
        for (expected, observed) in (0_u64..).zip(epochs) {
            if expected != observed {
                bail!(
                    "NATIVEPERF pid {pid} exec epochs are not contiguous: expected {expected}, observed {observed}"
                );
            }
        }
    }
    Ok(())
}

fn parse_fields<'a>(
    parts: impl Iterator<Item = &'a str>,
    line_number: usize,
) -> anyhow::Result<BTreeMap<&'a str, &'a str>> {
    let mut fields = BTreeMap::new();
    for part in parts {
        let (key, value) = part
            .split_once('=')
            .with_context(|| format!("NATIVEPERF line {line_number}: field has no equals sign"))?;
        if key.is_empty() || value.is_empty() {
            bail!("NATIVEPERF line {line_number}: empty field name or value");
        }
        if fields.insert(key, value).is_some() {
            bail!("NATIVEPERF line {line_number}: duplicate field {key}");
        }
    }
    Ok(fields)
}

fn required<'a>(
    fields: &BTreeMap<&'a str, &'a str>,
    field: &str,
    line_number: usize,
) -> anyhow::Result<&'a str> {
    fields
        .get(field)
        .copied()
        .with_context(|| format!("NATIVEPERF line {line_number}: missing {field}"))
}

fn parse_u64(
    fields: &BTreeMap<&str, &str>,
    field: &str,
    line_number: usize,
) -> anyhow::Result<u64> {
    required(fields, field, line_number)?
        .parse::<u64>()
        .with_context(|| format!("NATIVEPERF line {line_number}: invalid {field}"))
}

fn parse_i32(
    fields: &BTreeMap<&str, &str>,
    field: &str,
    line_number: usize,
) -> anyhow::Result<i32> {
    required(fields, field, line_number)?
        .parse::<i32>()
        .with_context(|| format!("NATIVEPERF line {line_number}: invalid {field}"))
}

fn require_only_fields(
    fields: &BTreeMap<&str, &str>,
    allowed: &[&str],
    line_number: usize,
    frame: &str,
) -> anyhow::Result<()> {
    for field in fields.keys() {
        if !allowed.contains(field) {
            bail!("NATIVEPERF line {line_number}: unknown {frame} field {field}");
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn complete_stream() -> String {
        [
            "NATIVEPERF1|thread|complete=1|pid=10|tid=10|era=0|frame=core|gateway_entries=10|reconciled_exits=10|overflowed=0|thread_cpu_ns=100|exec_epoch=0",
            "NATIVEPERF1|thread|complete=1|pid=10|tid=10|era=0|frame=resolver-process|translations=10",
            "NATIVEPERF1|thread|complete=1|pid=10|tid=10|era=1|frame=core|gateway_entries=5|reconciled_exits=5|overflowed=0|thread_cpu_ns=200|exec_epoch=1",
            "NATIVEPERF1|thread|complete=1|pid=10|tid=10|era=1|frame=resolver-process|translations=5",
            "NATIVEPERF1|thread|complete=1|pid=20|tid=20|era=0|frame=core|gateway_entries=12|reconciled_exits=12|overflowed=0|thread_cpu_ns=300|exec_epoch=0",
            "NATIVEPERF1|thread|complete=1|pid=20|tid=20|era=0|frame=resolver-process|translations=12",
            "NATIVEPERF1|thread|complete=1|pid=20|tid=21|era=0|frame=core|gateway_entries=8|reconciled_exits=8|overflowed=0|thread_cpu_ns=400|exec_epoch=0",
            "NATIVEPERF1|thread|complete=1|pid=20|tid=21|era=0|frame=resolver-process|translations=8",
            "NATIVEPERF1|supervisor|self_cpu_ns=10000|children_cpu_ns=13000",
        ]
        .join("\n")
    }

    fn rejected(stream: String, needle: &str) {
        let error = NativePerfEpochAuthority::parse(&stream).expect_err("stream must fail");
        assert!(error.to_string().contains(needle), "{error:#}");
    }

    #[test]
    fn native_perf_epochs_extracts_exact_authority() {
        let authority = NativePerfEpochAuthority::parse(&complete_stream()).expect("authority");
        assert_eq!(authority.process_epochs.len(), 3);
        assert_eq!(authority.pids.len(), 2);
        assert_eq!(authority.threads, 4);
        assert_eq!(authority.all_thread_translations, 35);
        assert_eq!(authority.supervisor_total_cpu_ns, 23_000);
    }

    #[test]
    fn native_perf_epochs_rejects_duplicate_core() {
        let mut stream = complete_stream();
        let first = stream.lines().next().expect("first core").to_owned();
        stream.push('\n');
        stream.push_str(&first);
        rejected(stream, "duplicate core");
    }

    #[test]
    fn native_perf_epochs_rejects_missing_resolver_process() {
        let stream = complete_stream()
            .lines()
            .filter(|line| !(line.contains("tid=21") && line.contains("resolver-process")))
            .collect::<Vec<_>>()
            .join("\n");
        rejected(stream, "missing resolver-process");
    }

    #[test]
    fn native_perf_epochs_rejects_incomplete_or_overflowed_core() {
        rejected(
            complete_stream().replacen("complete=1", "complete=0", 1),
            "complete",
        );
        rejected(
            complete_stream().replacen("overflowed=0", "overflowed=1", 1),
            "overflowed",
        );
    }

    #[test]
    fn native_perf_epochs_rejects_gateway_reconciliation_mismatch() {
        rejected(
            complete_stream().replacen("gateway_entries=10", "gateway_entries=11", 1),
            "gateway_entries",
        );
    }

    #[test]
    fn native_perf_epochs_requires_exactly_one_supervisor() {
        let mut duplicate = complete_stream();
        duplicate.push_str("\nNATIVEPERF1|supervisor|self_cpu_ns=1|children_cpu_ns=2");
        rejected(duplicate, "duplicate supervisor");
        rejected(
            complete_stream()
                .lines()
                .filter(|line| !line.contains("|supervisor|"))
                .collect::<Vec<_>>()
                .join("\n"),
            "missing supervisor",
        );
    }

    #[test]
    fn native_perf_epochs_rejects_non_contiguous_process_epochs() {
        rejected(
            complete_stream().replacen("exec_epoch=1", "exec_epoch=2", 1),
            "contiguous",
        );
    }

    #[test]
    fn native_perf_epochs_rejects_duplicate_main_thread_process_epoch() {
        let mut stream = complete_stream();
        stream.push_str(
            "\nNATIVEPERF1|thread|complete=1|pid=10|tid=10|era=2|frame=core|gateway_entries=1|reconciled_exits=1|overflowed=0|thread_cpu_ns=1|exec_epoch=1",
        );
        stream.push_str(
            "\nNATIVEPERF1|thread|complete=1|pid=10|tid=10|era=2|frame=resolver-process|translations=1",
        );
        rejected(stream, "duplicate main-thread process epoch");
    }

    #[test]
    fn native_perf_epochs_rejects_unknown_numeric_values_and_checked_sum_overflow() {
        rejected(
            complete_stream().replacen("thread_cpu_ns=100", "thread_cpu_ns=unknown", 1),
            "thread_cpu_ns",
        );
        let stream = complete_stream()
            .replacen("translations=10", &format!("translations={}", u64::MAX), 1)
            .replacen("translations=5", "translations=1", 1);
        rejected(stream, "translations overflow");
    }

    #[test]
    fn native_perf_epochs_rejects_invalid_frames() {
        let mut stream = complete_stream();
        stream.push_str("\nNATIVEPERF1|invalid|complete=0|pid=10|tid=10|era=2|reason=overflow");
        rejected(stream, "invalid frame");
    }
}
