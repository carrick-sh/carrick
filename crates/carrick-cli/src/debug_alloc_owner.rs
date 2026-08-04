//! Strict join and opportunity report for the native allocation-owner census.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use anyhow::{Context as _, bail};
use carrick_runtime::alloc_owner_wire::{
    AllocationFlushReason, AllocationOwner, AllocationOwnerCensusFile, OwnerSnapshot,
};
use serde::Serialize;

use crate::native_perf_epochs::NativePerfEpochAuthority;

const REPORT_SCHEMA: &str = "carrick.alloc-owner-census.v3";
const FILE_PREFIX: &str = "alloc-owner-";
const FILE_SUFFIX: &str = ".txt";
const TEMP_SUFFIX: &str = ".txt.tmp";
const FALLBACK_AUTHORITY: &str = "strict-fallback-no-normal-binding";
const NORMAL_AUTHORITY: &str = "normal-host-allocation-opportunity";

#[derive(Clone, Debug)]
pub(crate) struct AllocOwnerCensusRequest {
    pub(crate) dir: PathBuf,
    pub(crate) native_perf: PathBuf,
    pub(crate) expected_process_epochs: u64,
    pub(crate) expected_pids: u64,
    pub(crate) normal_host_allocation_opportunity_share: Option<f64>,
    pub(crate) qualification_share_of_total: f64,
}

#[derive(Clone, Debug, Serialize)]
struct FilesReport {
    discovered: u64,
    parsed: u64,
    temporary: u64,
}

#[derive(Clone, Debug, Serialize)]
struct IdentityReport {
    expected_process_epochs: u64,
    observed_process_epochs: u64,
    expected_pids: u64,
    observed_pids: u64,
    fragments: u64,
    flushes: BTreeMap<&'static str, u64>,
}

#[derive(Clone, Debug, Serialize)]
struct NativePerfReport {
    process_epochs: u64,
    pids: u64,
    threads: u64,
    all_thread_translations: u64,
    supervisor_total_cpu_ns: u64,
}

#[derive(Clone, Debug, Serialize)]
struct ThresholdReport {
    normal_host_allocation_opportunity_share: Option<f64>,
    qualification_share_of_total: Option<f64>,
    required_owner_share: Option<f64>,
    authority: &'static str,
}

#[derive(Clone, Debug, Serialize)]
struct OwnerReport {
    owner: &'static str,
    requested_bytes: u64,
    share: f64,
    alloc_calls: u64,
    zeroed_calls: u64,
    realloc_calls: u64,
}

#[derive(Clone, Debug, Serialize)]
struct OtherVerdict {
    share: f64,
    required_owner_share: Option<f64>,
    passes: bool,
}

#[derive(Clone, Debug, Serialize)]
struct CandidateReport {
    owner: &'static str,
    owner_share: f64,
    projected_share_of_total: Option<f64>,
    coverage_candidate: bool,
    carried: bool,
}

#[derive(Clone, Debug, Serialize)]
struct StopReport {
    stop: bool,
    reason: Option<&'static str>,
}

#[derive(Clone, Debug, Serialize)]
struct AllocOwnerCensusReport {
    schema: &'static str,
    valid: bool,
    errors: Vec<String>,
    files: FilesReport,
    identity: IdentityReport,
    native_perf: NativePerfReport,
    thresholds: ThresholdReport,
    total_requested_bytes: u64,
    owners: Vec<OwnerReport>,
    other: OtherVerdict,
    candidates: Vec<CandidateReport>,
    stop: StopReport,
}

pub(crate) fn run_alloc_owner_census(request: &AllocOwnerCensusRequest) -> anyhow::Result<()> {
    let report = analyze(request);
    println!("{}", render_report(&report)?);
    if !report.valid {
        bail!("allocation-owner census report is invalid");
    }
    Ok(())
}

fn render_report(report: &AllocOwnerCensusReport) -> anyhow::Result<String> {
    serde_json::to_string_pretty(report).context("failed to render allocation-owner report")
}

fn analyze(request: &AllocOwnerCensusRequest) -> AllocOwnerCensusReport {
    let mut errors = Vec::new();
    let authority = read_authority(&request.native_perf, &mut errors);
    let (records, files) = discover_records(&request.dir, &mut errors);

    let mut identities = BTreeSet::new();
    let mut groups = BTreeMap::<(i32, u64), Vec<AllocationOwnerCensusFile>>::new();
    for record in records {
        let identity = (record.pid, record.exec_epoch, record.fragment_sequence);
        if !identities.insert(identity) {
            errors.push(format!(
                "duplicate allocation fragment identity ({},{},{})",
                identity.0, identity.1, identity.2
            ));
            continue;
        }
        groups
            .entry((record.pid, record.exec_epoch))
            .or_default()
            .push(record);
    }
    for fragments in groups.values_mut() {
        fragments.sort_by_key(|record| record.fragment_sequence);
    }

    validate_fragment_sequences(&groups, &mut errors);
    validate_lifecycle(&groups, &mut errors);

    let observed_epochs: BTreeSet<_> = groups.keys().copied().collect();
    let observed_pids: BTreeSet<_> = observed_epochs.iter().map(|(pid, _)| *pid).collect();
    for missing in authority.process_epochs.difference(&observed_epochs) {
        errors.push(format!(
            "allocation census is missing NATIVEPERF process epoch ({},{})",
            missing.0, missing.1
        ));
    }
    for extra in observed_epochs.difference(&authority.process_epochs) {
        errors.push(format!(
            "allocation census has process epoch absent from NATIVEPERF ({},{})",
            extra.0, extra.1
        ));
    }

    check_expected_count(
        "process epochs",
        request.expected_process_epochs,
        authority.process_epochs.len(),
        &mut errors,
    );
    check_expected_count(
        "pids",
        request.expected_pids,
        authority.pids.len(),
        &mut errors,
    );

    let mut aggregate = [OwnerSnapshot::default(); AllocationOwner::COUNT];
    let mut flushes = flush_map();
    for fragments in groups.values() {
        for record in fragments {
            *flushes.entry(record.reason.token()).or_default() += 1;
            for owner in AllocationOwner::ALL {
                let source = record.owners[owner as usize];
                let target = &mut aggregate[owner as usize];
                checked_add(
                    &mut target.requested_bytes,
                    source.requested_bytes,
                    owner,
                    "requested bytes",
                    &mut errors,
                );
                checked_add(
                    &mut target.alloc_calls,
                    source.alloc_calls,
                    owner,
                    "alloc calls",
                    &mut errors,
                );
                checked_add(
                    &mut target.zeroed_calls,
                    source.zeroed_calls,
                    owner,
                    "zeroed calls",
                    &mut errors,
                );
                checked_add(
                    &mut target.realloc_calls,
                    source.realloc_calls,
                    owner,
                    "realloc calls",
                    &mut errors,
                );
            }
        }
    }
    let total_requested_bytes = aggregate.iter().try_fold(0_u64, |total, owner| {
        total.checked_add(owner.requested_bytes)
    });
    let total_requested_bytes = match total_requested_bytes {
        Some(0) => {
            errors.push("allocation census has zero requested bytes".to_owned());
            0
        }
        Some(total) => total,
        None => {
            errors.push("allocation census total requested bytes overflow".to_owned());
            0
        }
    };

    let owners = AllocationOwner::ALL
        .into_iter()
        .map(|owner| {
            let snapshot = aggregate[owner as usize];
            OwnerReport {
                owner: owner.token(),
                requested_bytes: snapshot.requested_bytes,
                share: share(snapshot.requested_bytes, total_requested_bytes),
                alloc_calls: snapshot.alloc_calls,
                zeroed_calls: snapshot.zeroed_calls,
                realloc_calls: snapshot.realloc_calls,
            }
        })
        .collect::<Vec<_>>();

    let supplied_h = request.normal_host_allocation_opportunity_share;
    let valid_h = supplied_h.filter(|share| valid_share(*share));
    if supplied_h.is_some() && valid_h.is_none() {
        errors.push(
            "normal host-allocation opportunity share must be finite and in (0, 1]".to_owned(),
        );
    }
    let supplied_p = request.qualification_share_of_total;
    let valid_p = valid_share(supplied_p).then_some(supplied_p);
    if valid_p.is_none() {
        errors.push("qualification share of total must be finite and in (0, 1]".to_owned());
    }
    let required_owner_share = match (supplied_h, valid_h, valid_p) {
        (None, _, Some(p)) => Some(p),
        (Some(_), Some(h), Some(p)) => {
            let required = p / h;
            if required.is_finite() {
                Some(required)
            } else {
                errors.push("required owner share is not representable".to_owned());
                None
            }
        }
        _ => None,
    };
    let authority_label = if supplied_h.is_none() {
        FALLBACK_AUTHORITY
    } else {
        NORMAL_AUTHORITY
    };

    let other_share = owners[AllocationOwner::Other as usize].share;
    let other_passes = required_owner_share.is_some_and(|required| other_share < required);
    if required_owner_share.is_some() && !other_passes {
        errors.push(format!(
            "other allocation share {other_share:.17} meets or exceeds required owner share {:.17}",
            required_owner_share.unwrap_or_default()
        ));
    }

    let stop = required_owner_share.is_some_and(|required| required > 1.0);
    let mut candidates = Vec::new();
    if !stop && let Some(required) = required_owner_share {
        for owner in owners.iter().skip(1) {
            if owner.share < required {
                continue;
            }
            candidates.push(CandidateReport {
                owner: owner.owner,
                owner_share: owner.share,
                projected_share_of_total: valid_h.map(|h| owner.share * h),
                coverage_candidate: valid_h.is_none(),
                carried: valid_h.is_some(),
            });
        }
    }
    candidates.sort_by(|left, right| {
        right
            .projected_share_of_total
            .unwrap_or(right.owner_share)
            .total_cmp(&left.projected_share_of_total.unwrap_or(left.owner_share))
            .then_with(|| left.owner.cmp(right.owner))
    });
    if let Some(h) = valid_h {
        let projected_sum = candidates
            .iter()
            .filter_map(|candidate| candidate.projected_share_of_total)
            .sum::<f64>();
        if projected_sum > h + f64::EPSILON {
            errors.push(format!(
                "candidate projected share {projected_sum:.17} exceeds normal opportunity {h:.17}"
            ));
        }
    }

    let fragments = groups
        .values()
        .map(Vec::len)
        .try_fold(0_u64, |total, count| {
            total.checked_add(u64::try_from(count).ok()?)
        })
        .unwrap_or_else(|| {
            errors.push("allocation fragment count overflow".to_owned());
            0
        });
    let observed_process_epochs = u64::try_from(groups.len()).unwrap_or_else(|_| {
        errors.push("allocation process-epoch count overflow".to_owned());
        0
    });

    AllocOwnerCensusReport {
        schema: REPORT_SCHEMA,
        valid: errors.is_empty(),
        errors,
        files,
        identity: IdentityReport {
            expected_process_epochs: request.expected_process_epochs,
            observed_process_epochs,
            expected_pids: request.expected_pids,
            observed_pids: u64::try_from(observed_pids.len()).unwrap_or(0),
            fragments,
            flushes,
        },
        native_perf: NativePerfReport {
            process_epochs: u64::try_from(authority.process_epochs.len()).unwrap_or(0),
            pids: u64::try_from(authority.pids.len()).unwrap_or(0),
            threads: authority.threads,
            all_thread_translations: authority.all_thread_translations,
            supervisor_total_cpu_ns: authority.supervisor_total_cpu_ns,
        },
        thresholds: ThresholdReport {
            normal_host_allocation_opportunity_share: valid_h,
            qualification_share_of_total: valid_p,
            required_owner_share,
            authority: authority_label,
        },
        total_requested_bytes,
        owners,
        other: OtherVerdict {
            share: other_share,
            required_owner_share,
            passes: other_passes,
        },
        candidates,
        stop: StopReport {
            stop,
            reason: stop.then_some("normal-host-allocation-pot-below-qualification-threshold"),
        },
    }
}

fn read_authority(path: &Path, errors: &mut Vec<String>) -> NativePerfEpochAuthority {
    match std::fs::read_to_string(path) {
        Ok(text) => match NativePerfEpochAuthority::parse(&text) {
            Ok(authority) => authority,
            Err(error) => {
                errors.push(format!(
                    "failed to parse NATIVEPERF authority {}: {error:#}",
                    path.display()
                ));
                empty_authority()
            }
        },
        Err(error) => {
            errors.push(format!(
                "failed to read NATIVEPERF authority {}: {error}",
                path.display()
            ));
            empty_authority()
        }
    }
}

fn empty_authority() -> NativePerfEpochAuthority {
    NativePerfEpochAuthority {
        process_epochs: BTreeSet::new(),
        pids: BTreeSet::new(),
        threads: 0,
        all_thread_translations: 0,
        supervisor_total_cpu_ns: 0,
    }
}

fn discover_records(
    dir: &Path,
    errors: &mut Vec<String>,
) -> (Vec<AllocationOwnerCensusFile>, FilesReport) {
    let mut paths = Vec::new();
    let mut temporary = 0_u64;
    match std::fs::read_dir(dir) {
        Ok(entries) => {
            for entry in entries {
                let entry = match entry {
                    Ok(entry) => entry,
                    Err(error) => {
                        errors.push(format!(
                            "failed to read allocation census directory entry: {error}"
                        ));
                        continue;
                    }
                };
                let name = entry.file_name();
                let Some(name) = name.to_str() else {
                    continue;
                };
                if name.starts_with(FILE_PREFIX) && name.ends_with(TEMP_SUFFIX) {
                    temporary = temporary.saturating_add(1);
                    errors.push(format!(
                        "truncated allocation census temporary file {}",
                        entry.path().display()
                    ));
                } else if name.starts_with(FILE_PREFIX) && name.ends_with(FILE_SUFFIX) {
                    paths.push(entry.path());
                }
            }
        }
        Err(error) => errors.push(format!(
            "failed to read allocation census directory {}: {error}",
            dir.display()
        )),
    }
    paths.sort();

    let discovered = u64::try_from(paths.len()).unwrap_or(u64::MAX);
    let mut records = Vec::new();
    for path in paths {
        match std::fs::read_to_string(&path) {
            Ok(text) => match AllocationOwnerCensusFile::parse(&text) {
                Ok(record) => records.push(record),
                Err(error) => errors.push(format!(
                    "failed to parse allocation census {}: {error}",
                    path.display()
                )),
            },
            Err(error) => errors.push(format!(
                "failed to read allocation census {}: {error}",
                path.display()
            )),
        }
    }
    let parsed = u64::try_from(records.len()).unwrap_or(u64::MAX);
    (
        records,
        FilesReport {
            discovered,
            parsed,
            temporary,
        },
    )
}

fn validate_fragment_sequences(
    groups: &BTreeMap<(i32, u64), Vec<AllocationOwnerCensusFile>>,
    errors: &mut Vec<String>,
) {
    for ((pid, epoch), fragments) in groups {
        for (expected, fragment) in (0_u64..).zip(fragments) {
            if fragment.fragment_sequence != expected {
                errors.push(format!(
                    "allocation fragments for ({pid},{epoch}) have a sequence gap: expected {expected}, observed {}",
                    fragment.fragment_sequence
                ));
                break;
            }
        }
    }
}

fn validate_lifecycle(
    groups: &BTreeMap<(i32, u64), Vec<AllocationOwnerCensusFile>>,
    errors: &mut Vec<String>,
) {
    for ((pid, epoch), fragments) in groups {
        for fragment in fragments.iter().take(fragments.len().saturating_sub(1)) {
            if fragment.reason != AllocationFlushReason::HostSelfReexecAttempt {
                errors.push(format!(
                    "non-final allocation fragment ({pid},{epoch},{}) has disposition {}",
                    fragment.fragment_sequence,
                    fragment.reason.token()
                ));
            }
        }
        let Some(final_fragment) = fragments.last() else {
            continue;
        };
        let successor = epoch
            .checked_add(1)
            .is_some_and(|next| groups.contains_key(&(*pid, next)));
        match final_fragment.reason {
            AllocationFlushReason::HostSelfReexecAttempt | AllocationFlushReason::InProcessExec
                if !successor =>
            {
                errors.push(format!(
                    "allocation epoch ({pid},{epoch}) ends in {} without a successor",
                    final_fragment.reason.token()
                ))
            }
            AllocationFlushReason::ProcessExit | AllocationFlushReason::AtexitBackstop
                if successor =>
            {
                errors.push(format!(
                    "terminal allocation epoch ({pid},{epoch}) has a successor"
                ));
            }
            _ => {}
        }
    }
}

fn check_expected_count(label: &str, expected: u64, observed: usize, errors: &mut Vec<String>) {
    if u64::try_from(observed) != Ok(expected) {
        errors.push(format!(
            "expected {expected} {label}, observed {observed} in NATIVEPERF authority"
        ));
    }
}

fn checked_add(
    target: &mut u64,
    value: u64,
    owner: AllocationOwner,
    field: &str,
    errors: &mut Vec<String>,
) {
    match target.checked_add(value) {
        Some(sum) => *target = sum,
        None => {
            errors.push(format!("{} {field} overflow", owner.token()));
            *target = u64::MAX;
        }
    }
}

fn valid_share(value: f64) -> bool {
    value.is_finite() && value > 0.0 && value <= 1.0
}

fn share(value: u64, total: u64) -> f64 {
    if total == 0 {
        0.0
    } else {
        value as f64 / total as f64
    }
}

fn flush_map() -> BTreeMap<&'static str, u64> {
    [
        AllocationFlushReason::HostSelfReexecAttempt,
        AllocationFlushReason::InProcessExec,
        AllocationFlushReason::ProcessExit,
        AllocationFlushReason::AtexitBackstop,
    ]
    .into_iter()
    .map(|reason| (reason.token(), 0))
    .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Fixture {
        _dir: tempfile::TempDir,
        request: AllocOwnerCensusRequest,
    }

    fn owner_snapshots() -> [OwnerSnapshot; AllocationOwner::COUNT] {
        let mut owners = [OwnerSnapshot::default(); AllocationOwner::COUNT];
        let bytes = [5, 8, 40, 20, 10, 5, 5, 7];
        for (owner, requested_bytes) in AllocationOwner::ALL.into_iter().zip(bytes) {
            owners[owner as usize] = OwnerSnapshot {
                requested_bytes,
                alloc_calls: 1,
                zeroed_calls: 0,
                realloc_calls: 0,
            };
        }
        owners
    }

    fn record(
        pid: i32,
        exec_epoch: u64,
        fragment_sequence: u64,
        reason: AllocationFlushReason,
    ) -> AllocationOwnerCensusFile {
        AllocationOwnerCensusFile {
            pid,
            exec_epoch,
            fragment_sequence,
            reason,
            overflow: false,
            lifecycle_error: false,
            owners: owner_snapshots(),
        }
    }

    fn valid_records() -> Vec<AllocationOwnerCensusFile> {
        vec![
            record(10, 0, 0, AllocationFlushReason::HostSelfReexecAttempt),
            record(10, 0, 1, AllocationFlushReason::HostSelfReexecAttempt),
            record(10, 1, 0, AllocationFlushReason::ProcessExit),
            record(20, 0, 0, AllocationFlushReason::InProcessExec),
            record(20, 1, 0, AllocationFlushReason::ProcessExit),
        ]
    }

    fn native_perf(epochs: &[(i32, u64)]) -> String {
        let mut lines = Vec::new();
        for (pid, epoch) in epochs {
            lines.push(format!(
                "NATIVEPERF1|thread|complete=1|pid={pid}|tid={pid}|era={epoch}|frame=core|gateway_entries=10|reconciled_exits=10|overflowed=0|thread_cpu_ns=100|exec_epoch={epoch}"
            ));
            lines.push(format!(
                "NATIVEPERF1|thread|complete=1|pid={pid}|tid={pid}|era={epoch}|frame=resolver-process|translations=10"
            ));
        }
        lines.push("NATIVEPERF1|supervisor|self_cpu_ns=10000|children_cpu_ns=13000".to_owned());
        lines.join("\n")
    }

    fn fixture_with(
        records: Vec<AllocationOwnerCensusFile>,
        epochs: &[(i32, u64)],
        expected_process_epochs: u64,
        expected_pids: u64,
        h: Option<f64>,
        p: f64,
    ) -> Fixture {
        let dir = tempfile::tempdir().expect("fixture directory");
        for (index, record) in records.into_iter().enumerate() {
            std::fs::write(
                dir.path().join(format!("alloc-owner-fixture-{index}.txt")),
                record.render().expect("render record"),
            )
            .expect("write record");
        }
        let native_perf_path = dir.path().join("native-perf.txt");
        std::fs::write(&native_perf_path, native_perf(epochs)).expect("write NATIVEPERF");
        Fixture {
            request: AllocOwnerCensusRequest {
                dir: dir.path().to_path_buf(),
                native_perf: native_perf_path,
                expected_process_epochs,
                expected_pids,
                normal_host_allocation_opportunity_share: h,
                qualification_share_of_total: p,
            },
            _dir: dir,
        }
    }

    fn valid_fixture() -> Fixture {
        fixture_with(
            valid_records(),
            &[(10, 0), (10, 1), (20, 0), (20, 1)],
            4,
            2,
            Some(0.30),
            0.10,
        )
    }

    fn assert_invalid(report: &AllocOwnerCensusReport, needle: &str) {
        assert!(!report.valid, "report unexpectedly valid");
        assert!(
            report.errors.iter().any(|error| error.contains(needle)),
            "missing `{needle}` in {:#?}",
            report.errors
        );
    }

    #[test]
    fn debug_alloc_owner_renders_exact_stable_portfolio() {
        let fixture = valid_fixture();
        let report = analyze(&fixture.request);
        assert!(report.valid, "{:#?}", report.errors);
        assert_eq!(report.candidates.len(), 1);
        assert_eq!(report.candidates[0].owner, "publication-recovery");
        assert_eq!(report.candidates[0].owner_share, 0.4);
        assert_eq!(report.candidates[0].projected_share_of_total, Some(0.12));
        assert!(report.candidates[0].carried);
        assert!(!report.candidates[0].coverage_candidate);

        let first = render_report(&report).expect("render report");
        let second = render_report(&analyze(&fixture.request)).expect("rerender report");
        assert_eq!(first, second);
        assert_eq!(first, GOLDEN_REPORT);
    }

    #[test]
    fn debug_alloc_owner_rejects_missing_and_extra_epochs() {
        let missing = fixture_with(
            valid_records()
                .into_iter()
                .filter(|record| !(record.pid == 20 && record.exec_epoch == 1))
                .collect(),
            &[(10, 0), (10, 1), (20, 0), (20, 1)],
            4,
            2,
            Some(0.3),
            0.1,
        );
        assert_invalid(
            &analyze(&missing.request),
            "missing NATIVEPERF process epoch",
        );

        let mut extra_records = valid_records();
        extra_records.push(record(30, 0, 0, AllocationFlushReason::ProcessExit));
        let extra = fixture_with(
            extra_records,
            &[(10, 0), (10, 1), (20, 0), (20, 1)],
            4,
            2,
            Some(0.3),
            0.1,
        );
        assert_invalid(&analyze(&extra.request), "absent from NATIVEPERF");
    }

    #[test]
    fn debug_alloc_owner_rejects_fragment_gap_and_duplicate_identity() {
        let mut gap_records = valid_records();
        gap_records[1].fragment_sequence = 2;
        let gap = fixture_with(
            gap_records,
            &[(10, 0), (10, 1), (20, 0), (20, 1)],
            4,
            2,
            Some(0.3),
            0.1,
        );
        assert_invalid(&analyze(&gap.request), "sequence gap");

        let mut duplicate_records = valid_records();
        duplicate_records.push(duplicate_records[0].clone());
        let duplicate = fixture_with(
            duplicate_records,
            &[(10, 0), (10, 1), (20, 0), (20, 1)],
            4,
            2,
            Some(0.3),
            0.1,
        );
        assert_invalid(
            &analyze(&duplicate.request),
            "duplicate allocation fragment identity",
        );
    }

    #[test]
    fn debug_alloc_owner_enforces_every_final_disposition() {
        let host = fixture_with(
            vec![record(
                10,
                0,
                0,
                AllocationFlushReason::HostSelfReexecAttempt,
            )],
            &[(10, 0)],
            1,
            1,
            Some(0.3),
            0.1,
        );
        assert_invalid(&analyze(&host.request), "without a successor");

        let in_process = fixture_with(
            vec![record(10, 0, 0, AllocationFlushReason::InProcessExec)],
            &[(10, 0)],
            1,
            1,
            Some(0.3),
            0.1,
        );
        assert_invalid(&analyze(&in_process.request), "without a successor");

        let terminal = fixture_with(
            vec![
                record(10, 0, 0, AllocationFlushReason::ProcessExit),
                record(10, 1, 0, AllocationFlushReason::ProcessExit),
            ],
            &[(10, 0), (10, 1)],
            2,
            1,
            Some(0.3),
            0.1,
        );
        assert_invalid(&analyze(&terminal.request), "terminal allocation epoch");
    }

    #[test]
    fn debug_alloc_owner_rejects_expected_count_mismatches() {
        let mut records = Vec::new();
        let mut epochs = Vec::new();
        for pid in 1_000..1_070 {
            records.push(record(pid, 0, 0, AllocationFlushReason::InProcessExec));
            records.push(record(pid, 1, 0, AllocationFlushReason::ProcessExit));
            epochs.push((pid, 0));
            epochs.push((pid, 1));
        }
        let wrong_epochs = fixture_with(records.clone(), &epochs, 139, 70, Some(0.3), 0.1);
        assert_invalid(
            &analyze(&wrong_epochs.request),
            "expected 139 process epochs, observed 140",
        );

        let wrong_pids = fixture_with(records, &epochs, 140, 71, Some(0.3), 0.1);
        assert_invalid(
            &analyze(&wrong_pids.request),
            "expected 71 pids, observed 70",
        );
    }

    #[test]
    fn debug_alloc_owner_rejects_other_at_threshold_and_invalid_shares() {
        let other = fixture_with(
            valid_records(),
            &[(10, 0), (10, 1), (20, 0), (20, 1)],
            4,
            2,
            Some(1.0),
            0.05,
        );
        assert_invalid(&analyze(&other.request), "other allocation share");

        let bad_h = fixture_with(
            valid_records(),
            &[(10, 0), (10, 1), (20, 0), (20, 1)],
            4,
            2,
            Some(0.0),
            0.1,
        );
        let report = analyze(&bad_h.request);
        assert_invalid(&report, "opportunity share");
        assert_eq!(report.thresholds.required_owner_share, None);

        let bad_p = fixture_with(
            valid_records(),
            &[(10, 0), (10, 1), (20, 0), (20, 1)],
            4,
            2,
            Some(0.3),
            f64::NAN,
        );
        let report = analyze(&bad_p.request);
        assert_invalid(&report, "qualification share");
        render_report(&report).expect("invalid non-finite input still renders");

        let unrepresentable_q = fixture_with(
            valid_records(),
            &[(10, 0), (10, 1), (20, 0), (20, 1)],
            4,
            2,
            Some(f64::from_bits(1)),
            1.0,
        );
        let report = analyze(&unrepresentable_q.request);
        assert_invalid(&report, "required owner share is not representable");
        render_report(&report).expect("unrepresentable quotient still renders");
    }

    #[test]
    fn debug_alloc_owner_rejects_malformed_and_temporary_files() {
        let fixture = valid_fixture();
        std::fs::write(
            fixture.request.dir.join("alloc-owner-malformed.txt"),
            "not a census\n",
        )
        .expect("write malformed file");
        std::fs::write(
            fixture.request.dir.join("alloc-owner-truncated.txt.tmp"),
            "partial",
        )
        .expect("write temporary file");
        let report = analyze(&fixture.request);
        assert_invalid(&report, "failed to parse allocation census");
        assert_invalid(&report, "truncated allocation census temporary file");
    }

    #[test]
    fn debug_alloc_owner_fallback_closes_coverage_without_carrying_opportunity() {
        let fixture = fixture_with(
            valid_records(),
            &[(10, 0), (10, 1), (20, 0), (20, 1)],
            4,
            2,
            None,
            0.1,
        );
        let report = analyze(&fixture.request);
        assert!(report.valid, "{:#?}", report.errors);
        assert_eq!(report.thresholds.authority, FALLBACK_AUTHORITY);
        assert_eq!(report.candidates.len(), 3);
        assert!(report.candidates.iter().all(|candidate| {
            candidate.coverage_candidate
                && !candidate.carried
                && candidate.projected_share_of_total.is_none()
        }));
        assert_eq!(report.candidates[0].owner, "publication-recovery");
        assert_eq!(report.candidates[1].owner, "block-assembler-transient");
        assert_eq!(report.candidates[2].owner, "decode-read-buffers");
    }

    #[test]
    fn debug_alloc_owner_q_above_one_is_a_valid_stop() {
        let fixture = fixture_with(
            valid_records(),
            &[(10, 0), (10, 1), (20, 0), (20, 1)],
            4,
            2,
            Some(0.05),
            0.1,
        );
        let report = analyze(&fixture.request);
        assert!(report.valid, "{:#?}", report.errors);
        assert!(report.stop.stop);
        assert!(report.candidates.is_empty());
    }

    const GOLDEN_REPORT: &str = r#"{
  "schema": "carrick.alloc-owner-census.v3",
  "valid": true,
  "errors": [],
  "files": {
    "discovered": 5,
    "parsed": 5,
    "temporary": 0
  },
  "identity": {
    "expected_process_epochs": 4,
    "observed_process_epochs": 4,
    "expected_pids": 2,
    "observed_pids": 2,
    "fragments": 5,
    "flushes": {
      "atexit-backstop": 0,
      "host-self-reexec-attempt": 2,
      "in-process-exec": 1,
      "process-exit": 2
    }
  },
  "native_perf": {
    "process_epochs": 4,
    "pids": 2,
    "threads": 4,
    "all_thread_translations": 40,
    "supervisor_total_cpu_ns": 23000
  },
  "thresholds": {
    "normal_host_allocation_opportunity_share": 0.3,
    "qualification_share_of_total": 0.1,
    "required_owner_share": 0.33333333333333337,
    "authority": "normal-host-allocation-opportunity"
  },
  "total_requested_bytes": 500,
  "owners": [
    {
      "owner": "other",
      "requested_bytes": 25,
      "share": 0.05,
      "alloc_calls": 5,
      "zeroed_calls": 0,
      "realloc_calls": 0
    },
    {
      "owner": "publication-map",
      "requested_bytes": 40,
      "share": 0.08,
      "alloc_calls": 5,
      "zeroed_calls": 0,
      "realloc_calls": 0
    },
    {
      "owner": "publication-recovery",
      "requested_bytes": 200,
      "share": 0.4,
      "alloc_calls": 5,
      "zeroed_calls": 0,
      "realloc_calls": 0
    },
    {
      "owner": "block-assembler-transient",
      "requested_bytes": 100,
      "share": 0.2,
      "alloc_calls": 5,
      "zeroed_calls": 0,
      "realloc_calls": 0
    },
    {
      "owner": "decode-read-buffers",
      "requested_bytes": 50,
      "share": 0.1,
      "alloc_calls": 5,
      "zeroed_calls": 0,
      "realloc_calls": 0
    },
    {
      "owner": "indirect-target-cache",
      "requested_bytes": 25,
      "share": 0.05,
      "alloc_calls": 5,
      "zeroed_calls": 0,
      "realloc_calls": 0
    },
    {
      "owner": "shared-translation-support",
      "requested_bytes": 25,
      "share": 0.05,
      "alloc_calls": 5,
      "zeroed_calls": 0,
      "realloc_calls": 0
    },
    {
      "owner": "publication-indexes",
      "requested_bytes": 35,
      "share": 0.07,
      "alloc_calls": 5,
      "zeroed_calls": 0,
      "realloc_calls": 0
    },
    {
      "owner": "translation-source-preparation",
      "requested_bytes": 0,
      "share": 0.0,
      "alloc_calls": 0,
      "zeroed_calls": 0,
      "realloc_calls": 0
    },
    {
      "owner": "translation-orchestration",
      "requested_bytes": 0,
      "share": 0.0,
      "alloc_calls": 0,
      "zeroed_calls": 0,
      "realloc_calls": 0
    }
  ],
  "other": {
    "share": 0.05,
    "required_owner_share": 0.33333333333333337,
    "passes": true
  },
  "candidates": [
    {
      "owner": "publication-recovery",
      "owner_share": 0.4,
      "projected_share_of_total": 0.12,
      "coverage_candidate": false,
      "carried": true
    }
  ],
  "stop": {
    "stop": false,
    "reason": null
  }
}"#;
}
