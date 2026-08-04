//! Fail-closed consumer for the opt-in native process-lifecycle export.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::path::Path;

use anyhow::{Context, bail};
use serde::Serialize;
use sha2::{Digest as _, Sha256};

const SCHEMA: &str = "carrick.exec-stamp-census.v1";
const REQUIRED_LIVE_VALIDITY: u8 = 7;
const REQUIRED_RELATED_VALIDITY: u8 = 15;

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
enum Phase {
    CloneEnter,
    ForkChildStart,
    CloneParentReturn,
    ExecveDispatch,
    CapsulePrepare,
    PreExec,
    MainEntry,
    ProbesReady,
    ResumeEntry,
    DispatcherReady,
    ImageMapped,
    RuntimeReady,
    ExitBegin,
    RuntimeReturn,
    PreHostExit,
    WaitReaped,
    RunComplete,
}

impl Phase {
    fn parse(value: &str) -> anyhow::Result<Self> {
        Ok(match value {
            "clone-enter" => Self::CloneEnter,
            "fork-child-start" => Self::ForkChildStart,
            "clone-parent-return" => Self::CloneParentReturn,
            "execve-dispatch" => Self::ExecveDispatch,
            "capsule-prepare" => Self::CapsulePrepare,
            "pre-exec" => Self::PreExec,
            "main-entry" => Self::MainEntry,
            "probes-ready" => Self::ProbesReady,
            "resume-entry" => Self::ResumeEntry,
            "dispatcher-ready" => Self::DispatcherReady,
            "image-mapped" => Self::ImageMapped,
            "runtime-ready" => Self::RuntimeReady,
            "exit-begin" => Self::ExitBegin,
            "runtime-return" => Self::RuntimeReturn,
            "pre-host-exit" => Self::PreHostExit,
            "wait-reaped" => Self::WaitReaped,
            "run-complete" => Self::RunComplete,
            other => bail!("unknown EXECSTAMP2 phase `{other}`"),
        })
    }

    fn name(self) -> &'static str {
        match self {
            Self::CloneEnter => "clone-enter",
            Self::ForkChildStart => "fork-child-start",
            Self::CloneParentReturn => "clone-parent-return",
            Self::ExecveDispatch => "execve-dispatch",
            Self::CapsulePrepare => "capsule-prepare",
            Self::PreExec => "pre-exec",
            Self::MainEntry => "main-entry",
            Self::ProbesReady => "probes-ready",
            Self::ResumeEntry => "resume-entry",
            Self::DispatcherReady => "dispatcher-ready",
            Self::ImageMapped => "image-mapped",
            Self::RuntimeReady => "runtime-ready",
            Self::ExitBegin => "exit-begin",
            Self::RuntimeReturn => "runtime-return",
            Self::PreHostExit => "pre-host-exit",
            Self::WaitReaped => "wait-reaped",
            Self::RunComplete => "run-complete",
        }
    }
}

#[derive(Clone, Debug)]
struct Record {
    line: usize,
    pid: u32,
    phase: Phase,
    valid: u8,
    mono_ns: u64,
    process_user_ns: u64,
    process_system_ns: u64,
    thread_user_ns: u64,
    thread_system_ns: u64,
    related_pid: u32,
    link_id: u64,
    related_status: i32,
    related_user_ns: u64,
    related_system_ns: u64,
}

impl Record {
    fn process_cpu_ns(&self) -> anyhow::Result<u64> {
        self.process_user_ns
            .checked_add(self.process_system_ns)
            .with_context(|| format!("line {} process CPU overflow", self.line))
    }

    fn thread_cpu_ns(&self) -> anyhow::Result<u64> {
        self.thread_user_ns
            .checked_add(self.thread_system_ns)
            .with_context(|| format!("line {} thread CPU overflow", self.line))
    }

    fn related_cpu_ns(&self) -> anyhow::Result<u64> {
        self.related_user_ns
            .checked_add(self.related_system_ns)
            .with_context(|| format!("line {} related CPU overflow", self.line))
    }
}

#[derive(Clone, Copy, Debug)]
struct Observation {
    wall_ns: u64,
    cpu_ns: u64,
    interval: (u64, u64),
}

#[derive(Debug, Default)]
struct ForkParts<'a> {
    enter: Option<&'a Record>,
    child_start: Option<&'a Record>,
    parent_return: Option<&'a Record>,
}

#[derive(Debug, Serialize)]
struct Distribution {
    count: usize,
    sum_ns: u64,
    median_ns: u64,
    p90_ns: u64,
    max_ns: u64,
}

#[derive(Debug, Serialize)]
struct SegmentReport {
    wall: Distribution,
    cpu: Distribution,
    cpu_share_of_guest_tree: f64,
    cpu_share_of_invocation: f64,
}

#[derive(Debug, Serialize)]
struct RunCpuReport {
    supervisor_ns: u64,
    guest_tree_ns: u64,
    invocation_ns: u64,
}

#[derive(Debug, Serialize)]
struct CoverageReport {
    phase_counts: BTreeMap<String, u64>,
    pids: usize,
    runtime_returns: usize,
    pre_host_exits: usize,
    leaf_exit_residuals: usize,
    unreaped_root_exits: usize,
}

#[derive(Debug, Serialize)]
struct ExecStampReport {
    schema: &'static str,
    #[serde(skip_serializing_if = "String::is_empty")]
    input_sha256: String,
    records: usize,
    exec_chains: usize,
    fork_pairs: usize,
    terminal_reaps: usize,
    workload_ns: u64,
    run_cpu: RunCpuReport,
    measured_opportunity_cpu_ns: u64,
    measured_opportunity_cpu_share_of_guest_tree: f64,
    measured_opportunity_cpu_share_of_invocation: f64,
    opportunity_wall_union_ns: u64,
    opportunity_wall_union_upper_bound_share_of_workload: f64,
    coverage: CoverageReport,
    segments: BTreeMap<String, SegmentReport>,
}

pub(crate) fn run_exec_stamp_census(input: &Path, workload_ns: u64) -> anyhow::Result<()> {
    let bytes = std::fs::read(input)
        .with_context(|| format!("failed to read exec-stamp export {}", input.display()))?;
    let text = std::str::from_utf8(&bytes)
        .with_context(|| format!("exec-stamp export {} is not UTF-8", input.display()))?;
    let mut report = parse_report(text, workload_ns)?;
    report.input_sha256 = format!("{:x}", Sha256::digest(&bytes));
    println!("{}", serde_json::to_string_pretty(&report)?);
    Ok(())
}

fn parse_report(input: &str, workload_ns: u64) -> anyhow::Result<ExecStampReport> {
    if workload_ns == 0 {
        bail!("--workload-ns must be nonzero");
    }
    if input.is_empty() {
        bail!("exec-stamp export is empty");
    }
    if !input.ends_with('\n') {
        bail!("exec-stamp export has a truncated final line");
    }
    let mut records = input
        .lines()
        .enumerate()
        .map(|(index, line)| parse_record(index + 1, line))
        .collect::<anyhow::Result<Vec<_>>>()?;
    records.sort_by_key(|record| (record.mono_ns, record.line));

    let mut phase_counts = BTreeMap::new();
    let mut pids = HashSet::new();
    for record in &records {
        *phase_counts
            .entry(record.phase.name().to_owned())
            .or_insert(0) += 1;
        pids.insert(record.pid);
    }

    let run_completions: Vec<_> = records
        .iter()
        .filter(|record| record.phase == Phase::RunComplete)
        .collect();
    let [run_complete] = run_completions.as_slice() else {
        bail!(
            "exec-stamp export requires exactly one run-complete record, found {}",
            run_completions.len()
        );
    };
    let supervisor_ns = run_complete.process_cpu_ns()?;
    let guest_tree_ns = run_complete.related_cpu_ns()?;
    if guest_tree_ns == 0 {
        bail!("run-complete guest-tree CPU is zero");
    }
    let invocation_ns = supervisor_ns
        .checked_add(guest_tree_ns)
        .context("run-complete invocation CPU overflow")?;

    let mut by_pid: HashMap<u32, Vec<&Record>> = HashMap::new();
    for record in &records {
        by_pid.entry(record.pid).or_default().push(record);
    }

    let mut observations: BTreeMap<&'static str, Vec<Observation>> = BTreeMap::new();
    let mut fork_parts: HashMap<(u32, u64), ForkParts<'_>> = HashMap::new();
    let mut child_to_fork = HashMap::new();
    for record in &records {
        match record.phase {
            Phase::CloneEnter => {
                let parts = fork_parts.entry((record.pid, record.link_id)).or_default();
                insert_once(&mut parts.enter, record, "clone-enter")?;
            }
            Phase::CloneParentReturn => {
                let parts = fork_parts.entry((record.pid, record.link_id)).or_default();
                insert_once(&mut parts.parent_return, record, "clone-parent-return")?;
                if child_to_fork
                    .insert(record.related_pid, (record.pid, record.link_id))
                    .is_some()
                {
                    bail!(
                        "child pid {} belongs to multiple fork links",
                        record.related_pid
                    );
                }
            }
            Phase::ForkChildStart => {
                let key = (record.related_pid, record.link_id);
                let parts = fork_parts.entry(key).or_default();
                insert_once(&mut parts.child_start, record, "fork-child-start")?;
            }
            _ => {}
        }
    }
    for (&(parent_pid, link_id), parts) in &fork_parts {
        let enter = parts
            .enter
            .with_context(|| format!("fork ({parent_pid},{link_id}) has no clone-enter"))?;
        let child_start = parts
            .child_start
            .with_context(|| format!("fork ({parent_pid},{link_id}) has no fork-child-start"))?;
        let parent_return = parts
            .parent_return
            .with_context(|| format!("fork ({parent_pid},{link_id}) has no clone-parent-return"))?;
        if child_start.related_pid != parent_pid
            || parent_return.related_pid != child_start.pid
            || enter.related_pid != 0
        {
            bail!("fork ({parent_pid},{link_id}) has inconsistent related pids");
        }
        let wall_ns = checked_delta(child_start.mono_ns, enter.mono_ns, "fork wall")?;
        let cpu_ns = checked_delta(
            parent_return.thread_cpu_ns()?,
            enter.thread_cpu_ns()?,
            "fork thread CPU",
        )?;
        push_observation(
            &mut observations,
            "fork",
            wall_ns,
            cpu_ns,
            enter.mono_ns,
            child_start.mono_ns,
        );
    }

    let mut exec_chains = 0usize;
    for (&pid, process_records) in &by_pid {
        validate_process_cpu_monotonic(pid, process_records)?;
        for (index, record) in process_records.iter().enumerate() {
            if record.phase != Phase::ExecveDispatch {
                continue;
            }
            let chain = find_exec_chain(pid, &process_records[index..])?;
            exec_chains += 1;
            add_process_segment(&mut observations, "old-image-exec", chain[0], chain[2])?;
            add_process_segment(&mut observations, "host-exec", chain[2], chain[3])?;
            add_process_segment(&mut observations, "resume", chain[3], chain[8])?;
            add_process_segment(&mut observations, "exec-total", chain[0], chain[8])?;
        }
        if let Some(fork_start) = process_records
            .iter()
            .find(|record| record.phase == Phase::ForkChildStart)
            && let Some(exec_dispatch) = process_records
                .iter()
                .find(|record| record.phase == Phase::ExecveDispatch)
        {
            add_process_segment(
                &mut observations,
                "child-to-exec",
                fork_start,
                exec_dispatch,
            )?;
        }
    }
    if exec_chains == 0 {
        bail!("exec-stamp export contains no complete exec chain");
    }

    let mut reaps = HashMap::new();
    for record in records
        .iter()
        .filter(|record| record.phase == Phase::WaitReaped)
    {
        if !libc::WIFEXITED(record.related_status) || libc::WEXITSTATUS(record.related_status) != 0
        {
            bail!(
                "line {} reaped child {} non-successfully (status={})",
                record.line,
                record.related_pid,
                record.related_status
            );
        }
        if reaps.insert(record.related_pid, record).is_some() {
            bail!(
                "child {} has multiple terminal reap records",
                record.related_pid
            );
        }
        if !child_to_fork.contains_key(&record.related_pid) {
            bail!(
                "reaped child {} has no authenticated fork link",
                record.related_pid
            );
        }
    }
    for child_pid in child_to_fork.keys() {
        if !reaps.contains_key(child_pid) {
            bail!("forked child {child_pid} has no terminal reap record");
        }
    }

    let mut runtime_returns = 0usize;
    let mut pre_host_exits = 0usize;
    let mut leaf_exit_residuals = 0usize;
    let mut unreaped_root_exits = 0usize;
    for (&pid, process_records) in &by_pid {
        let process_pre_host_exits: Vec<_> = process_records
            .iter()
            .filter(|record| record.phase == Phase::PreHostExit)
            .copied()
            .collect();
        let process_runtime_returns: Vec<_> = process_records
            .iter()
            .filter(|record| record.phase == Phase::RuntimeReturn)
            .copied()
            .collect();
        if process_pre_host_exits.len() > 1 || process_runtime_returns.len() > 1 {
            bail!("pid {pid} has duplicate terminal lifecycle stamps");
        }
        pre_host_exits += process_pre_host_exits.len();
        let exit_begins: Vec<_> = process_records
            .iter()
            .filter(|record| record.phase == Phase::ExitBegin)
            .copied()
            .collect();
        if exit_begins.len() > 1 {
            bail!("pid {pid} has multiple exit-begin records");
        }
        let Some(exit_begin) = exit_begins.first().copied() else {
            if reaps.contains_key(&pid) {
                bail!("reaped child {pid} has no exported exit lifecycle");
            }
            continue;
        };
        let runtime_return = process_runtime_returns.first().copied();
        let pre_host_exit = process_pre_host_exits.first().copied();
        let close = match (runtime_return, pre_host_exit) {
            (Some(runtime_return), Some(pre_host_exit)) => {
                runtime_returns += 1;
                add_process_segment(
                    &mut observations,
                    "runtime-unwind",
                    runtime_return,
                    pre_host_exit,
                )?;
                runtime_return
            }
            (Some(runtime_return), None) => {
                runtime_returns += 1;
                runtime_return
            }
            (None, Some(pre_host_exit)) => pre_host_exit,
            (None, None) => bail!("pid {pid} exit-begin has no terminal runtime stamp"),
        };
        add_process_segment(&mut observations, "exit-runtime", exit_begin, close)?;

        let Some(reap) = reaps.get(&pid).copied() else {
            unreaped_root_exits += 1;
            continue;
        };
        let anchor = pre_host_exit
            .or(runtime_return)
            .with_context(|| format!("pid {pid} has no terminal anchor"))?;
        if !process_records
            .iter()
            .any(|record| record.phase == Phase::CloneParentReturn)
        {
            let cpu_ns = checked_delta(
                reap.related_cpu_ns()?,
                anchor.process_cpu_ns()?,
                "leaf post-exit CPU",
            )?;
            let wall_ns = checked_delta(reap.mono_ns, anchor.mono_ns, "leaf post-exit wall")?;
            push_observation(
                &mut observations,
                "leaf-post-exit",
                wall_ns,
                cpu_ns,
                anchor.mono_ns,
                reap.mono_ns,
            );
            leaf_exit_residuals += 1;
        }
    }
    if unreaped_root_exits > 1 {
        bail!("found {unreaped_root_exits} exited processes without terminal reap records");
    }

    let opportunity_names = [
        "fork",
        "exec-total",
        "exit-runtime",
        "runtime-unwind",
        "leaf-post-exit",
    ];
    let measured_opportunity_cpu_ns = opportunity_names.iter().try_fold(0u64, |sum, name| {
        observations
            .get(name)
            .into_iter()
            .flatten()
            .try_fold(sum, |sum, value| {
                sum.checked_add(value.cpu_ns)
                    .context("measured opportunity CPU overflow")
            })
    })?;
    let opportunity_intervals = opportunity_names
        .iter()
        .flat_map(|name| observations.get(name).into_iter().flatten())
        .map(|observation| observation.interval)
        .collect::<Vec<_>>();
    let opportunity_wall_union_ns = interval_union_ns(opportunity_intervals)?;

    let segments = observations
        .into_iter()
        .map(|(name, values)| {
            let wall = distribution(values.iter().map(|value| value.wall_ns))?;
            let cpu = distribution(values.iter().map(|value| value.cpu_ns))?;
            Ok((
                name.to_owned(),
                SegmentReport {
                    cpu_share_of_guest_tree: ratio(cpu.sum_ns, guest_tree_ns),
                    cpu_share_of_invocation: ratio(cpu.sum_ns, invocation_ns),
                    wall,
                    cpu,
                },
            ))
        })
        .collect::<anyhow::Result<BTreeMap<_, _>>>()?;

    Ok(ExecStampReport {
        schema: SCHEMA,
        input_sha256: String::new(),
        records: records.len(),
        exec_chains,
        fork_pairs: fork_parts.len(),
        terminal_reaps: reaps.len(),
        workload_ns,
        run_cpu: RunCpuReport {
            supervisor_ns,
            guest_tree_ns,
            invocation_ns,
        },
        measured_opportunity_cpu_ns,
        measured_opportunity_cpu_share_of_guest_tree: ratio(
            measured_opportunity_cpu_ns,
            guest_tree_ns,
        ),
        measured_opportunity_cpu_share_of_invocation: ratio(
            measured_opportunity_cpu_ns,
            invocation_ns,
        ),
        opportunity_wall_union_ns,
        opportunity_wall_union_upper_bound_share_of_workload: ratio(
            opportunity_wall_union_ns,
            workload_ns,
        ),
        coverage: CoverageReport {
            phase_counts,
            pids: pids.len(),
            runtime_returns,
            pre_host_exits,
            leaf_exit_residuals,
            unreaped_root_exits,
        },
        segments,
    })
}

fn parse_record(line_number: usize, line: &str) -> anyhow::Result<Record> {
    let parts: Vec<_> = line.split('|').collect();
    if parts.len() != 14 || parts[0] != "EXECSTAMP2" {
        bail!("line {line_number} is not one exact EXECSTAMP2 record");
    }
    let field = |index: usize, name: &str| -> anyhow::Result<&str> {
        let (actual, value) = parts[index]
            .split_once('=')
            .with_context(|| format!("line {line_number} field {index} has no `=`"))?;
        if actual != name || value.is_empty() {
            bail!("line {line_number} expected `{name}=...` at field {index}");
        }
        Ok(value)
    };
    let parse_u64 = |index, name| -> anyhow::Result<u64> {
        field(index, name)?
            .parse()
            .with_context(|| format!("line {line_number} `{name}` is not u64"))
    };
    let pid = u32::try_from(parse_u64(1, "pid")?)
        .with_context(|| format!("line {line_number} pid exceeds u32"))?;
    let phase = Phase::parse(field(2, "phase")?)?;
    let valid = u8::try_from(parse_u64(3, "valid")?)
        .with_context(|| format!("line {line_number} validity exceeds u8"))?;
    let record = Record {
        line: line_number,
        pid,
        phase,
        valid,
        mono_ns: parse_u64(4, "mono_ns")?,
        process_user_ns: parse_u64(5, "process_user_ns")?,
        process_system_ns: parse_u64(6, "process_system_ns")?,
        thread_user_ns: parse_u64(7, "thread_user_ns")?,
        thread_system_ns: parse_u64(8, "thread_system_ns")?,
        related_pid: u32::try_from(parse_u64(9, "related_pid")?)
            .with_context(|| format!("line {line_number} related pid exceeds u32"))?,
        link_id: parse_u64(10, "link_id")?,
        related_status: field(11, "related_status")?
            .parse()
            .with_context(|| format!("line {line_number} related status is not i32"))?,
        related_user_ns: parse_u64(12, "related_user_ns")?,
        related_system_ns: parse_u64(13, "related_system_ns")?,
    };
    validate_record_shape(&record)?;
    Ok(record)
}

fn validate_record_shape(record: &Record) -> anyhow::Result<()> {
    if record.pid == 0 || record.mono_ns == 0 {
        bail!("line {} has a zero pid or monotonic stamp", record.line);
    }
    match record.phase {
        Phase::CloneEnter => {
            require_live_shape(record, true)?;
            if record.related_pid != 0 {
                bail!(
                    "line {} clone-enter unexpectedly names a child",
                    record.line
                );
            }
        }
        Phase::ForkChildStart | Phase::CloneParentReturn => {
            require_live_shape(record, true)?;
            if record.related_pid == 0 {
                bail!("line {} fork-side record has no related pid", record.line);
            }
        }
        Phase::WaitReaped => {
            if record.valid != REQUIRED_RELATED_VALIDITY
                || record.related_pid == 0
                || record.link_id != 0
            {
                bail!("line {} has an invalid terminal-reap shape", record.line);
            }
        }
        Phase::RunComplete => {
            if record.valid != REQUIRED_RELATED_VALIDITY
                || record.related_pid != 0
                || record.link_id != 0
                || record.related_status != 0
            {
                bail!("line {} has an invalid run-complete shape", record.line);
            }
        }
        _ => require_live_shape(record, false)?,
    }
    Ok(())
}

fn require_live_shape(record: &Record, linked: bool) -> anyhow::Result<()> {
    if record.valid != REQUIRED_LIVE_VALIDITY
        || (record.link_id != 0) != linked
        || record.related_status != 0
        || record.related_user_ns != 0
        || record.related_system_ns != 0
        || (!linked && record.related_pid != 0)
    {
        bail!("line {} has an invalid live-record shape", record.line);
    }
    Ok(())
}

fn insert_once<'a>(
    slot: &mut Option<&'a Record>,
    record: &'a Record,
    kind: &str,
) -> anyhow::Result<()> {
    if slot.replace(record).is_some() {
        bail!("duplicate {kind} for fork link {}", record.link_id);
    }
    Ok(())
}

fn validate_process_cpu_monotonic(pid: u32, records: &[&Record]) -> anyhow::Result<()> {
    for pair in records.windows(2) {
        if pair[1].process_cpu_ns()? < pair[0].process_cpu_ns()? {
            bail!(
                "pid {pid} process CPU regressed between lines {} and {}",
                pair[0].line,
                pair[1].line
            );
        }
    }
    Ok(())
}

fn find_exec_chain<'a>(pid: u32, records: &'a [&Record]) -> anyhow::Result<[&'a Record; 9]> {
    let expected = [
        Phase::ExecveDispatch,
        Phase::CapsulePrepare,
        Phase::PreExec,
        Phase::MainEntry,
        Phase::ProbesReady,
        Phase::ResumeEntry,
        Phase::DispatcherReady,
        Phase::ImageMapped,
        Phase::RuntimeReady,
    ];
    let relevant: Vec<_> = records
        .iter()
        .copied()
        .filter(|record| expected.contains(&record.phase))
        .take(expected.len())
        .collect();
    if relevant.len() != expected.len()
        || !relevant
            .iter()
            .zip(expected)
            .all(|(record, expected)| record.phase == expected)
    {
        bail!("pid {pid} has an incomplete or out-of-order exec chain");
    }
    relevant
        .try_into()
        .map_err(|_| anyhow::anyhow!("pid {pid} exec-chain conversion failed"))
}

fn add_process_segment(
    observations: &mut BTreeMap<&'static str, Vec<Observation>>,
    name: &'static str,
    start: &Record,
    end: &Record,
) -> anyhow::Result<()> {
    if start.pid != end.pid {
        bail!("segment {name} crosses pid {} -> {}", start.pid, end.pid);
    }
    let wall_ns = checked_delta(end.mono_ns, start.mono_ns, "segment wall")?;
    let cpu_ns = checked_delta(
        end.process_cpu_ns()?,
        start.process_cpu_ns()?,
        "segment process CPU",
    )?;
    push_observation(
        observations,
        name,
        wall_ns,
        cpu_ns,
        start.mono_ns,
        end.mono_ns,
    );
    Ok(())
}

fn push_observation(
    observations: &mut BTreeMap<&'static str, Vec<Observation>>,
    name: &'static str,
    wall_ns: u64,
    cpu_ns: u64,
    start_ns: u64,
    end_ns: u64,
) {
    observations.entry(name).or_default().push(Observation {
        wall_ns,
        cpu_ns,
        interval: (start_ns, end_ns),
    });
}

fn checked_delta(end: u64, start: u64, name: &str) -> anyhow::Result<u64> {
    end.checked_sub(start)
        .with_context(|| format!("{name} regressed ({start} -> {end})"))
}

fn distribution(values: impl Iterator<Item = u64>) -> anyhow::Result<Distribution> {
    let mut values: Vec<_> = values.collect();
    if values.is_empty() {
        bail!("cannot summarize an empty segment population");
    }
    values.sort_unstable();
    let sum_ns = values.iter().try_fold(0u64, |sum, value| {
        sum.checked_add(*value).context("segment sum overflow")
    })?;
    let median_ns = values[(values.len() - 1) / 2];
    let p90_index = (values.len() * 9).div_ceil(10).saturating_sub(1);
    Ok(Distribution {
        count: values.len(),
        sum_ns,
        median_ns,
        p90_ns: values[p90_index],
        max_ns: values[values.len() - 1],
    })
}

fn interval_union_ns(mut intervals: Vec<(u64, u64)>) -> anyhow::Result<u64> {
    intervals.sort_unstable();
    let mut total = 0u64;
    let Some((mut start, mut end)) = intervals.first().copied() else {
        return Ok(0);
    };
    for (next_start, next_end) in intervals.into_iter().skip(1) {
        if next_end < next_start {
            bail!("opportunity interval regressed");
        }
        if next_start <= end {
            end = end.max(next_end);
        } else {
            total = total
                .checked_add(end - start)
                .context("opportunity wall union overflow")?;
            start = next_start;
            end = next_end;
        }
    }
    total
        .checked_add(end - start)
        .context("opportunity wall union overflow")
}

fn ratio(numerator: u64, denominator: u64) -> f64 {
    numerator as f64 / denominator as f64
}

#[cfg(test)]
mod tests {
    use super::*;

    #[allow(clippy::too_many_arguments)]
    fn line(
        pid: u32,
        phase: &str,
        mono_ns: u64,
        process_ns: u64,
        thread_ns: u64,
        related_pid: u32,
        link_id: u64,
        related_status: i32,
        related_ns: u64,
    ) -> String {
        let valid = if phase == "wait-reaped" || phase == "run-complete" {
            15
        } else {
            7
        };
        format!(
            "EXECSTAMP2|pid={pid}|phase={phase}|valid={valid}|mono_ns={mono_ns}|\
             process_user_ns={process_ns}|process_system_ns=0|thread_user_ns={thread_ns}|\
             thread_system_ns=0|related_pid={related_pid}|link_id={link_id}|\
             related_status={related_status}|related_user_ns={related_ns}|related_system_ns=0\n"
        )
    }

    fn complete_fixture() -> String {
        let mut text = String::new();
        text += &line(100, "clone-enter", 100, 100, 50, 0, 1, 0, 0);
        text += &line(200, "fork-child-start", 110, 5, 5, 100, 1, 0, 0);
        text += &line(100, "clone-parent-return", 120, 120, 70, 200, 1, 0, 0);
        text += &line(200, "execve-dispatch", 130, 15, 15, 0, 0, 0, 0);
        text += &line(200, "capsule-prepare", 140, 20, 20, 0, 0, 0, 0);
        text += &line(200, "pre-exec", 150, 30, 30, 0, 0, 0, 0);
        text += &line(200, "main-entry", 170, 50, 50, 0, 0, 0, 0);
        text += &line(200, "probes-ready", 175, 55, 55, 0, 0, 0, 0);
        text += &line(200, "resume-entry", 180, 60, 60, 0, 0, 0, 0);
        text += &line(200, "dispatcher-ready", 185, 65, 65, 0, 0, 0, 0);
        text += &line(200, "image-mapped", 190, 70, 70, 0, 0, 0, 0);
        text += &line(200, "runtime-ready", 200, 80, 80, 0, 0, 0, 0);
        text += &line(200, "exit-begin", 300, 150, 150, 0, 0, 0, 0);
        text += &line(200, "runtime-return", 310, 160, 160, 0, 0, 0, 0);
        text += &line(200, "pre-host-exit", 315, 165, 165, 0, 0, 0, 0);
        text += &line(100, "wait-reaped", 320, 130, 80, 200, 0, 0, 180);
        text += &line(10, "run-complete", 400, 30, 30, 0, 0, 0, 220);
        text
    }

    #[test]
    fn complete_fixture_reconciles_cpu_and_relationships() {
        let report = parse_report(&complete_fixture(), 1_000).expect("complete fixture");
        assert_eq!(report.exec_chains, 1);
        assert_eq!(report.fork_pairs, 1);
        assert_eq!(report.terminal_reaps, 1);
        assert_eq!(report.run_cpu.guest_tree_ns, 220);
        assert_eq!(report.run_cpu.invocation_ns, 250);
        assert_eq!(report.measured_opportunity_cpu_ns, 115);
        assert_eq!(
            report.measured_opportunity_cpu_share_of_invocation,
            115.0 / 250.0
        );
        assert_eq!(
            report.segments["exec-total"].cpu_share_of_invocation,
            65.0 / 250.0
        );
        let json = serde_json::to_value(&report).expect("serialize report");
        assert_eq!(
            json["opportunity_wall_union_upper_bound_share_of_workload"],
            0.1
        );
        assert!(
            json.get("opportunity_wall_union_share_of_workload")
                .is_none()
        );
        assert_eq!(report.coverage.leaf_exit_residuals, 1);
    }

    #[test]
    fn v1_and_truncated_exports_fail_closed() {
        assert!(parse_report("EXECSTAMP1|pid=1\n", 1).is_err());
        let truncated = complete_fixture().trim_end().to_owned();
        assert!(parse_report(&truncated, 1).is_err());
    }

    #[test]
    fn missing_exec_phase_fails_closed() {
        let fixture =
            complete_fixture().replace(&line(200, "image-mapped", 190, 70, 70, 0, 0, 0, 0), "");
        assert!(parse_report(&fixture, 1_000).is_err());
    }

    #[test]
    fn reaped_child_without_exported_exit_lifecycle_fails_closed() {
        let fixture = complete_fixture()
            .replace(&line(200, "exit-begin", 300, 150, 150, 0, 0, 0, 0), "")
            .replace(&line(200, "runtime-return", 310, 160, 160, 0, 0, 0, 0), "")
            .replace(&line(200, "pre-host-exit", 315, 165, 165, 0, 0, 0, 0), "");
        assert!(parse_report(&fixture, 1_000).is_err());
    }

    #[test]
    fn duplicate_terminal_lifecycle_stamp_fails_closed() {
        let mut fixture = complete_fixture();
        fixture += &line(200, "runtime-return", 311, 161, 161, 0, 0, 0, 0);
        assert!(parse_report(&fixture, 1_000).is_err());
    }
}
