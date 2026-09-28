//! Strict reader for the HVPatch whole-carrier CPU attribution profile.
//!
//! Decomposes 100% of carrier CPU for one guest run into:
//!   - time in guest (`hv_vcpu_run`)
//!   - host syscall service (by class)
//!   - fault service (by fault class: first touch, COW, frame grant, stage-2)
//!   - EL1 mailbox/grant handling
//!   - executor scheduling/park/unpark
//!   - lock wait
//!
//! The D program emits an END aggregation. Its scalar `sample-population` is
//! authoritative only when every emitted stack count closes exactly to it, and
//! the capture fails closed on zero events or any lossy drop.

use std::collections::{BTreeMap, BTreeSet, btree_map::Entry};
use std::fs;
use std::path::Path;

use anyhow::{Context, Result, anyhow, bail};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::trace_profile::ProfileCaptureStatus;

const PREFIX: &str = "HVPCARRIERATTR";
pub(crate) const PROGRAM_SHA256_PLACEHOLDER: &str =
    "/* CARRICK_HVPCARRIERCPUATTR_PROGRAM_SHA256 */";

/// Render the bundled template's immutable digest into the raw-stream header.
pub(crate) fn render_profile_script(template: &str) -> Result<String> {
    let slots = template.match_indices(PROGRAM_SHA256_PLACEHOLDER).count();
    if slots != 1 {
        bail!(
            "{PREFIX} profile template must contain exactly one program-SHA-256 placeholder, found {slots}"
        );
    }
    Ok(template.replacen(PROGRAM_SHA256_PLACEHOLDER, &program_sha256(), 1))
}

pub(crate) fn program_sha256() -> String {
    format!(
        "{:x}",
        Sha256::digest(
            carrick_runtime::dtrace_consumer::BUNDLED_HVPATCH_CARRIER_CPU_ATTRIBUTION_D.as_bytes(),
        )
    )
}

/// The four distinct fault classes specified for carrier CPU attribution.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum FaultClass {
    FirstTouch,
    Cow,
    FrameGrant,
    Stage2,
}

impl FaultClass {
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::FirstTouch => "first-touch",
            Self::Cow => "cow",
            Self::FrameGrant => "frame-grant",
            Self::Stage2 => "stage-2",
        }
    }
}

/// Primary attribution categories for carrier CPU.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "category", content = "detail", rename_all = "kebab-case")]
pub(crate) enum CpuCategory {
    GuestExecution,
    HostSyscall(String),
    FaultService(FaultClass),
    El1Mailbox,
    ExecutorScheduling,
    LockWait,
    Other,
}

/// Classify a user stack (frames ordered from leaf to root) into one of the
/// attribution categories.
pub(crate) fn classify_stack(frames: &[&str]) -> CpuCategory {
    // Walk frames leaf-to-root to identify the primary on-CPU activity.
    // 1. Check for executor parking on idle_condvar.
    for frame in frames {
        if frame.contains("idle_condvar") {
            return CpuCategory::ExecutorScheduling;
        }
    }

    // 2. Check for lock wait/contention near leaf (psynch, mutex, ulock, rwlock).
    for frame in frames {
        if frame.contains("psynch_cvwait")
            || frame.contains("psynch_mutexwait")
            || frame.contains("__ulock_wait")
            || frame.contains("hw_lock_lock_contended")
            || frame.contains("lck_mtx_lock")
            || frame.contains("lck_rw_lock_shared")
            || frame.contains("RawMutex::lock_slow")
            || frame.contains("parking_lot::raw_mutex")
        {
            return CpuCategory::LockWait;
        }
        // Don't search too deep for leaf lock primitives.
        if frame.contains("run_to_exit") || frame.contains("run_worker") {
            break;
        }
    }

    // 3. Check for EL1 mailbox / grant request handling.
    for frame in frames {
        if frame.contains("claim_frame_grant_request")
            || frame.contains("complete_grant")
            || frame.contains("frame_grant_mailbox")
            || frame.contains("publish_frame_grant_refusal")
            || frame.contains("cancel_frame_grant_request")
            || frame.contains("hvf_syscall_transport")
        {
            return CpuCategory::El1Mailbox;
        }
    }

    // 4. Check for fault service and specific fault classes.
    for frame in frames {
        if frame.contains("commit_resident_frame_grant")
            || frame.contains("prepare_el1_frame_grant")
            || frame.contains("publish_el1_frame_grant_on_host")
            || frame.contains("resident_frame_grant_plan")
        {
            return CpuCategory::FaultService(FaultClass::FrameGrant);
        }
        if frame.contains("resolve_frame_cow_fault")
            || frame.contains("note_cow_resolution")
            || frame.contains("cow_engine")
            || frame.contains("Stage1CowFault")
            || frame.contains("frame_cow")
        {
            return CpuCategory::FaultService(FaultClass::Cow);
        }
        if frame.contains("inventory_hv_vm_map_replay")
            || frame.contains("map_host_alias")
            || frame.contains("lookup_shared_alias")
            || frame.contains("global_frame_stage2")
        {
            return CpuCategory::FaultService(FaultClass::Stage2);
        }
        if frame.contains("commit_resident_fault")
            || frame.contains("resident_fault_plan")
            || frame.contains("apply_first_touch")
            || frame.contains("commit_mmap_growdown")
            || frame.contains("mmap_growdown_fault_plan")
            || frame.contains("resolve_stale_stage1_fault")
            || frame.contains("handle_user_abort")
            || frame.contains("arm_fast_fault")
            || frame.contains("vm_fault_internal")
            || frame.contains("vm_fault")
        {
            return CpuCategory::FaultService(FaultClass::FirstTouch);
        }
    }

    // 5. Check for host syscall service by class.
    for frame in frames {
        if frame.contains("openat")
            || frame.contains("open_at_path")
            || frame.contains("sys_openat")
        {
            return CpuCategory::HostSyscall("openat".to_owned());
        }
        if frame.contains("sys_mmap")
            || frame.contains("handle_mmap")
            || frame.contains("mmap_pgoff")
            || (frame.contains("mmap")
                && !frame.contains("hv_vm_map")
                && !frame.contains("map_host_alias"))
        {
            return CpuCategory::HostSyscall("mmap".to_owned());
        }
        if frame.contains("munmap") || frame.contains("sys_munmap") {
            return CpuCategory::HostSyscall("munmap".to_owned());
        }
        if frame.contains("sys_brk") || frame.contains("handle_brk") || frame.contains("brk") {
            return CpuCategory::HostSyscall("brk".to_owned());
        }
        if frame.contains("sys_write") || frame.contains("writev") || frame.contains("pwrite64") {
            return CpuCategory::HostSyscall("write".to_owned());
        }
        if frame.contains("sys_read") || frame.contains("readv") || frame.contains("pread64") {
            return CpuCategory::HostSyscall("read".to_owned());
        }
        if frame.contains("newfstatat")
            || frame.contains("sys_newfstatat")
            || frame.contains("fstat")
            || frame.contains("statx")
        {
            return CpuCategory::HostSyscall("newfstatat".to_owned());
        }
        if frame.contains("futex") || frame.contains("sys_futex") || frame.contains("futex_route") {
            return CpuCategory::HostSyscall("futex".to_owned());
        }
        if frame.contains("sys_close") || frame.contains("close") {
            return CpuCategory::HostSyscall("close".to_owned());
        }
        if frame.contains("renameat") || frame.contains("sys_renameat") {
            return CpuCategory::HostSyscall("renameat".to_owned());
        }
        if frame.contains("unlinkat") || frame.contains("sys_unlinkat") {
            return CpuCategory::HostSyscall("unlinkat".to_owned());
        }
        if frame.contains("getdents64") || frame.contains("sys_getdents64") {
            return CpuCategory::HostSyscall("getdents64".to_owned());
        }
        if frame.contains("execve") || frame.contains("sys_execve") {
            return CpuCategory::HostSyscall("execve".to_owned());
        }
        if frame.contains("sys_clone") || frame.contains("clone") {
            return CpuCategory::HostSyscall("clone".to_owned());
        }
        if frame.contains("pipe2") || frame.contains("sys_pipe2") {
            return CpuCategory::HostSyscall("pipe".to_owned());
        }
        if frame.contains("fcntl") || frame.contains("sys_fcntl") {
            return CpuCategory::HostSyscall("fcntl".to_owned());
        }
        if frame.contains("ppoll")
            || frame.contains("sys_ppoll")
            || frame.contains("epoll_pwait")
            || frame.contains("epoll_ctl")
        {
            return CpuCategory::HostSyscall("poll".to_owned());
        }
        if frame.contains("socket")
            || frame.contains("bind")
            || frame.contains("connect")
            || frame.contains("sendto")
            || frame.contains("recvfrom")
        {
            return CpuCategory::HostSyscall("socket".to_owned());
        }
        if frame.contains("SyscallDispatcher")
            || frame.contains("dispatch_syscall")
            || frame.contains("syscall_service")
        {
            return CpuCategory::HostSyscall("other-syscall".to_owned());
        }
    }

    // 6. Check for executor scheduling/park/unpark.
    for frame in frames {
        if frame.contains("Scheduler::")
            || frame.contains("take_row_bound")
            || frame.contains("run_worker")
            || frame.contains("mn_admit")
            || frame.contains("mn_reclaim")
            || frame.contains("executor_claim")
            || frame.contains("scheduler_wake")
            || frame.contains("lease_settle")
            || frame.contains("vtimer")
        {
            return CpuCategory::ExecutorScheduling;
        }
    }

    // 7. Check for guest execution (hv_vcpu_run).
    for frame in frames {
        if frame.contains("hv_vcpu_run")
            || frame.contains("Vcpu::run")
            || frame.contains("HvfAarch64Vcpu::run")
            || frame.contains("run_to_exit")
        {
            return CpuCategory::GuestExecution;
        }
    }

    CpuCategory::Other
}

/// Machine-readable summary of HVPatch carrier CPU attribution.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub(crate) struct HvpatchCarrierCpuAttributionSummary {
    pub(crate) sample_population: u64,
    pub(crate) stack_population: u64,
    pub(crate) stack_count: u64,
    pub(crate) program_sha256: String,
    pub(crate) image_text_base: String,
    pub(crate) guest_execution_samples: u64,
    pub(crate) host_syscall_samples: u64,
    pub(crate) fault_service_samples: u64,
    pub(crate) el1_mailbox_samples: u64,
    pub(crate) executor_scheduling_samples: u64,
    pub(crate) lock_wait_samples: u64,
    pub(crate) other_samples: u64,
    pub(crate) syscall_classes: BTreeMap<String, u64>,
    pub(crate) fault_classes: BTreeMap<String, u64>,
    pub(crate) usdt_metrics: BTreeMap<String, u64>,
    #[serde(skip)]
    pub(crate) raw: String,
}

impl HvpatchCarrierCpuAttributionSummary {
    pub(crate) fn from_path(path: &Path, status: ProfileCaptureStatus) -> Result<Self> {
        let raw = fs::read_to_string(path).with_context(|| {
            format!("read HVPatch carrier attribution stream {}", path.display())
        })?;
        Self::from_raw(raw, status)
    }

    pub(crate) fn from_raw(raw: String, status: ProfileCaptureStatus) -> Result<Self> {
        require_lossless(status)?;

        let mut summary = None;
        let mut header = None;
        let mut population = None;
        let mut image_text_base = None;
        let mut section_seen = false;
        let mut stack_frames = Vec::new();
        let mut stack_count = 0_u64;
        let mut stack_population = 0_u64;

        let mut guest_execution_samples = 0_u64;
        let mut host_syscall_samples = 0_u64;
        let mut fault_service_samples = 0_u64;
        let mut el1_mailbox_samples = 0_u64;
        let mut executor_scheduling_samples = 0_u64;
        let mut lock_wait_samples = 0_u64;
        let mut other_samples = 0_u64;

        let mut syscall_classes = BTreeMap::new();
        let mut fault_classes = BTreeMap::new();
        let mut usdt_metrics = BTreeMap::new();

        for line in raw.lines() {
            if !section_seen {
                if line.is_empty() {
                    continue;
                }
                let record = Record::parse(line)?;
                match record.tag.as_str() {
                    "header" => {
                        record.exact_fields(&["program_sha256"])?;
                        if header
                            .replace(record.value("program_sha256")?.to_owned())
                            .is_some()
                        {
                            bail!("duplicate {PREFIX} header");
                        }
                    }
                    "summary" => {
                        if summary.replace(Summary::parse(&record)?).is_some() {
                            bail!("duplicate {PREFIX} summary");
                        }
                    }
                    "sample-population" => {
                        record.exact_fields(&["count"])?;
                        if population.replace(record.u64("count")?).is_some() {
                            bail!("duplicate {PREFIX} sample-population");
                        }
                    }
                    "image" => {
                        record.exact_fields(&["host_pid", "text_base", "slide"])?;
                        if image_text_base
                            .replace(record.value("text_base")?.to_owned())
                            .is_some()
                        {
                            bail!("duplicate {PREFIX} image");
                        }
                    }
                    "section=usdt-metrics" => {
                        record.exact_fields(&[])?;
                    }
                    "usdt" => {
                        record.exact_fields(&["metric", "count"])?;
                        let metric = record.value("metric")?.to_owned();
                        let count = record.u64("count")?;
                        usdt_metrics.insert(metric, count);
                    }
                    "section=user-stacks" => {
                        record.exact_fields(&[])?;
                        section_seen = true;
                    }
                    other => bail!("unknown {PREFIX} record tag {other:?}"),
                }
                continue;
            }

            if line.starts_with(PREFIX) {
                bail!("{PREFIX} record appears after the user-stacks section");
            }
            let trimmed = line.trim();
            if trimmed.is_empty() {
                continue;
            }
            if is_canonical_u64(trimmed) {
                if stack_frames.is_empty() {
                    bail!("{PREFIX} stack count has no preceding user-stack frames");
                }
                let count = parse_u64(trimmed, "stack count")?;
                if count == 0 {
                    bail!("{PREFIX} emitted a zero-count user stack");
                }
                stack_population = stack_population
                    .checked_add(count)
                    .ok_or_else(|| anyhow!("{PREFIX} stack count overflow"))?;
                stack_count = stack_count
                    .checked_add(1)
                    .ok_or_else(|| anyhow!("{PREFIX} stack cardinality overflow"))?;

                // Classify the completed stack trace.
                let frame_slices: Vec<&str> = stack_frames.iter().map(String::as_str).collect();
                let category = classify_stack(&frame_slices);
                match category {
                    CpuCategory::GuestExecution => {
                        guest_execution_samples = guest_execution_samples
                            .checked_add(count)
                            .ok_or_else(|| anyhow!("guest execution overflow"))?;
                    }
                    CpuCategory::HostSyscall(class) => {
                        host_syscall_samples = host_syscall_samples
                            .checked_add(count)
                            .ok_or_else(|| anyhow!("host syscall overflow"))?;
                        *syscall_classes.entry(class).or_insert(0_u64) += count;
                    }
                    CpuCategory::FaultService(class) => {
                        fault_service_samples = fault_service_samples
                            .checked_add(count)
                            .ok_or_else(|| anyhow!("fault service overflow"))?;
                        *fault_classes
                            .entry(class.as_str().to_owned())
                            .or_insert(0_u64) += count;
                    }
                    CpuCategory::El1Mailbox => {
                        el1_mailbox_samples = el1_mailbox_samples
                            .checked_add(count)
                            .ok_or_else(|| anyhow!("el1 mailbox overflow"))?;
                    }
                    CpuCategory::ExecutorScheduling => {
                        executor_scheduling_samples = executor_scheduling_samples
                            .checked_add(count)
                            .ok_or_else(|| anyhow!("executor scheduling overflow"))?;
                    }
                    CpuCategory::LockWait => {
                        lock_wait_samples = lock_wait_samples
                            .checked_add(count)
                            .ok_or_else(|| anyhow!("lock wait overflow"))?;
                    }
                    CpuCategory::Other => {
                        other_samples = other_samples
                            .checked_add(count)
                            .ok_or_else(|| anyhow!("other samples overflow"))?;
                    }
                }

                stack_frames.clear();
            } else {
                stack_frames.push(trimmed.to_owned());
            }
        }

        let header = header.ok_or_else(|| anyhow!("{PREFIX} stream has no header"))?;
        if header != program_sha256() {
            bail!(
                "{PREFIX} header program_sha256 {header} does not name the bundled carrier attribution program ({})",
                program_sha256()
            );
        }
        let summary = summary.ok_or_else(|| anyhow!("{PREFIX} stream has no summary"))?;
        let sample_population =
            population.ok_or_else(|| anyhow!("{PREFIX} stream has no sample-population"))?;
        if !section_seen {
            bail!("{PREFIX} stream has no user-stacks section");
        }
        if !stack_frames.is_empty() {
            bail!("{PREFIX} user-stack aggregation ends without its count");
        }
        summary.validate()?;
        if sample_population == 0 || stack_count == 0 {
            bail!("{PREFIX} captured no user-stack population");
        }
        if stack_population != sample_population {
            bail!(
                "{PREFIX} stack-count closure failed: sample-population={sample_population}, user-stack-counts={stack_population}"
            );
        }

        let image_text_base = image_text_base
            .ok_or_else(|| anyhow!("{PREFIX} stream has no carrier image record"))?;

        Ok(Self {
            sample_population,
            stack_population,
            stack_count,
            program_sha256: program_sha256(),
            image_text_base,
            guest_execution_samples,
            host_syscall_samples,
            fault_service_samples,
            el1_mailbox_samples,
            executor_scheduling_samples,
            lock_wait_samples,
            other_samples,
            syscall_classes,
            fault_classes,
            usdt_metrics,
            raw,
        })
    }

    pub(crate) fn guest_execution_share(&self) -> f64 {
        share(self.guest_execution_samples, self.sample_population)
    }

    pub(crate) fn host_syscall_share(&self) -> f64 {
        share(self.host_syscall_samples, self.sample_population)
    }

    pub(crate) fn fault_service_share(&self) -> f64 {
        share(self.fault_service_samples, self.sample_population)
    }

    pub(crate) fn el1_mailbox_share(&self) -> f64 {
        share(self.el1_mailbox_samples, self.sample_population)
    }

    pub(crate) fn executor_scheduling_share(&self) -> f64 {
        share(self.executor_scheduling_samples, self.sample_population)
    }

    pub(crate) fn lock_wait_share(&self) -> f64 {
        share(self.lock_wait_samples, self.sample_population)
    }

    pub(crate) fn other_share(&self) -> f64 {
        share(self.other_samples, self.sample_population)
    }

    pub(crate) fn render_human(&self) -> String {
        let mut out = String::new();
        out.push_str(&format!(
            "HVPatch carrier CPU attribution: total_samples={}, user_stacks={}, image_text_base={}\n",
            self.sample_population, self.stack_count, self.image_text_base
        ));
        out.push_str(&format!(
            "  guest_execution:     {:>8} ({:>5.1}%)\n",
            self.guest_execution_samples,
            self.guest_execution_share() * 100.0
        ));
        out.push_str(&format!(
            "  host_syscall:        {:>8} ({:>5.1}%)\n",
            self.host_syscall_samples,
            self.host_syscall_share() * 100.0
        ));
        for (class, count) in &self.syscall_classes {
            out.push_str(&format!(
                "    {:<18} {:>8} ({:>5.1}%)\n",
                class,
                count,
                share(*count, self.sample_population) * 100.0
            ));
        }
        out.push_str(&format!(
            "  fault_service:       {:>8} ({:>5.1}%)\n",
            self.fault_service_samples,
            self.fault_service_share() * 100.0
        ));
        for (class, count) in &self.fault_classes {
            out.push_str(&format!(
                "    {:<18} {:>8} ({:>5.1}%)\n",
                class,
                count,
                share(*count, self.sample_population) * 100.0
            ));
        }
        out.push_str(&format!(
            "  el1_mailbox:         {:>8} ({:>5.1}%)\n",
            self.el1_mailbox_samples,
            self.el1_mailbox_share() * 100.0
        ));
        out.push_str(&format!(
            "  executor_scheduling: {:>8} ({:>5.1}%)\n",
            self.executor_scheduling_samples,
            self.executor_scheduling_share() * 100.0
        ));
        out.push_str(&format!(
            "  lock_wait:           {:>8} ({:>5.1}%)\n",
            self.lock_wait_samples,
            self.lock_wait_share() * 100.0
        ));
        if self.other_samples > 0 {
            out.push_str(&format!(
                "  other:               {:>8} ({:>5.1}%)\n",
                self.other_samples,
                self.other_share() * 100.0
            ));
        }
        out.trim_end().to_owned()
    }
}

fn share(count: u64, total: u64) -> f64 {
    if total == 0 {
        0.0
    } else {
        count as f64 / total as f64
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
        if parts.next() != Some(PREFIX) {
            bail!("unknown {PREFIX} protocol prefix in {line:?}");
        }
        let tag = parts
            .next()
            .filter(|tag| !tag.is_empty())
            .ok_or_else(|| anyhow!("truncated {PREFIX} record"))?
            .to_owned();
        let mut fields = BTreeMap::new();
        for raw in parts {
            let (key, value) = raw
                .split_once('=')
                .ok_or_else(|| anyhow!("{PREFIX} field lacks '=': {raw:?}"))?;
            if key.is_empty() || value.is_empty() {
                bail!("{PREFIX} field has an empty key or value");
            }
            match fields.entry(key.to_owned()) {
                Entry::Vacant(slot) => {
                    slot.insert(value.to_owned());
                }
                Entry::Occupied(_) => bail!("duplicate {PREFIX} field {key:?}"),
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
            bail!("{PREFIX} {:?} field contract mismatch", self.tag);
        }
        Ok(())
    }

    fn value(&self, field: &str) -> Result<&str> {
        self.fields
            .get(field)
            .map(String::as_str)
            .ok_or_else(|| anyhow!("{PREFIX} {:?} record lacks {field:?}", self.tag))
    }

    fn u64(&self, field: &str) -> Result<u64> {
        parse_u64(self.value(field)?, field)
    }
}

#[derive(Clone, Copy, Debug)]
struct Summary {
    root_exited: u64,
    bounded: u64,
    errors: u64,
    saw_sample: u64,
}

impl Summary {
    fn parse(record: &Record) -> Result<Self> {
        record.exact_fields(&["status", "root_exited", "bounded", "errors", "saw_sample"])?;
        if record.value("status")? != "ok" {
            bail!("{PREFIX} producer reported an error");
        }
        Ok(Self {
            root_exited: record.u64("root_exited")?,
            bounded: record.u64("bounded")?,
            errors: record.u64("errors")?,
            saw_sample: record.u64("saw_sample")?,
        })
    }

    fn validate(self) -> Result<()> {
        if self.root_exited != 1 || self.bounded != 0 || self.errors != 0 || self.saw_sample != 1 {
            bail!(
                "{PREFIX} producer summary is not a clean completed capture: root_exited={}, bounded={}, errors={}, saw_sample={}",
                self.root_exited,
                self.bounded,
                self.errors,
                self.saw_sample,
            );
        }
        Ok(())
    }
}

fn is_canonical_u64(value: &str) -> bool {
    value == "0" || (!value.starts_with('0') && value.bytes().all(|byte| byte.is_ascii_digit()))
}

fn parse_u64(value: &str, field: &str) -> Result<u64> {
    if !is_canonical_u64(value) {
        bail!("{PREFIX} {field} is not a canonical unsigned integer: {value:?}");
    }
    value
        .parse()
        .with_context(|| format!("invalid {PREFIX} {field}"))
}

fn require_lossless(status: ProfileCaptureStatus) -> Result<()> {
    if status != ProfileCaptureStatus::default() {
        bail!(
            "{PREFIX} capture is not lossless: principal={}, aggregation={}, dynamic={}, dynamic_rinse={}, dynamic_dirty={}, other={}, interrupted={}",
            status.principal_drops,
            status.aggregation_drops,
            status.dynamic_drops,
            status.dynamic_rinse_drops,
            status.dynamic_dirty_drops,
            status.other_drops,
            status.interrupted,
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_stream() -> String {
        let p_sha = program_sha256();
        [
            &format!("HVPCARRIERATTR|header|program_sha256={p_sha}"),
            "HVPCARRIERATTR|image|host_pid=1234|text_base=0x100000000|slide=0x0",
            "HVPCARRIERATTR|summary|status=ok|root_exited=1|bounded=0|errors=0|saw_sample=1",
            "HVPCARRIERATTR|sample-population|count=100",
            "HVPCARRIERATTR|section=usdt-metrics",
            "HVPCARRIERATTR|usdt|metric=syscall-services|count=20",
            "HVPCARRIERATTR|usdt|metric=vcpu-faults|count=15",
            "HVPCARRIERATTR|usdt|metric=cow-events|count=5",
            "HVPCARRIERATTR|usdt|metric=frame-grants|count=4",
            "HVPCARRIERATTR|usdt|metric=stage2-aliases|count=3",
            "HVPCARRIERATTR|section=user-stacks",
            // Guest execution (hv_vcpu_run): 40 samples
            "              carrick`hv_vcpu_run+0x10",
            "              carrick`carrick_vmm_hvf::trap::HvfAarch64Vcpu::run_to_exit+0x120",
            "              40",
            "",
            // Host syscall: openat: 10 samples
            "              libsystem_kernel.dylib`__openat+0x8",
            "              carrick`carrick_kernel::dispatch::fs::openat+0x40",
            "              carrick`carrick_kernel::dispatch::SyscallDispatcher::dispatch+0x100",
            "              10",
            "",
            // Host syscall: mmap: 10 samples
            "              libsystem_kernel.dylib`__mmap+0x8",
            "              carrick`carrick_kernel::dispatch::mem::mmap+0x50",
            "              carrick`carrick_kernel::dispatch::SyscallDispatcher::dispatch+0x100",
            "              10",
            "",
            // Fault: first touch: 6 samples
            "              carrick`carrick_kernel::dispatch::mem::fault::commit_resident_fault+0x50",
            "              carrick`carrick_runtime::vcpu_loop::signal::resolve_mutating_fault+0x80",
            "              6",
            "",
            // Fault: COW: 4 samples
            "              carrick`carrick_vmm_hvf::trap::cow_engine::resolve_frame_cow_fault+0x30",
            "              carrick`carrick_vmm_hvf::trap::run_to_exit+0x100",
            "              4",
            "",
            // Fault: frame grant: 3 samples
            "              carrick`carrick_runtime::vcpu_loop::signal::commit_resident_frame_grant+0x40",
            "              carrick`carrick_runtime::vcpu_loop::signal::resolve_mutating_fault+0x80",
            "              3",
            "",
            // Fault: stage-2: 2 samples
            "              carrick`carrick_vmm_hvf::trap::inventory_hv_vm_map_replay+0x30",
            "              carrick`carrick_vmm_hvf::trap::run_to_exit+0x100",
            "              2",
            "",
            // EL1 mailbox: 5 samples
            "              carrick`carrick_runtime::vcpu_loop::signal::claim_frame_grant_request+0x20",
            "              carrick`carrick_runtime::vcpu_loop::signal::resolve_mutating_fault+0x80",
            "              5",
            "",
            // Executor scheduling: 8 samples
            "              carrick`carrick_kernel::kernel::scheduler::idle_condvar+0x10",
            "              carrick`carrick_kernel::kernel::scheduler::Scheduler::take+0x90",
            "              8",
            "",
            // Lock wait: 7 samples
            "              libsystem_kernel.dylib`__psynch_mutexwait+0x8",
            "              carrick`parking_lot::raw_mutex::RawMutex::lock_slow+0x40",
            "              carrick`carrick_kernel::dispatch::fs::openat+0x20",
            "              7",
            "",
            // Other: 5 samples
            "              carrick`some_other_helper+0x10",
            "              5",
            "",
        ]
        .join("\n")
    }

    #[test]
    fn parse_valid_carrier_cpu_attribution_stream() {
        let stream = sample_stream();
        let summary =
            HvpatchCarrierCpuAttributionSummary::from_raw(stream, ProfileCaptureStatus::default())
                .expect("summary parse");

        assert_eq!(summary.sample_population, 100);
        assert_eq!(summary.stack_population, 100);
        assert_eq!(summary.stack_count, 11);
        assert_eq!(summary.guest_execution_samples, 40);
        assert_eq!(summary.host_syscall_samples, 20);
        assert_eq!(summary.fault_service_samples, 15);
        assert_eq!(summary.el1_mailbox_samples, 5);
        assert_eq!(summary.executor_scheduling_samples, 8);
        assert_eq!(summary.lock_wait_samples, 7);
        assert_eq!(summary.other_samples, 5);

        assert_eq!(summary.syscall_classes.get("openat"), Some(&10));
        assert_eq!(summary.syscall_classes.get("mmap"), Some(&10));

        assert_eq!(summary.fault_classes.get("first-touch"), Some(&6));
        assert_eq!(summary.fault_classes.get("cow"), Some(&4));
        assert_eq!(summary.fault_classes.get("frame-grant"), Some(&3));
        assert_eq!(summary.fault_classes.get("stage-2"), Some(&2));

        assert_eq!(summary.usdt_metrics.get("syscall-services"), Some(&20));
        assert_eq!(summary.usdt_metrics.get("vcpu-faults"), Some(&15));

        // Shares
        assert!((summary.guest_execution_share() - 0.40).abs() < 1e-6);
        assert!((summary.host_syscall_share() - 0.20).abs() < 1e-6);
        assert!((summary.fault_service_share() - 0.15).abs() < 1e-6);
        assert!((summary.el1_mailbox_share() - 0.05).abs() < 1e-6);
        assert!((summary.executor_scheduling_share() - 0.08).abs() < 1e-6);
        assert!((summary.lock_wait_share() - 0.07).abs() < 1e-6);
        assert!((summary.other_share() - 0.05).abs() < 1e-6);

        // Human output check
        let human = summary.render_human();
        assert!(human.contains("HVPatch carrier CPU attribution"));
        assert!(human.contains("guest_execution:"));
        assert!(human.contains("40 ( 40.0%)"));
        assert!(human.contains("host_syscall:"));
        assert!(human.contains("20 ( 20.0%)"));
        assert!(human.contains("openat"));
        assert!(human.contains("10 ( 10.0%)"));
        assert!(human.contains("first-touch"));
        assert!(human.contains("6 (  6.0%)"));
    }

    #[test]
    fn rejects_stack_population_closure_mismatch() {
        let stream = sample_stream().replace(
            "HVPCARRIERATTR|sample-population|count=100",
            "HVPCARRIERATTR|sample-population|count=99",
        );
        let err =
            HvpatchCarrierCpuAttributionSummary::from_raw(stream, ProfileCaptureStatus::default())
                .expect_err("closure mismatch");
        assert!(err.to_string().contains("stack-count closure failed"));
    }

    #[test]
    fn rejects_lossy_capture() {
        let stream = sample_stream();
        let status = ProfileCaptureStatus {
            aggregation_drops: 1,
            ..Default::default()
        };
        let err = HvpatchCarrierCpuAttributionSummary::from_raw(stream, status)
            .expect_err("lossy capture");
        assert!(err.to_string().contains("not lossless"));
    }

    #[test]
    fn rejects_corrupt_summary_status() {
        for corrupt in [
            sample_stream().replace("root_exited=1", "root_exited=0"),
            sample_stream().replace("bounded=0", "bounded=1"),
            sample_stream().replace("errors=0", "errors=1"),
            sample_stream().replace("saw_sample=1", "saw_sample=0"),
            sample_stream().replace(&program_sha256(), &"00".repeat(32)),
        ] {
            assert!(
                HvpatchCarrierCpuAttributionSummary::from_raw(
                    corrupt,
                    ProfileCaptureStatus::default(),
                )
                .is_err()
            );
        }
    }

    #[test]
    fn render_script_placeholder_substitution() {
        let template = format!(
            "dtrace:::BEGIN {{ printf(\"HVPCARRIERATTR|header|program_sha256={}\"); }}",
            PROGRAM_SHA256_PLACEHOLDER
        );
        let rendered = render_profile_script(&template).expect("render");
        assert!(rendered.contains(&program_sha256()));
        assert!(!rendered.contains(PROGRAM_SHA256_PLACEHOLDER));
    }
}
