//! `boot_probe`: boot a CPL0 ring image as a [`SoftCarrier`], optionally
//! admit an initial guest MM through the shared
//! [`carrick_x86_cpl0_host::cpl0_boot::load_guest_mm`], then run until the
//! first carrier host exit (port I/O or `HLT`) or a failure, and say exactly
//! how far it got. The report is produced even when boot fails.

use std::fmt;
use std::sync::Arc;

use carrick_hal::PhysicalFrameInventory;
use carrick_softcpu_x86::{SoftAccessKind, SoftMachineExit, X86Exception, read_guest_bytes};
use carrick_x86::cpl0_entry::{FATAL_PORT, FAULT_DOORBELL_PORT};
use carrick_x86::{FaultDoorbellRecord, X86_FAULT_RECORD_U32_WORDS};
use carrick_x86_cpl0_host::cpl0_boot::{
    InitialReservationLimits, initial_extent_bytes_for, load_guest_mm,
};

use crate::carrier::{SoftBootImage, SoftCarrier, SoftStop};

/// Binds a stopped, booted carrier before its initial MM is admitted
/// (e.g. the shared kernel's issued root task).
pub type ProbeBind<'a> = &'a dyn Fn(&mut SoftCarrier) -> Result<(), String>;

/// The ring image and stopped-carrier shape to probe.
#[derive(Clone)]
pub struct ProbeImage<'a> {
    pub name: &'a str,
    pub elf: &'a [u8],
    /// Per-slot CPL3 fixture code mapped at `USER_CODE` (empty: none).
    pub programs: [&'a [u8]; 2],
    /// Production boot: an initial guest-MM extent of this many bytes.
    /// Ignored with `user_elf`, whose extent is sized by the shared policy.
    pub initial_extent_bytes: Option<usize>,
    /// The image is the test-support fixture build.
    pub fixture_image: bool,
    /// Production boot: admit this static x86-64 ELF as the initial guest MM
    /// (no argv or env) before running.
    pub user_elf: Option<&'a [u8]>,
    /// The production IPC window authority.
    pub ipc: Option<Arc<dyn carrick_el1_abi::IpcWindowBacking>>,
    /// Runs after boot and before initial-MM admission.
    pub bind: Option<ProbeBind<'a>>,
}

/// How a probe run ended.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum BootExit {
    /// Neutral preparation, memory installation or CPU programming failed.
    Setup(String),
    /// The shared initial-MM admission refused.
    Admission(String),
    /// The ring reached a carrier host exit (port I/O or `HLT`).
    HostExit(SoftMachineExit),
    /// A complete fault-doorbell record: the ring's IDT stubs reported an
    /// exception to the carrier.
    FaultDoorbell(FaultDoorbellRecord),
    /// The soft CPU stopped on an unemulated instruction.
    Unsupported(SoftMachineExit),
    /// Exception delivery escalated past `#DF`.
    TripleFault(X86Exception),
    /// The block budget ran out with no host exit.
    StepBudget { rip: u64 },
    /// Translation or JIT failure inside the soft CPU at instruction `va`.
    Emit { va: u64, detail: String },
}

/// One run's findings. `summary` is the one-line "boots to X / fails at Y".
#[derive(Clone, Debug)]
pub struct BootReport {
    pub image: String,
    pub entry: u64,
    /// The initial guest MM was admitted (`load_guest_mm` returned `Ok`).
    pub admitted: bool,
    /// Basic blocks retired (the soft CPU does not count instructions).
    pub blocks: u64,
    pub final_rip: u64,
    pub final_cpl: u8,
    pub symbol: Option<String>,
    pub bytes: Vec<u8>,
    pub decoded: Option<String>,
    /// Exception deliveries observed (`interrupted rip -> stub rip`).
    pub deliveries: Vec<(u64, u64)>,
    /// `RAX` at a `FATAL_PORT` exit: the ring's fatal payload.
    pub fatal_payload: Option<u64>,
    /// The functions of the most recent blocks, oldest first, with
    /// consecutive repeats collapsed (`symbol x count`).
    pub recent: Vec<String>,
    pub outcome: BootExit,
    pub summary: String,
}

impl fmt::Display for BootReport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "[{}] {}", self.image, self.summary)?;
        writeln!(f, "  entry       {:#x}", self.entry)?;
        writeln!(f, "  blocks      {}", self.blocks)?;
        writeln!(
            f,
            "  final       rip={:#x} cpl={} symbol={}",
            self.final_rip,
            self.final_cpl,
            self.symbol.as_deref().unwrap_or("?")
        )?;
        writeln!(
            f,
            "  bytes       {:02x?} ({})",
            self.bytes,
            self.decoded.as_deref().unwrap_or("undecoded")
        )?;
        for (from, to) in &self.deliveries {
            writeln!(f, "  delivery    {from:#x} -> stub {to:#x}")?;
        }
        for function in &self.recent {
            writeln!(f, "  recent      {function}")?;
        }
        write!(f, "  outcome     {:?}", self.outcome)
    }
}

/// Collapse consecutive equal names into `name x count` (a lone name stays
/// bare). Names compare whole: `foo` never absorbs `foo_bar`.
fn collapse_runs(names: impl IntoIterator<Item = String>) -> Vec<String> {
    let mut runs: Vec<(String, u64)> = Vec::new();
    for name in names {
        match runs.last_mut() {
            Some((last, count)) if *last == name => *count += 1,
            _ => runs.push((name, 1)),
        }
    }
    runs.into_iter()
        .map(|(name, count)| {
            if count == 1 {
                name
            } else {
                format!("{name} x {count}")
            }
        })
        .collect()
}

/// Boot `image` on one soft CPU (slot 0) and run at most `max_blocks`.
pub fn boot_probe(
    inventory: Arc<dyn PhysicalFrameInventory>,
    image: ProbeImage<'_>,
    max_blocks: u64,
) -> BootReport {
    let symbols = Symbols::parse(image.elf);
    let mut report = BootReport {
        image: image.name.to_owned(),
        entry: 0,
        admitted: false,
        blocks: 0,
        final_rip: 0,
        final_cpl: 0,
        symbol: None,
        bytes: Vec::new(),
        decoded: None,
        deliveries: Vec::new(),
        fatal_payload: None,
        recent: Vec::new(),
        outcome: BootExit::Setup(String::new()),
        summary: String::new(),
    };
    let user = match image.user_elf.map(user_image).transpose() {
        Ok(user) => user,
        Err(error) => {
            report.outcome = BootExit::Setup(error.clone());
            report.summary = format!("fails at setup: {error}");
            return report;
        }
    };
    let initial_extent_bytes = match &user {
        Some((_, extent)) => Some(*extent),
        None => image.initial_extent_bytes,
    };
    let mut carrier = match SoftCarrier::boot(
        inventory,
        SoftBootImage {
            elf: image.elf,
            programs: image.programs,
            initial_extent_bytes,
            fixture_image: image.fixture_image,
            ipc: image.ipc,
        },
        max_blocks,
    ) {
        Ok(carrier) => carrier,
        Err(error) => {
            report.outcome = BootExit::Setup(error.to_string());
            report.summary = format!("fails at setup: {error}");
            return report;
        }
    };
    report.entry = carrier.entry();
    report.outcome = 'run: {
        if let Some(bind) = image.bind
            && let Err(error) = bind(&mut carrier)
        {
            break 'run BootExit::Setup(error);
        }
        if let Some((program, _)) = &user {
            let Ok(prepared) = carrick_mem::x86_initial_image::prepare_x86_elf(program) else {
                break 'run BootExit::Setup("user ELF image".to_owned());
            };
            if let Err(error) = load_guest_mm(
                &mut carrier,
                &prepared,
                &[],
                &[],
                InitialReservationLimits::UNLIMITED,
            ) {
                break 'run BootExit::Admission(error.to_string());
            }
            report.admitted = true;
        }
        let mut doorbell = Vec::new();
        loop {
            let Some(exit) = carrier.run() else {
                break 'run match carrier.trace().stop.clone() {
                    Some(SoftStop::Unsupported(exit)) => BootExit::Unsupported(exit),
                    Some(SoftStop::TripleFault(exception)) => BootExit::TripleFault(exception),
                    Some(SoftStop::StepBudget { rip }) => BootExit::StepBudget { rip },
                    Some(SoftStop::Kicked) | None => BootExit::StepBudget {
                        rip: carrier.machine().context().rip,
                    },
                    Some(SoftStop::Emit { va, detail }) => BootExit::Emit { va, detail },
                };
            };
            match exit {
                SoftMachineExit::IoOut {
                    port: FAULT_DOORBELL_PORT,
                    size: 4,
                    value,
                    ..
                } => {
                    doorbell.push(value);
                    if doorbell.len() == X86_FAULT_RECORD_U32_WORDS {
                        break 'run match FaultDoorbellRecord::from_u32_words(&doorbell) {
                            Ok(record) => BootExit::FaultDoorbell(record),
                            Err(error) => BootExit::Setup(error.to_string()),
                        };
                    }
                }
                SoftMachineExit::IoOut {
                    port: FATAL_PORT, ..
                } => {
                    report.fatal_payload = carrier.trace().last_exit.as_ref().map(|(_, rax)| *rax);
                    break 'run BootExit::HostExit(exit);
                }
                exit => break 'run BootExit::HostExit(exit),
            }
        }
    };
    let trace = carrier.trace().clone();
    report.blocks = trace.blocks;
    report.deliveries = trace.deliveries;
    report.recent = collapse_runs(
        trace
            .recent
            .into_iter()
            .map(|rip| symbols.function(rip).unwrap_or_else(|| format!("{rip:#x}"))),
    );
    let machine = carrier.machine_mut();
    let rip = match report.outcome {
        BootExit::HostExit(
            SoftMachineExit::IoOut { rip, .. }
            | SoftMachineExit::IoIn { rip, .. }
            | SoftMachineExit::Hlt { rip, .. },
        )
        | BootExit::Unsupported(SoftMachineExit::UnhandledSensitive { rip, .. }) => rip,
        BootExit::FaultDoorbell(record) => record.rip,
        BootExit::Emit { va, .. } => va,
        _ => machine.context().rip,
    };
    report.final_rip = rip;
    report.final_cpl = machine.context().cpl;
    report.symbol = symbols.nearest(rip);
    let mut bytes = [0_u8; 15];
    let (cpu, memory) = machine.parts_mut();
    if read_guest_bytes(
        cpu.context_mut(),
        memory,
        rip,
        &mut bytes,
        SoftAccessKind::Read,
    )
    .is_ok()
    {
        report.decoded = decode(rip, &bytes);
        report.bytes = bytes.to_vec();
    }
    report.summary = summarize(&report);
    report
}

/// Load a static x86-64 user ELF and size its initial extent through the
/// shared policy KVM uses.
fn user_image(elf: &[u8]) -> Result<(carrick_mem::elf::ElfProgram<'_>, usize), String> {
    let program = carrick_mem::elf::ElfProgram::load(elf, 62, &|_| None)
        .map_err(|error| format!("user ELF: {error:?}"))?;
    let image = carrick_mem::x86_initial_image::prepare_x86_elf(&program)
        .map_err(|error| format!("user ELF image: {error:?}"))?;
    let extent = initial_extent_bytes_for(&image, &[], &[]).map_err(|error| error.to_string())?;
    drop(image);
    Ok((program, extent))
}

fn summarize(report: &BootReport) -> String {
    let at = format!(
        "{:#x}{} after {} blocks",
        report.final_rip,
        report
            .symbol
            .as_deref()
            .map(|symbol| format!(" ({symbol})"))
            .unwrap_or_default(),
        report.blocks
    );
    let summary = match &report.outcome {
        BootExit::HostExit(SoftMachineExit::IoOut {
            port: FATAL_PORT, ..
        }) => format!(
            "boots to ring fatal exit (FATAL_PORT, rax {:#x}) at {at}",
            report.fatal_payload.unwrap_or_default()
        ),
        BootExit::HostExit(SoftMachineExit::IoOut {
            port, size, value, ..
        }) => format!(
            "boots to first carrier host exit OUT port {port:#x}{} size {size} value {value:#x} at {at}",
            port_name(*port)
                .map(|name| format!(" ({name})"))
                .unwrap_or_default()
        ),
        BootExit::HostExit(SoftMachineExit::IoIn { port, size, .. }) => {
            format!("boots to first carrier host exit IN port {port:#x} size {size} at {at}")
        }
        BootExit::HostExit(exit) => format!("boots to first carrier host exit {exit:?} at {at}"),
        BootExit::FaultDoorbell(record) => format!(
            "boots to fault doorbell (vector {} error {:#x} cs {:#x} cr2 {:#x}) for fault at {at}",
            record.vector, record.error_code, record.cs, record.cr2
        ),
        BootExit::Setup(error) => format!("fails at setup: {error}"),
        BootExit::Admission(error) => format!("fails at initial-MM admission: {error} at {at}"),
        BootExit::Unsupported(SoftMachineExit::UnhandledSensitive { op, .. }) => format!(
            "fails at unsupported {op:?} [{}] at {at}",
            report.decoded.as_deref().unwrap_or("undecoded")
        ),
        BootExit::Unsupported(exit) => format!("fails at unsupported {exit:?} at {at}"),
        BootExit::TripleFault(exception) => format!("fails at triple fault {exception:?} at {at}"),
        BootExit::StepBudget { .. } => format!("fails at block budget, still running at {at}"),
        BootExit::Emit { detail, .. } => format!(
            "fails at soft CPU translation of [{}] {detail} at {at}",
            report.decoded.as_deref().unwrap_or("undecoded")
        ),
    };
    match summary.strip_prefix("boots to ") {
        Some(rest) if report.admitted => format!("boots past initial-MM admission to {rest}"),
        _ => summary,
    }
}

/// The carrier protocol's name for a ring port.
fn port_name(port: u16) -> Option<&'static str> {
    use carrick_x86::cpl0_entry as ports;
    Some(match port {
        ports::FORWARD_PORT => "FORWARD_PORT",
        ports::FAULT_DOORBELL_PORT => "FAULT_DOORBELL_PORT",
        ports::CONTROL_PORT => "CONTROL_PORT",
        ports::ENTRY_KICK_PORT => "ENTRY_KICK_PORT",
        ports::RETURN_KICK_PORT => "RETURN_KICK_PORT",
        ports::WORK_PORT => "WORK_PORT",
        ports::NATIVE_SERVICE_PORT => "NATIVE_SERVICE_PORT",
        ports::YIELD_PORT => "YIELD_PORT",
        ports::OWNER_GRANT_PORT => "OWNER_GRANT_PORT",
        _ => return None,
    })
}

fn decode(rip: u64, bytes: &[u8]) -> Option<String> {
    let mut decoder = iced_x86::Decoder::with_ip(64, bytes, rip, iced_x86::DecoderOptions::NONE);
    let instruction = decoder.decode();
    (!instruction.is_invalid())
        .then(|| format!("{:?} len {}", instruction.code(), instruction.len()))
}

/// Ring ELF symbols, for naming the final RIP.
struct Symbols(Vec<(u64, u64, String)>);

impl Symbols {
    fn parse(elf: &[u8]) -> Self {
        let Ok(parsed) = goblin::elf::Elf::parse(elf) else {
            return Self(Vec::new());
        };
        let mut symbols: Vec<_> = parsed
            .syms
            .iter()
            .filter(|symbol| symbol.st_value != 0 && symbol.is_function())
            .filter_map(|symbol| {
                let name = parsed.strtab.get_at(symbol.st_name)?;
                Some((
                    symbol.st_value,
                    symbol.st_size,
                    rustc_demangle::demangle(name).to_string(),
                ))
            })
            .collect();
        symbols.sort_unstable_by_key(|&(address, ..)| address);
        Self(symbols)
    }

    /// The containing function's name, without offset.
    fn function(&self, rip: u64) -> Option<String> {
        let index = self.0.partition_point(|&(address, ..)| address <= rip);
        let (address, size, name) = self.0.get(index.checked_sub(1)?)?;
        (size == &0 || rip < address + size).then(|| name.clone())
    }

    fn nearest(&self, rip: u64) -> Option<String> {
        let index = self.0.partition_point(|&(address, ..)| address <= rip);
        let (address, size, name) = self.0.get(index.checked_sub(1)?)?;
        (size == &0 || rip < address + size).then(|| format!("{name}+{:#x}", rip - address))
    }
}

#[cfg(test)]
mod tests {
    use super::collapse_runs;

    #[test]
    fn runs_collapse_on_whole_names_only() {
        let names = ["foo", "foo", "foo_bar", "foo_bar", "foo_bar", "foo", "bar"];
        assert_eq!(
            collapse_runs(names.map(String::from)),
            ["foo x 2", "foo_bar x 3", "foo", "bar"]
        );
    }
}
