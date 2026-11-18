//! `boot_probe`: run a prepared CPL0 ring image on `SoftMachine` until its
//! first carrier host exit (port I/O or `HLT`) or a failure, and say exactly
//! how far it got. The report is produced even when boot fails.

use std::fmt;
use std::num::NonZeroU64;

use carrick_hal::{PhysicalFrameInventory, TrapError};
use carrick_softcpu_x86::{
    EmitError, GuestCpuidView, SoftAccessKind, SoftMachine, SoftMachineExit, X86Exception,
    read_guest_bytes,
};
use carrick_x86::cpl0_entry::{
    DIRECT_VA, FATAL_PORT, FAULT_DOORBELL_PORT, PublishedApicId, PublishedApicIds,
};
use carrick_x86::{FaultDoorbellRecord, X86_FAULT_RECORD_U32_WORDS};
use carrick_x86_cpl0_host::cpl0_boot::{
    BootCpuState, LAYOUT, META_GPA, ROUTES_OFFSET, fail, prepare_boot,
};

use crate::cpu::apply_boot_cpu_state;
use crate::memory::SoftBootMemory;

/// Soft TSC frequency published to the CPUID view and the CPU binding.
const SOFT_TSC_HZ: u64 = 2_000_000_000;
/// The probe's one carrier identity (`FileRegionId` must be nonzero).
const PROBE_CARRIER: NonZeroU64 = NonZeroU64::MIN;

/// The ring image and stopped-carrier shape to probe.
#[derive(Clone, Copy)]
pub struct ProbeImage<'a> {
    pub name: &'a str,
    pub elf: &'a [u8],
    /// Per-slot CPL3 fixture code mapped at `USER_CODE` (empty: none).
    pub programs: [&'a [u8]; 2],
    /// Production boot: an initial guest-MM extent of this many bytes.
    pub initial_extent_bytes: Option<usize>,
    /// The image is the test-support fixture build.
    pub fixture_image: bool,
}

/// How a probe run ended.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum BootExit {
    /// Neutral preparation, memory installation or CPU programming failed.
    Setup(String),
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
        write!(f, "  outcome     {:?}", self.outcome)
    }
}

/// Boot `image` on one soft CPU (slot 0) and run at most `max_blocks`.
pub fn boot_probe(
    inventory: &dyn PhysicalFrameInventory,
    image: ProbeImage<'_>,
    max_blocks: u64,
) -> BootReport {
    let symbols = Symbols::parse(image.elf);
    let mut report = BootReport {
        image: image.name.to_owned(),
        entry: 0,
        blocks: 0,
        final_rip: 0,
        final_cpl: 0,
        symbol: None,
        bytes: Vec::new(),
        decoded: None,
        deliveries: Vec::new(),
        fatal_payload: None,
        outcome: BootExit::Setup(String::new()),
        summary: String::new(),
    };
    let mut machine = match stopped_machine(inventory, image, &mut report) {
        Ok(machine) => machine,
        Err(error) => {
            report.outcome = BootExit::Setup(error.to_string());
            report.summary = format!("fails at setup: {error}");
            return report;
        }
    };
    let stubs = DIRECT_VA + carrick_x86::fault_stub_base(LAYOUT)
        ..DIRECT_VA + carrick_x86::fault_tss_base(LAYOUT);
    let mut doorbell = Vec::new();
    report.outcome = loop {
        if report.blocks >= max_blocks {
            break BootExit::StepBudget {
                rip: machine.context().rip,
            };
        }
        let before = machine.context().rip;
        let step = machine.step();
        report.blocks += 1;
        let exit = match step {
            Err(error) => {
                break BootExit::Emit {
                    va: emit_va(&error),
                    detail: format!("{error:?}"),
                };
            }
            Ok(None) => {
                let rip = machine.context().rip;
                if stubs.contains(&rip) && !stubs.contains(&before) {
                    report.deliveries.push((before, rip));
                }
                continue;
            }
            Ok(Some(exit)) => exit,
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
                    break match FaultDoorbellRecord::from_u32_words(&doorbell) {
                        Ok(record) => BootExit::FaultDoorbell(record),
                        Err(error) => BootExit::Setup(error.to_string()),
                    };
                }
            }
            SoftMachineExit::IoOut {
                port: FATAL_PORT, ..
            } => {
                report.fatal_payload = Some(machine.context().gpr[carrick_softcpu_x86::reg::RAX]);
                break BootExit::HostExit(exit);
            }
            SoftMachineExit::IoOut { .. }
            | SoftMachineExit::IoIn { .. }
            | SoftMachineExit::Hlt { .. } => break BootExit::HostExit(exit),
            SoftMachineExit::UnhandledSensitive { .. } => break BootExit::Unsupported(exit),
            SoftMachineExit::TripleFault { last_exception } => {
                break BootExit::TripleFault(last_exception);
            }
            SoftMachineExit::StepBudgetExhausted { rip, .. } => {
                break BootExit::StepBudget { rip };
            }
        }
    };
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
    let (mut cpu, mut memory) = machine.into_parts();
    let mut bytes = [0_u8; 15];
    let ctx = cpu.context_mut();
    if read_guest_bytes(ctx, &mut memory, rip, &mut bytes, SoftAccessKind::Read).is_ok() {
        report.decoded = decode(rip, &bytes);
        report.bytes = bytes.to_vec();
    }
    report.summary = summarize(&report);
    report
}

fn stopped_machine(
    inventory: &dyn PhysicalFrameInventory,
    image: ProbeImage<'_>,
    report: &mut BootReport,
) -> Result<SoftMachine<SoftBootMemory>, TrapError> {
    let production = image.initial_extent_bytes.is_some();
    let prepared = prepare_boot(
        inventory,
        image.elf,
        image.programs,
        false,
        image.initial_extent_bytes,
        image.fixture_image,
        None,
    )?;
    report.entry = prepared.plan.entry;
    let memory = SoftBootMemory::install(&prepared, image.initial_extent_bytes, PROBE_CARRIER)?;
    let cpuid = GuestCpuidView::x86_64_v3()
        .with_apic_id(0)
        .with_tsc(carrick_x86::TscCrystalRatio::from_hz(SOFT_TSC_HZ));
    let mut machine = SoftMachine::new(memory, Box::new(cpuid))
        .map_err(|error| fail(format!("soft CPU: {error:?}")))?;
    let slot = carrick_guest_arch::CpuId::new(0);
    let state = BootCpuState::new(
        prepared.plan.entry,
        &prepared.boot,
        slot,
        prepared.hardware_interrupts,
        production,
    )?;
    apply_boot_cpu_state(
        machine.context_mut(),
        &cpuid,
        &state,
        prepared.hardware_interrupts,
        production,
    )?;
    let hz = machine.context().tsc_hz();
    if hz == 0 {
        return Err(fail("soft CPU reported no usable TSC frequency"));
    }
    machine
        .mem()
        .binding(0)?
        .tsc_hz
        .store(hz, std::sync::atomic::Ordering::Release);
    if prepared.hardware_interrupts {
        let apic = machine.context().lapic().apic_id();
        // SAFETY: `prepare_boot` initialized the retained route table; the
        // CPU is stopped, so no guest reader exists before publication.
        let routes = unsafe {
            machine
                .mem()
                .record::<PublishedApicIds>(META_GPA + ROUTES_OFFSET)?
        };
        // M1 is single-vCPU (#2397): only slot 0 is created and published.
        if !routes.publish(slot, PublishedApicId(apic)) {
            return Err(fail("invalid APIC slot publication"));
        }
    }
    Ok(machine)
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
    match &report.outcome {
        BootExit::HostExit(SoftMachineExit::IoOut {
            port: FATAL_PORT, ..
        }) => format!(
            "boots to ring fatal exit (FATAL_PORT, rax {:#x}) at {at}",
            report.fatal_payload.unwrap_or_default()
        ),
        BootExit::HostExit(SoftMachineExit::IoOut {
            port, size, value, ..
        }) => format!(
            "boots to first carrier host exit OUT port {port:#x} size {size} value {value:#x} at {at}"
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
    }
}

const fn emit_va(error: &EmitError) -> u64 {
    match *error {
        EmitError::EncodeFailed { va, .. }
        | EmitError::HostJit { va, .. }
        | EmitError::ForeignInventory { va }
        | EmitError::InventoryTerminal { va } => va,
    }
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

    fn nearest(&self, rip: u64) -> Option<String> {
        let index = self.0.partition_point(|&(address, ..)| address <= rip);
        let (address, size, name) = self.0.get(index.checked_sub(1)?)?;
        (size == &0 || rip < address + size).then(|| format!("{name}+{:#x}", rip - address))
    }
}
