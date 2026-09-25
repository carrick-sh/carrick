//! The carrier VM's interrupt controller: Hypervisor.framework's in-kernel
//! GICv3 (`hv_gic_create`), EL1 plan 1a. This module is the only caller of raw
//! `hv_gic_*` (test `raw_hv_gic_calls_stay_in_gic_rs`).
//!
//! Setup follows `hv_gic.h` and libkrun (Apache-2.0): the GIC is created right
//! after `hv_vm_create` and before any `hv_vcpu_create`; each vCPU gets a
//! unique MPIDR on its owning thread before its redistributor is touched;
//! vCPUs live for the VM's life (`trap::vcpu_topology`). The host writes no
//! distributor register (the default `GICD_CTLR` already delivers SGIs and
//! PPIs, qualified live on macOS 27.2 / M4). Carrick has no guest GIC driver,
//! so per vCPU this module programs, on the owning thread, what a driver's
//! CPU bring-up would: the redistributor (the kick SGI and the virtual timer
//! PPI enabled in group 1, with priorities) and the CPU interface (priority
//! mask, group 1 enable).
//!
//! Once a VM has a GIC, `hv_vcpu_set_pending_interrupt` returns
//! `HV_UNSUPPORTED` (`hv_vcpu.h`), so the kick a vCPU owes at its next EL0
//! boundary (`carrick_aarch64::owed_kick`) is SGI [`KICK_INTID`] made pending
//! in the vCPU's redistributor (`GICR_ISPENDR0`) and withdrawn with
//! `GICR_ICPENDR0`. Unlike the legacy line, that pending state survives
//! `hv_vcpu_run` returns until the guest takes it or the host withdraws it.
//! Host kicks themselves stay `hv_vcpus_exit`, as in every VMM.
//!
//! `CARRICK_HVF_GIC=0` (exact string) is the bisection hatch: a GIC-less VM,
//! the SDK IRQ line as the kick vehicle, and today's EL1 vector bytes.

#![cfg(all(target_os = "macos", target_arch = "aarch64"))]

use applevisor_sys as sys;
use carrick_hal::TrapError;
use carrick_mem::memory::{
    LINUX_GIC_DISTRIBUTOR_BASE, LINUX_GIC_DISTRIBUTOR_MAX, LINUX_GIC_REDISTRIBUTOR_BASE,
    LINUX_GIC_REDISTRIBUTOR_MAX,
};

/// SGI the host makes pending for a kick owed to the EL0 boundary.
pub(crate) const KICK_INTID: u32 = carrick_el1_abi::GIC_KICK_INTID;
/// Hypervisor.framework's EL1 virtual timer PPI (checked at GIC creation).
pub(crate) const VTIMER_INTID: u32 = carrick_el1_abi::GIC_VTIMER_INTID;
const _: () = assert!(KICK_INTID < 16, "the owed kick is an SGI");
const _: () = assert!(
    VTIMER_INTID >= 16 && VTIMER_INTID < 32,
    "the vtimer is a PPI"
);

/// Lower value is higher priority: the timer outranks the kick.
const VTIMER_PRIORITY: u8 = 0x80;
const KICK_PRIORITY: u8 = 0xa0;
/// CPU-interface priority mask: every Carrick priority passes.
const ICC_PMR: u64 = 0xf0;
/// Every SGI and PPI bit of the `*R0` redistributor registers.
const ALL_PRIVATE: u64 = 0xffff_ffff;
const HV_NO_RESOURCES: sys::hv_return_t = 0xfae9_4005_u32 as sys::hv_return_t;

/// The carrier's interrupt model, read once from `CARRICK_HVF_GIC`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InterruptModel {
    /// The in-kernel GICv3; the owed kick is a redistributor-pending SGI.
    Gic,
    /// `CARRICK_HVF_GIC=0`: no GIC, the owed kick on the SDK IRQ line through
    /// `hv_vcpu_set_pending_interrupt`.
    LegacyPendingLine,
}

/// The one reader of `CARRICK_HVF_GIC`, latched once per process: the VM, the
/// kick vehicle and the EL1 vector bytes all derive from it, so they cannot
/// disagree within a carrier.
pub fn interrupt_model() -> InterruptModel {
    static MODEL: std::sync::OnceLock<InterruptModel> = std::sync::OnceLock::new();
    *MODEL.get_or_init(|| interrupt_model_from_env(std::env::var("CARRICK_HVF_GIC").ok()))
}

/// The EL1 vector page's interrupt mode for this carrier's model.
pub fn el1_irq_mode() -> carrick_mem::memory::El1IrqMode {
    match interrupt_model() {
        InterruptModel::Gic => carrick_mem::memory::El1IrqMode::GicWindow,
        InterruptModel::LegacyPendingLine => carrick_mem::memory::El1IrqMode::Masked,
    }
}

fn interrupt_model_from_env(value: Option<String>) -> InterruptModel {
    if value.as_deref() == Some("0") {
        InterruptModel::LegacyPendingLine
    } else {
        InterruptModel::Gic
    }
}

/// `MPIDR_EL1` for GIC affinity index `index`: RES1 bit 31, Aff1 = index / 16,
/// Aff0 = index % 16, so an `ICC_SGI1R_EL1` TargetList (Aff0 0-15 within one
/// Aff1) can address every vCPU.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct Mpidr(u64);

impl Mpidr {
    pub(crate) const fn for_index(index: u16) -> Self {
        Self((1 << 31) | ((index as u64 / 16) << 8) | (index as u64 % 16))
    }

    pub(crate) const fn raw(self) -> u64 {
        self.0
    }
}

/// What Hypervisor.framework reports for its GIC device on this host.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct GicGeometry {
    pub(crate) distributor_size: u64,
    pub(crate) distributor_alignment: u64,
    pub(crate) redistributor_region_size: u64,
    pub(crate) redistributor_size: u64,
    pub(crate) redistributor_alignment: u64,
}

impl GicGeometry {
    fn query() -> Result<Self, TrapError> {
        let (mut ds, mut da, mut rr, mut rs, mut ra) = (0usize, 0usize, 0usize, 0usize, 0usize);
        // SAFETY: out-pointers to locals; these queries need no VM.
        unsafe {
            gic_check(
                sys::hv_gic_get_distributor_size(&mut ds),
                "hv_gic_get_distributor_size",
            )?;
            gic_check(
                sys::hv_gic_get_distributor_base_alignment(&mut da),
                "hv_gic_get_distributor_base_alignment",
            )?;
            gic_check(
                sys::hv_gic_get_redistributor_region_size(&mut rr),
                "hv_gic_get_redistributor_region_size",
            )?;
            gic_check(
                sys::hv_gic_get_redistributor_size(&mut rs),
                "hv_gic_get_redistributor_size",
            )?;
            gic_check(
                sys::hv_gic_get_redistributor_base_alignment(&mut ra),
                "hv_gic_get_redistributor_base_alignment",
            )?;
        }
        Ok(Self {
            distributor_size: ds as u64,
            distributor_alignment: da as u64,
            redistributor_region_size: rr as u64,
            redistributor_size: rs as u64,
            redistributor_alignment: ra as u64,
        })
    }

    /// Fail closed when the reserved window cannot hold the device.
    pub(crate) fn fits_window(&self) -> Result<(), TrapError> {
        let fits = self.distributor_alignment != 0
            && self.redistributor_alignment != 0
            && self.redistributor_size != 0
            && LINUX_GIC_DISTRIBUTOR_BASE.is_multiple_of(self.distributor_alignment)
            && self.distributor_size <= LINUX_GIC_DISTRIBUTOR_MAX
            && LINUX_GIC_REDISTRIBUTOR_BASE.is_multiple_of(self.redistributor_alignment)
            && self.redistributor_region_size <= LINUX_GIC_REDISTRIBUTOR_MAX;
        if fits {
            Ok(())
        } else {
            Err(TrapError::Hypervisor(format!(
                "GIC geometry does not fit the reserved window: {self:?}"
            )))
        }
    }

    /// Redistributors, hence vCPUs, one VM's GIC can hold.
    pub(crate) fn redistributor_capacity(&self) -> usize {
        (self.redistributor_region_size / self.redistributor_size.max(1)) as usize
    }
}

/// The GIC of the carrier's one live VM generation.
#[derive(Debug)]
struct CarrierGic {
    generation: u64,
    /// Next affinity index. vCPUs are created only while the generation
    /// assembles and destroyed only at teardown (`vcpu_topology`), so a
    /// counter hands every vCPU of the generation a distinct index.
    next_index: usize,
    capacity: usize,
}

/// `None` between VM generations and in the legacy model.
static CARRIER_GIC: parking_lot::Mutex<Option<CarrierGic>> = parking_lot::Mutex::new(None);

fn gic_check(rc: sys::hv_return_t, what: &str) -> Result<(), TrapError> {
    if rc == 0 {
        Ok(())
    } else {
        Err(TrapError::Hypervisor(format!(
            "{what}: rc={:#x}",
            rc as u32
        )))
    }
}

/// Why `create_carrier_gic` failed. `NoResources` is `hv_gic_create`'s
/// `HV_NO_RESOURCES`, which the VM-creation funnel parks and retries like
/// `hv_vm_create`'s.
#[derive(Debug)]
pub(crate) enum GicCreateFailure {
    NoResources,
    Fatal(TrapError),
}

impl From<TrapError> for GicCreateFailure {
    fn from(error: TrapError) -> Self {
        Self::Fatal(error)
    }
}

/// Create the in-kernel GIC for the VM `hv_vm_create` just made (custody
/// generation `generation`). Called only by `create_vm_with_admission`, before
/// it hands the VM out, so it precedes every `hv_vcpu_create` of that VM.
pub(crate) fn create_carrier_gic(generation: u64) -> Result<(), GicCreateFailure> {
    if interrupt_model() != InterruptModel::Gic {
        return Ok(());
    }
    let geometry = GicGeometry::query()?;
    geometry.fits_window()?;
    // SAFETY: the config object is created, used and released here; both
    // bases lie in the reserved window, which the stage-2 map boundary and
    // stage-1 publication refuse to map.
    unsafe {
        let config = sys::hv_gic_config_create();
        if config.is_null() {
            return Err(
                TrapError::Hypervisor("hv_gic_config_create returned null".to_owned()).into(),
            );
        }
        let created = gic_check(
            sys::hv_gic_config_set_distributor_base(config, LINUX_GIC_DISTRIBUTOR_BASE),
            "hv_gic_config_set_distributor_base",
        )
        .and_then(|()| {
            gic_check(
                sys::hv_gic_config_set_redistributor_base(config, LINUX_GIC_REDISTRIBUTOR_BASE),
                "hv_gic_config_set_redistributor_base",
            )
        })
        .map_err(GicCreateFailure::Fatal)
        .and_then(|()| match sys::hv_gic_create(config) {
            HV_NO_RESOURCES => Err(GicCreateFailure::NoResources),
            rc => gic_check(rc, "hv_gic_create").map_err(GicCreateFailure::Fatal),
        });
        sys::os_release(config);
        created?;
        let mut vtimer = 0u32;
        gic_check(
            sys::hv_gic_get_intid(sys::hv_gic_intid_t::EL1_VIRTUAL_TIMER, &mut vtimer),
            "hv_gic_get_intid(EL1_VIRTUAL_TIMER)",
        )?;
        if vtimer != VTIMER_INTID {
            return Err(TrapError::Hypervisor(format!(
                "HVF EL1 virtual timer is INTID {vtimer}, Carrick's EL1 code expects {VTIMER_INTID}"
            ))
            .into());
        }
    }
    *CARRIER_GIC.lock() = Some(CarrierGic {
        generation,
        next_index: 0,
        capacity: geometry.redistributor_capacity(),
    });
    Ok(())
}

/// The VM was destroyed; its GIC went with it.
pub(crate) fn carrier_vm_released() {
    *CARRIER_GIC.lock() = None;
}

fn redistributor_write(
    vcpu: u64,
    reg: sys::hv_gic_redistributor_reg_t,
    value: u64,
) -> Result<(), TrapError> {
    // SAFETY: owning thread of a live vCPU of this VM (every caller).
    gic_check(
        unsafe { sys::hv_gic_set_redistributor_reg(vcpu, reg, value) },
        "hv_gic_set_redistributor_reg",
    )
    .map_err(|error| TrapError::Hypervisor(format!("{reg:?} of vCPU {vcpu}: {error}")))
}

fn set_priority(vcpu: u64, intid: u32, priority: u8) -> Result<(), TrapError> {
    use sys::hv_gic_redistributor_reg_t as R;
    let reg = match intid / 4 {
        0 => R::IPRIORITYR0,
        1 => R::IPRIORITYR1,
        2 => R::IPRIORITYR2,
        3 => R::IPRIORITYR3,
        4 => R::IPRIORITYR4,
        5 => R::IPRIORITYR5,
        6 => R::IPRIORITYR6,
        _ => R::IPRIORITYR7,
    };
    let shift = (intid % 4) * 8;
    let mut value = 0u64;
    // SAFETY: owning thread of a live vCPU of this VM.
    gic_check(
        unsafe { sys::hv_gic_get_redistributor_reg(vcpu, reg, &mut value) },
        "GICR_IPRIORITYR read",
    )?;
    value = (value & !(0xff << shift)) | (u64::from(priority) << shift);
    redistributor_write(vcpu, reg, value)
}

/// Give a freshly created vCPU its affinity, then configure its
/// redistributor and CPU interface. Owning thread, before the vCPU first runs.
pub(crate) fn configure_new_vcpu(vcpu: u64) -> Result<(), TrapError> {
    if interrupt_model() != InterruptModel::Gic {
        return Ok(());
    }
    let index = {
        let mut guard = CARRIER_GIC.lock();
        let Some(gic) = guard.as_mut() else {
            return Err(TrapError::Hypervisor(
                "vCPU created in a GIC carrier whose VM has no GIC".to_owned(),
            ));
        };
        if gic.next_index >= gic.capacity {
            return Err(TrapError::Hypervisor(format!(
                "GIC of VM generation {} is full: {} redistributors",
                gic.generation, gic.capacity
            )));
        }
        let index = gic.next_index;
        gic.next_index += 1;
        u16::try_from(index)
            .map_err(|_| TrapError::Hypervisor(format!("GIC affinity index {index} overflows")))?
    };
    use sys::hv_gic_redistributor_reg_t as R;
    let enabled = (1u64 << KICK_INTID) | (1u64 << VTIMER_INTID);
    // SAFETY: owning thread of a live vCPU of this VM; MPIDR is set before any
    // redistributor access, as hv_gic.h requires.
    gic_check(
        unsafe {
            sys::hv_vcpu_set_sys_reg(
                vcpu,
                sys::hv_sys_reg_t::MPIDR_EL1,
                Mpidr::for_index(index).raw(),
            )
        },
        "MPIDR_EL1",
    )?;
    // A guest driver's CPU bring-up: withdraw every private interrupt Carrick
    // does not use, and any pending or active state, then enable its own.
    redistributor_write(vcpu, R::ICENABLER0, ALL_PRIVATE & !enabled)?;
    redistributor_write(vcpu, R::ICPENDR0, ALL_PRIVATE)?;
    redistributor_write(vcpu, R::ICACTIVER0, ALL_PRIVATE)?;
    redistributor_write(vcpu, R::IGROUPR0, enabled)?;
    set_priority(vcpu, VTIMER_INTID, VTIMER_PRIORITY)?;
    set_priority(vcpu, KICK_INTID, KICK_PRIORITY)?;
    redistributor_write(vcpu, R::ISENABLER0, enabled)?;
    // SAFETY: owning thread of a live vCPU of this VM.
    unsafe {
        gic_check(
            sys::hv_gic_set_icc_reg(vcpu, sys::hv_gic_icc_reg_t::PMR_EL1, ICC_PMR),
            "ICC_PMR_EL1",
        )?;
        gic_check(
            sys::hv_gic_set_icc_reg(vcpu, sys::hv_gic_icc_reg_t::IGRPEN1_EL1, 1),
            "ICC_IGRPEN1_EL1",
        )
    }
}

/// Make the owed kick pending on `vcpu` (owning thread). GIC: the kick SGI in
/// the vCPU's redistributor, which survives `hv_vcpu_run` returns until the
/// guest takes it or [`clear_kick`] withdraws it. Hatch: the SDK IRQ line,
/// which Hypervisor.framework clears on every run return.
pub(crate) fn arm_kick(vcpu: &applevisor::vcpu::Vcpu) -> Result<(), TrapError> {
    set_kick_pending(vcpu, true)
}

/// Withdraw an owed kick that some exit surfaced.
pub(crate) fn clear_kick(vcpu: &applevisor::vcpu::Vcpu) -> Result<(), TrapError> {
    set_kick_pending(vcpu, false)
}

fn set_kick_pending(vcpu: &applevisor::vcpu::Vcpu, pending: bool) -> Result<(), TrapError> {
    match interrupt_model() {
        InterruptModel::Gic => {
            let reg = if pending {
                sys::hv_gic_redistributor_reg_t::ISPENDR0
            } else {
                sys::hv_gic_redistributor_reg_t::ICPENDR0
            };
            redistributor_write(vcpu.id(), reg, 1 << KICK_INTID)
        }
        InterruptModel::LegacyPendingLine => vcpu
            .set_pending_interrupt(crate::trap::HVF_VIRTUAL_IRQ, pending)
            .map_err(|error| TrapError::Hypervisor(error.to_string())),
    }
}

/// Diagnostic view of the carrier VM's GIC (signed embed tests).
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct CarrierGicSnapshot {
    /// The live VM generation carries the in-kernel GIC.
    pub gic: bool,
    /// Custody generation of that VM.
    pub generation: u64,
    /// vCPUs given an affinity and a configured redistributor.
    pub vcpus: usize,
    /// Redistributors the GIC holds.
    pub capacity: usize,
}

pub fn carrier_gic_snapshot() -> CarrierGicSnapshot {
    CARRIER_GIC
        .lock()
        .as_ref()
        .map_or_else(CarrierGicSnapshot::default, |gic| CarrierGicSnapshot {
            gic: true,
            generation: gic.generation,
            vcpus: gic.next_index,
            capacity: gic.capacity,
        })
}

/// Signed-test probe of the guest virtual timer (EL1 plan 1a): arm a
/// one-shot EL1 timer on the vCPU that resumes the next forwarded Linux
/// syscall `marker_nr`, then account every exit of that vCPU until EL1 has
/// taken the timer interrupt. 1a has no production timer user (the EL1
/// scheduler adds preemption); idle, the probe costs one relaxed load per
/// `hv_vcpu_run` entry and one per exit.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct VtimerProbeReport {
    /// The host armed the timer on a vCPU resuming the marker syscall.
    pub armed: bool,
    /// An exit of that vCPU found the timer interrupt taken at EL1.
    pub delivered: bool,
    /// The probed vCPU.
    pub vcpu: u64,
    /// Exits of the probed vCPU between arming and delivery that the host
    /// itself caused: a host kick (`CANCELED`, the `hvc #4` kick exit) or a
    /// syscall forwarded for pending host work. They carry no timer.
    pub host_initiated_exits: u64,
    /// Every other exit of the probed vCPU between arming and delivery.
    pub other_exits: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum VtimerProbeError {
    /// `CARRICK_HVF_GIC=0`: without the in-kernel GIC the timer exits to the
    /// host.
    NoGic,
    /// `CARRICK_EL1=0`: no EL1 kernel, no IRQ window.
    El1Disabled,
}

#[derive(Debug, Default)]
struct VtimerProbe {
    /// `(marker_nr, delay_ticks)` until a vCPU resumes the marker.
    request: Option<(u64, u64)>,
    /// `irq_taken[vtimer]` when the timer was armed.
    taken_before: u64,
    report: VtimerProbeReport,
}

static VTIMER_PROBE_ACTIVE: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);
static VTIMER_PROBE: parking_lot::Mutex<Option<VtimerProbe>> = parking_lot::Mutex::new(None);

pub fn el1_vtimer_probe_arm_after_syscall(
    marker_nr: u64,
    delay_ticks: u64,
) -> Result<(), VtimerProbeError> {
    if interrupt_model() != InterruptModel::Gic {
        return Err(VtimerProbeError::NoGic);
    }
    if !carrick_mem::memory::el1_kernel_enabled() {
        return Err(VtimerProbeError::El1Disabled);
    }
    *VTIMER_PROBE.lock() = Some(VtimerProbe {
        request: Some((marker_nr, delay_ticks)),
        ..VtimerProbe::default()
    });
    VTIMER_PROBE_ACTIVE.store(true, std::sync::atomic::Ordering::Release);
    Ok(())
}

pub fn el1_vtimer_probe_report() -> VtimerProbeReport {
    VTIMER_PROBE
        .lock()
        .as_ref()
        .map_or_else(VtimerProbeReport::default, |probe| probe.report)
}

/// Before `hv_vcpu_run` (owning thread): arm the requested timer if this
/// vCPU is about to resume the marker syscall.
pub(crate) fn service_vtimer_probe(
    vcpu: &applevisor::vcpu::Vcpu,
    mailbox: &crate::syscall_mailbox::MailboxBinding,
) -> Result<(), TrapError> {
    if !VTIMER_PROBE_ACTIVE.load(std::sync::atomic::Ordering::Relaxed) {
        return Ok(());
    }
    let mut guard = VTIMER_PROBE.lock();
    let Some(probe) = guard.as_mut() else {
        return Ok(());
    };
    let Some((marker_nr, delay_ticks)) = probe.request else {
        return Ok(());
    };
    if mailbox.leased_slot().is_none() || mailbox.diagnostics().native_nr != marker_nr {
        return Ok(());
    }
    let mut offset = 0u64;
    // SAFETY: owning thread of a live vCPU; CNTV_* are this vCPU's registers.
    unsafe {
        gic_check(
            sys::hv_vcpu_get_vtimer_offset(vcpu.id(), &mut offset),
            "hv_vcpu_get_vtimer_offset",
        )?;
        let now = carrick_host::clock::monotonic_ticks().wrapping_sub(offset);
        gic_check(
            sys::hv_vcpu_set_sys_reg(
                vcpu.id(),
                sys::hv_sys_reg_t::CNTV_CVAL_EL0,
                now.wrapping_add(delay_ticks),
            ),
            "CNTV_CVAL_EL0",
        )?;
        gic_check(
            sys::hv_vcpu_set_sys_reg(vcpu.id(), sys::hv_sys_reg_t::CNTV_CTL_EL0, 1),
            "CNTV_CTL_EL0",
        )?;
    }
    probe.request = None;
    probe.taken_before = crate::trap::el1_irqs_taken(VTIMER_INTID);
    probe.report.armed = true;
    probe.report.vcpu = vcpu.id();
    Ok(())
}

/// After `hv_vcpu_run` returns (owning thread): account the exit of the
/// probed vCPU until the timer interrupt has been taken at EL1.
pub(crate) fn note_vtimer_probe_exit(vcpu: u64, host_initiated: impl FnOnce() -> bool) {
    if !VTIMER_PROBE_ACTIVE.load(std::sync::atomic::Ordering::Relaxed) {
        return;
    }
    let mut guard = VTIMER_PROBE.lock();
    let Some(probe) = guard.as_mut() else {
        return;
    };
    if !probe.report.armed || probe.report.delivered || probe.report.vcpu != vcpu {
        return;
    }
    if crate::trap::el1_irqs_taken(VTIMER_INTID) > probe.taken_before {
        probe.report.delivered = true;
        VTIMER_PROBE_ACTIVE.store(false, std::sync::atomic::Ordering::Relaxed);
    } else if host_initiated() {
        probe.report.host_initiated_exits += 1;
    } else {
        probe.report.other_exits += 1;
    }
}

/// `ID_AA64PFR0_EL1.GIC`, bits 27:24: the GIC system-register interface.
const ID_AA64PFR0_GIC_FIELD: u64 = 0xf << 24;

/// The value an EL0 read of `ID_AA64PFR0_EL1` returns. Linux does not expose
/// the GIC system-register field to userspace (it reads 0), and a GIC-less
/// Hypervisor.framework VM reports 0 there; with the in-kernel GIC the vCPU
/// reports 1. The EL0 view hides the field so the GIC is guest-invisible.
pub(crate) const fn el0_id_aa64pfr0_view(raw: u64) -> u64 {
    raw & !ID_AA64PFR0_GIC_FIELD
}

#[cfg(test)]
mod tests {
    use super::*;

    fn src(path: &str) -> String {
        std::fs::read_to_string(std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join(path))
            .unwrap_or_else(|error| panic!("{path}: {error}"))
    }

    /// Lines that are not `//` comments.
    fn code_lines(text: &str) -> String {
        text.lines()
            .filter(|line| !line.trim_start().starts_with("//"))
            .collect::<Vec<_>>()
            .join("\n")
    }

    #[test]
    fn mpidr_carries_res1_and_sgi_addressable_affinity() {
        assert_eq!(Mpidr::for_index(0).raw(), 0x8000_0000);
        assert_eq!(Mpidr::for_index(15).raw(), 0x8000_000f);
        assert_eq!(Mpidr::for_index(16).raw(), 0x8000_0100);
        assert_eq!(Mpidr::for_index(63).raw(), 0x8000_030f);
        let distinct: std::collections::BTreeSet<u64> = (0..256)
            .map(|index| Mpidr::for_index(index).raw())
            .collect();
        assert_eq!(distinct.len(), 256);
    }

    #[test]
    fn geometry_must_fit_the_reserved_window() {
        // Hypervisor.framework on macOS 27.2 / M4.
        let host = GicGeometry {
            distributor_size: 0x1_0000,
            distributor_alignment: 0x1_0000,
            redistributor_region_size: 0x200_0000,
            redistributor_size: 0x2_0000,
            redistributor_alignment: 0x1_0000,
        };
        assert!(host.fits_window().is_ok());
        assert_eq!(host.redistributor_capacity(), 256);
        let too_big = GicGeometry {
            redistributor_region_size: 0x1_0000_0000,
            ..host
        };
        assert!(too_big.fits_window().is_err());
        let misaligned = GicGeometry {
            redistributor_alignment: 0x200_0000,
            ..host
        };
        assert!(misaligned.fits_window().is_err());
        let unknown = GicGeometry {
            redistributor_size: 0,
            ..host
        };
        assert!(unknown.fits_window().is_err());
    }

    #[test]
    fn only_the_exact_hatch_value_disables_the_gic() {
        assert_eq!(interrupt_model_from_env(None), InterruptModel::Gic);
        assert_eq!(
            interrupt_model_from_env(Some("0".to_owned())),
            InterruptModel::LegacyPendingLine
        );
        for other in ["1", "", "false", "00", " 0"] {
            assert_eq!(
                interrupt_model_from_env(Some(other.to_owned())),
                InterruptModel::Gic,
                "{other:?}"
            );
        }
    }

    #[test]
    fn el0_view_of_id_aa64pfr0_hides_only_the_gic_field() {
        // Qualified live: GIC-less VM 0x1101000010110011, with a GIC
        // 0x1101000011110011.
        assert_eq!(
            el0_id_aa64pfr0_view(0x1101_0000_1111_0011),
            0x1101_0000_1011_0011
        );
        assert_eq!(
            el0_id_aa64pfr0_view(0x1101_0000_1011_0011),
            0x1101_0000_1011_0011
        );
    }

    /// One raw-API boundary: only this module names `hv_gic_*`.
    #[test]
    fn raw_hv_gic_calls_stay_in_gic_rs() {
        fn visit(dir: &std::path::Path, hits: &mut Vec<String>) {
            for entry in std::fs::read_dir(dir).unwrap() {
                let path = entry.unwrap().path();
                if path.is_dir() {
                    if path.file_name().is_some_and(|name| name == "bin") {
                        continue; // standalone probe binaries own their own VMs
                    }
                    visit(&path, hits);
                } else if path.extension().is_some_and(|ext| ext == "rs")
                    && !path.ends_with("gic.rs")
                    && std::fs::read_to_string(&path)
                        .unwrap()
                        .contains(concat!("hv_", "gic_"))
                {
                    hits.push(path.display().to_string());
                }
            }
        }
        let mut hits = Vec::new();
        visit(
            &std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src"),
            &mut hits,
        );
        assert!(hits.is_empty(), "raw hv_gic_* outside gic.rs: {hits:?}");
    }

    /// The GIC exists before any vCPU of the VM: it is created inside the
    /// VM-creation funnel, after hv_vm_create and before the funnel hands the
    /// VM to any caller.
    #[test]
    fn gic_is_created_inside_the_vm_creation_funnel() {
        let trap = code_lines(&src("src/trap.rs"));
        let funnel = trap
            .split(concat!("fn create_vm_with_", "admission("))
            .nth(1)
            .and_then(|rest| rest.split("\n}\n").next())
            .expect("create_vm_with_admission body");
        let create = funnel
            .find("virtual_machine_with_private_signals_blocked(")
            .expect("hv_vm_create");
        let gic = funnel
            .find("crate::gic::create_carrier_gic(")
            .expect("GIC creation in the funnel");
        let handoff = funnel.rfind("Ok((").expect("hand-off");
        assert!(create < gic && gic < handoff);
        let released = code_lines(&src("src/trap/vcpu_admission.rs"));
        let release = released
            .split("fn record_vm_released(")
            .nth(1)
            .and_then(|rest| rest.split("\n}\n").next())
            .expect("record_vm_released");
        assert!(release.contains("crate::gic::carrier_vm_released()"));
    }

    /// Every vCPU is configured before it is handed out, in both creation
    /// wrappers, and nothing else calls `vcpu_create()`.
    #[test]
    fn every_vcpu_is_configured_by_its_creation_wrapper() {
        let admission = code_lines(&src("src/trap/vcpu_admission.rs"));
        for wrapper in [
            concat!("fn create_vcpu_with_", "permit("),
            concat!("fn create_", "vcpu("),
        ] {
            let body = admission
                .split(wrapper)
                .nth(1)
                .and_then(|rest| rest.split("\n}\n").next())
                .expect("wrapper body");
            let created = body.find("vcpu_created(").expect("counted");
            let configure = body
                .find("crate::gic::configure_new_vcpu(guard.id())?")
                .expect("configure, failing closed");
            let guard = body
                .find("SetupVcpuGuard::new(vcpu, SetupVcpuCleanup::DestroyOnError)")
                .expect("a failed configuration destroys the vCPU");
            assert!(created < guard && guard < configure, "{wrapper}");
        }
        let mut production = String::new();
        for file in ["src/trap.rs", "src/hvf_aarch64_engine.rs"] {
            production.push_str(&code_lines(&src(file)));
        }
        for entry in
            std::fs::read_dir(std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/trap"))
                .unwrap()
        {
            let path = entry.unwrap().path();
            if path.extension().is_some_and(|ext| ext == "rs") {
                production.push_str(&code_lines(&std::fs::read_to_string(path).unwrap()));
            }
        }
        assert_eq!(production.matches(concat!(".vcpu_", "create()")).count(), 2);
    }

    /// The kick vehicle is chosen in one place: no other HVF source calls the
    /// legacy pending-interrupt API, which HVF refuses once a GIC exists.
    #[test]
    fn kick_vehicle_is_chosen_in_one_place() {
        let mut hits = Vec::new();
        for file in ["src/trap.rs", "src/hvf_aarch64_engine.rs"] {
            let count = code_lines(&src(file))
                .matches(concat!("set_pending_", "interrupt("))
                .count();
            if count != 0 {
                hits.push((file, count));
            }
        }
        assert!(
            hits.is_empty(),
            "legacy pending-interrupt calls outside gic.rs: {hits:?}"
        );
    }

    /// `run_to_exit` re-arms a kick that landed in an EL1 critical section and
    /// keeps running. Under the GIC that SGI survives run returns, so every
    /// exit `run_to_exit` surfaces other than the `hvc #4` kick exit (which
    /// withdraws it itself) must withdraw it, as `OwedKick::settle` does for
    /// the engine's owed kick.
    #[test]
    fn run_to_exit_withdraws_an_in_loop_kick_on_every_surfaced_exit() {
        let trap = code_lines(&src("src/trap.rs"));
        let outer = trap
            .split(concat!("pub(crate) fn run_to_", "exit("))
            .nth(1)
            .and_then(|rest| rest.split("\n    }\n").next())
            .expect("run_to_exit");
        assert!(outer.contains("Self::run_to_exit_inner(vcpu, mailbox, &mut kick_armed)"));
        assert!(outer.contains("crate::gic::clear_kick(vcpu)"));
        let inner = trap
            .split(concat!("fn run_to_exit_", "inner("))
            .nth(1)
            .expect("run_to_exit_inner");
        assert_eq!(inner.matches("*kick_armed = true").count(), 1);
        assert_eq!(inner.matches("*kick_armed = false").count(), 1);
        assert_eq!(inner.matches("crate::gic::arm_kick(vcpu)").count(), 1);
        assert_eq!(inner.matches("crate::gic::clear_kick(vcpu)").count(), 1);
    }
}
