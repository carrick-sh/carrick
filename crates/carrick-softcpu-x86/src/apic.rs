//! Software local xAPIC (`ID`, `TPR`, `PPR`, `EOI`, `SVR`, `ISR`/`TMR`/`IRR`, `ESR`, `ICR`,
//! `LVT` timer) and `IA32_TSC_DEADLINE` / initial-count timer model for `carrick-softcpu-x86`.
//!
//! Models the architectural xAPIC register page at `IA32_APIC_BASE[35:12]` (default
//! `0xfee0_0000`), `CR8` <-> `TPR` synchronization, priority resolution (`PPR` vs `IRR`/`ISR`),
//! `EOI` completion, `ICR` inter-processor interrupts (self, broadcast, and physical/logical
//! target via [`ApicCluster`]), and deterministic/injectable [`TscClock`] deadlines with bounded
//! wakeups into the soft CPU execution loop.

use std::fmt;
use std::sync::atomic::{AtomicBool, AtomicU8, AtomicU32, AtomicU64, Ordering};
use std::sync::{Arc, Condvar, Mutex, RwLock, Weak};
use std::time::{Duration, Instant};

/// Default guest physical base address of the local xAPIC MMIO page.
pub const LAPIC_DEFAULT_PHYS_BASE: u64 = 0xfee0_0000;
/// Size in bytes of the local xAPIC MMIO register page.
pub const LAPIC_MMIO_SIZE: u64 = 0x1000;

/// Local APIC ID register offset (`0x020`, bits `31:24` hold the 8-bit xAPIC ID).
pub const LAPIC_ID_OFFSET: u16 = 0x020;
/// Local APIC Version register offset (`0x030`).
pub const LAPIC_VERSION_OFFSET: u16 = 0x030;
/// Task Priority Register offset (`0x080`).
pub const LAPIC_TPR_OFFSET: u16 = 0x080;
/// Arbitration Priority Register offset (`0x090`).
pub const LAPIC_APR_OFFSET: u16 = 0x090;
/// Processor Priority Register offset (`0x0a0`).
pub const LAPIC_PPR_OFFSET: u16 = 0x0a0;
/// End-Of-Interrupt register offset (`0x0b0`).
pub const LAPIC_EOI_OFFSET: u16 = 0x0b0;
/// Remote Read Register offset (`0x0c0`).
pub const LAPIC_RRD_OFFSET: u16 = 0x0c0;
/// Logical Destination Register offset (`0x0d0`).
pub const LAPIC_LDR_OFFSET: u16 = 0x0d0;
/// Destination Format Register offset (`0x0e0`).
pub const LAPIC_DFR_OFFSET: u16 = 0x0e0;
/// Spurious Interrupt Vector Register offset (`0x0f0`).
pub const LAPIC_SVR_OFFSET: u16 = 0x0f0;
/// In-Service Register bank base offset (`0x100..=0x170`, 8 x 16-byte-spaced 32-bit words).
pub const LAPIC_ISR_BASE_OFFSET: u16 = 0x100;
/// Trigger Mode Register bank base offset (`0x180..=0x1f0`, 8 x 16-byte-spaced 32-bit words).
pub const LAPIC_TMR_BASE_OFFSET: u16 = 0x180;
/// Interrupt Request Register bank base offset (`0x200..=0x270`, 8 x 16-byte-spaced 32-bit words).
pub const LAPIC_IRR_BASE_OFFSET: u16 = 0x200;
/// Error Status Register offset (`0x280`).
pub const LAPIC_ESR_OFFSET: u16 = 0x280;
/// LVT Corrected Machine Check Interrupt register offset (`0x2f0`).
pub const LAPIC_LVT_CMCI_OFFSET: u16 = 0x2f0;
/// Interrupt Command Register low 32-bit word offset (`0x300`; writing triggers IPI dispatch).
pub const LAPIC_ICR_LOW_OFFSET: u16 = 0x300;
/// Interrupt Command Register high 32-bit word offset (`0x310`; bits `31:24` hold destination ID).
pub const LAPIC_ICR_HIGH_OFFSET: u16 = 0x310;
/// LVT Timer register offset (`0x320`).
pub const LAPIC_LVT_TIMER_OFFSET: u16 = 0x320;
/// LVT Thermal Sensor register offset (`0x330`).
pub const LAPIC_LVT_THERMAL_OFFSET: u16 = 0x330;
/// LVT Performance Monitoring Counters register offset (`0x340`).
pub const LAPIC_LVT_PMC_OFFSET: u16 = 0x340;
/// LVT LINT0 register offset (`0x350`).
pub const LAPIC_LVT_LINT0_OFFSET: u16 = 0x350;
/// LVT LINT1 register offset (`0x360`).
pub const LAPIC_LVT_LINT1_OFFSET: u16 = 0x360;
/// LVT Error register offset (`0x370`).
pub const LAPIC_LVT_ERROR_OFFSET: u16 = 0x370;
/// Initial Count Register for APIC timer (`0x380`).
pub const LAPIC_TIMER_ICR_OFFSET: u16 = 0x380;
/// Current Count Register for APIC timer (`0x390`).
pub const LAPIC_TIMER_CCR_OFFSET: u16 = 0x390;
/// Divide Configuration Register for APIC timer (`0x3e0`).
pub const LAPIC_TIMER_DCR_OFFSET: u16 = 0x3e0;

/// Default local APIC version word: integrated xAPIC (`0x14`), 6 LVT entries (`max_lvt = 5`).
pub const LAPIC_VERSION_DEFAULT: u32 = 0x0005_0014;
/// Power-on reset value of `SVR`: APIC software-disabled, spurious vector `0xff`.
pub const LAPIC_SVR_RESET: u32 = 0x0000_00ff;
/// `SVR[8]`: APIC software enable bit.
pub const LAPIC_SVR_ENABLE: u32 = 1 << 8;
/// `LVT[16]`: interrupt delivery mask bit (`1` = masked).
pub const LAPIC_LVT_MASKED: u32 = 1 << 16;
/// Shift for `LVT_TIMER[18:17]` timer mode field.
pub const LAPIC_LVT_TIMER_MODE_SHIFT: u32 = 17;
/// Mask for `LVT_TIMER[18:17]` timer mode field.
pub const LAPIC_LVT_TIMER_MODE_MASK: u32 = 0b11 << LAPIC_LVT_TIMER_MODE_SHIFT;
/// `LVT_TIMER[18:17] = 0b00`: one-shot initial-count mode.
pub const LAPIC_LVT_TIMER_MODE_ONESHOT: u32 = 0b00 << LAPIC_LVT_TIMER_MODE_SHIFT;
/// `LVT_TIMER[18:17] = 0b01`: periodic initial-count mode.
pub const LAPIC_LVT_TIMER_MODE_PERIODIC: u32 = 0b01 << LAPIC_LVT_TIMER_MODE_SHIFT;
/// `LVT_TIMER[18:17] = 0b10`: `IA32_TSC_DEADLINE` mode.
pub const LAPIC_LVT_TIMER_MODE_TSC_DEADLINE: u32 = 0b10 << LAPIC_LVT_TIMER_MODE_SHIFT;

/// `ICR_LOW[10:8]` delivery mode mask.
pub const LAPIC_ICR_DELIVERY_MODE_MASK: u32 = 0b111 << 8;
/// `ICR_LOW[10:8] = 0b000`: fixed interrupt vector delivery.
pub const LAPIC_ICR_DELIVERY_FIXED: u32 = 0b000 << 8;
/// `ICR_LOW[10:8] = 0b001`: lowest-priority interrupt vector delivery.
pub const LAPIC_ICR_DELIVERY_LOWEST_PRIORITY: u32 = 0b001 << 8;
/// `ICR_LOW[11]`: logical destination mode (`0` = physical, `1` = logical).
pub const LAPIC_ICR_DEST_MODE_LOGICAL: u32 = 1 << 11;
/// `ICR_LOW[12]`: delivery status (`0` = idle, `1` = send pending).
pub const LAPIC_ICR_DELIVERY_STATUS_PENDING: u32 = 1 << 12;
/// `ICR_LOW[14]`: level (`0` = de-assert, `1` = assert).
pub const LAPIC_ICR_LEVEL_ASSERT: u32 = 1 << 14;
/// `ICR_LOW[15]`: trigger mode (`0` = edge, `1` = level).
pub const LAPIC_ICR_TRIGGER_LEVEL: u32 = 1 << 15;
/// Shift for `ICR_LOW[19:18]` destination shorthand field.
pub const LAPIC_ICR_SHORTHAND_SHIFT: u32 = 18;
/// Mask for `ICR_LOW[19:18]` destination shorthand field.
pub const LAPIC_ICR_SHORTHAND_MASK: u32 = 0b11 << LAPIC_ICR_SHORTHAND_SHIFT;
/// `ICR_LOW[19:18] = 0b00`: no shorthand (use destination field in `ICR_HIGH[31:24]`).
pub const LAPIC_ICR_SHORTHAND_NONE: u32 = 0b00 << LAPIC_ICR_SHORTHAND_SHIFT;
/// `ICR_LOW[19:18] = 0b01`: self IPI.
pub const LAPIC_ICR_SHORTHAND_SELF: u32 = 0b01 << LAPIC_ICR_SHORTHAND_SHIFT;
/// `ICR_LOW[19:18] = 0b10`: broadcast to all processors including self.
pub const LAPIC_ICR_SHORTHAND_ALL_INCLUDING_SELF: u32 = 0b10 << LAPIC_ICR_SHORTHAND_SHIFT;
/// `ICR_LOW[19:18] = 0b11`: broadcast to all processors excluding self.
pub const LAPIC_ICR_SHORTHAND_ALL_EXCLUDING_SELF: u32 = 0b11 << LAPIC_ICR_SHORTHAND_SHIFT;

/// `ESR[5]`: Send Illegal Vector (attempted IPI with vector `< 16`).
pub const LAPIC_ESR_SEND_ILLEGAL_VECTOR: u32 = 1 << 5;
/// `ESR[6]`: Receive Illegal Vector (received or local LVT vector `< 16`).
pub const LAPIC_ESR_RECEIVE_ILLEGAL_VECTOR: u32 = 1 << 6;
/// `ESR[7]`: Illegal Register Address.
pub const LAPIC_ESR_ILLEGAL_REG_ADDRESS: u32 = 1 << 7;

/// First architecturally valid interrupt vector for local APIC fixed/LVT delivery (`0..15` are
/// reserved for architectural exceptions and set `ESR` instead of `IRR`).
pub const LAPIC_MIN_VALID_VECTOR: u8 = 16;

/// Operating mode of the local APIC LVT timer (`LVT_TIMER[18:17]`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LapicTimerMode {
    /// One-shot countdown from `LAPIC_TIMER_ICR` (`0b00`).
    OneShot,
    /// Periodic reload of `LAPIC_TIMER_ICR` (`0b01`).
    Periodic,
    /// Absolute TSC deadline programmed via `IA32_TSC_DEADLINE` (`0b10`).
    TscDeadline,
    /// Reserved encoding (`0b11`).
    Reserved,
}

impl LapicTimerMode {
    /// Decodes `LVT_TIMER[18:17]`.
    #[must_use]
    pub const fn from_lvt(lvt_timer: u32) -> Self {
        match (lvt_timer & LAPIC_LVT_TIMER_MODE_MASK) >> LAPIC_LVT_TIMER_MODE_SHIFT {
            0b00 => Self::OneShot,
            0b01 => Self::Periodic,
            0b10 => Self::TscDeadline,
            _ => Self::Reserved,
        }
    }
}

/// Injectable time-stamp counter and bounded deadline wait source for `SoftCpu` / `SoftMachine`.
pub trait TscClock: Send + Sync + fmt::Debug {
    /// Returns the current unscaled TSC tick counter at nominal frequency `tsc_hz`.
    fn now_tsc(&self, tsc_hz: u64) -> u64;

    /// Waits until either `kick` is signaled, `deadline_tsc` is reached, or `max_wait` elapses.
    ///
    /// Returns `true` if a kick or deadline was reached before `max_wait` expired.
    fn wait_until(
        &self,
        deadline_tsc: Option<u64>,
        tsc_hz: u64,
        kick: &ApicNode,
        max_wait: Duration,
    ) -> bool;

    /// Optional hook allowing deterministic clocks to register an [`ApicNode`] so manual clock
    /// advances immediately wake parked `HLT` waiters.
    fn register_node(&self, _node: Weak<ApicNode>) {}
}

/// Host monotonic wall-clock TSC source backed by [`Instant`].
#[derive(Debug)]
pub struct MonotonicTscClock {
    base_tsc: AtomicU64,
    anchor: Instant,
}

impl MonotonicTscClock {
    /// Creates a monotonic TSC clock anchored at `Instant::now()` with `base_tsc`.
    #[must_use]
    pub fn new(base_tsc: u64) -> Self {
        Self {
            base_tsc: AtomicU64::new(base_tsc),
            anchor: Instant::now(),
        }
    }
}

impl Default for MonotonicTscClock {
    fn default() -> Self {
        Self::new(0)
    }
}

impl TscClock for MonotonicTscClock {
    fn now_tsc(&self, tsc_hz: u64) -> u64 {
        let elapsed_ns = self.anchor.elapsed().as_nanos();
        let delta = elapsed_ns
            .saturating_mul(u128::from(tsc_hz))
            .checked_div(1_000_000_000)
            .map_or(u64::MAX, |ticks| u64::try_from(ticks).unwrap_or(u64::MAX));
        self.base_tsc.load(Ordering::Acquire).saturating_add(delta)
    }

    fn wait_until(
        &self,
        deadline_tsc: Option<u64>,
        tsc_hz: u64,
        kick: &ApicNode,
        max_wait: Duration,
    ) -> bool {
        if kick.is_kicked() || kick.has_pending_irr() {
            return true;
        }
        let now = self.now_tsc(tsc_hz);
        if let Some(deadline) = deadline_tsc
            && now >= deadline
        {
            return true;
        }
        let wait_duration = if let Some(deadline) = deadline_tsc {
            let remaining_ticks = deadline.saturating_sub(now);
            let hz = tsc_hz.max(1);
            let nanos = u128::from(remaining_ticks)
                .saturating_mul(1_000_000_000)
                .saturating_add(u128::from(hz - 1))
                / u128::from(hz);
            let deadline_dur = Duration::from_nanos(u64::try_from(nanos).unwrap_or(u64::MAX));
            deadline_dur.min(max_wait)
        } else {
            max_wait
        };
        if wait_duration.is_zero() {
            return kick.is_kicked()
                || kick.has_pending_irr()
                || deadline_tsc.is_some_and(|d| self.now_tsc(tsc_hz) >= d);
        }
        kick.wait_for_kick_or_timeout(wait_duration);
        kick.is_kicked()
            || kick.has_pending_irr()
            || deadline_tsc.is_some_and(|d| self.now_tsc(tsc_hz) >= d)
    }
}

/// Deterministic, manually controlled [`TscClock`] for VM-free timer and IPI tests.
pub struct ManualTscClock {
    tsc: AtomicU64,
    auto_advance_on_wait: AtomicBool,
    nodes: Mutex<Vec<Weak<ApicNode>>>,
}

impl fmt::Debug for ManualTscClock {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ManualTscClock")
            .field("tsc", &self.tsc.load(Ordering::Relaxed))
            .field(
                "auto_advance_on_wait",
                &self.auto_advance_on_wait.load(Ordering::Relaxed),
            )
            .finish_non_exhaustive()
    }
}

impl ManualTscClock {
    /// Creates a manual TSC clock starting at `initial_tsc`.
    #[must_use]
    pub const fn new(initial_tsc: u64) -> Self {
        Self {
            tsc: AtomicU64::new(initial_tsc),
            auto_advance_on_wait: AtomicBool::new(false),
            nodes: Mutex::new(Vec::new()),
        }
    }

    /// Creates a manual TSC clock starting at `initial_tsc` that automatically advances to the
    /// armed timer deadline when a vCPU parks in `HLT` (`wait_until`).
    #[must_use]
    pub const fn with_auto_advance(initial_tsc: u64) -> Self {
        Self {
            tsc: AtomicU64::new(initial_tsc),
            auto_advance_on_wait: AtomicBool::new(true),
            nodes: Mutex::new(Vec::new()),
        }
    }

    /// Configures whether `wait_until` automatically advances the clock to an armed timer deadline.
    pub fn set_auto_advance_on_wait(&self, enabled: bool) {
        self.auto_advance_on_wait.store(enabled, Ordering::Release);
    }

    /// Returns the current manual TSC value.
    #[must_use]
    pub fn now(&self) -> u64 {
        self.tsc.load(Ordering::Acquire)
    }

    /// Sets the manual TSC value and notifies any parked [`ApicNode`] waiters.
    pub fn set(&self, value: u64) {
        self.tsc.store(value, Ordering::Release);
        self.notify_nodes();
    }

    /// Advances the manual TSC value by `delta` and returns the new TSC value.
    pub fn advance(&self, delta: u64) -> u64 {
        let prev = self.tsc.fetch_add(delta, Ordering::AcqRel);
        let next = prev.saturating_add(delta);
        self.notify_nodes();
        next
    }

    fn notify_nodes(&self) {
        if let Ok(mut guard) = self.nodes.lock() {
            guard.retain(|weak| {
                if let Some(node) = weak.upgrade() {
                    node.notify_clock_advance();
                    true
                } else {
                    false
                }
            });
        }
    }
}

impl Default for ManualTscClock {
    fn default() -> Self {
        Self::new(0)
    }
}

impl TscClock for ManualTscClock {
    fn now_tsc(&self, _tsc_hz: u64) -> u64 {
        self.now()
    }

    fn wait_until(
        &self,
        deadline_tsc: Option<u64>,
        _tsc_hz: u64,
        kick: &ApicNode,
        max_wait: Duration,
    ) -> bool {
        if kick.is_kicked() || kick.has_pending_irr() {
            return true;
        }
        let now = self.now();
        if let Some(deadline) = deadline_tsc {
            if now >= deadline {
                return true;
            }
            if self.auto_advance_on_wait.load(Ordering::Acquire) {
                self.set(deadline);
                return true;
            }
        }
        if max_wait.is_zero() {
            return kick.is_kicked()
                || kick.has_pending_irr()
                || deadline_tsc.is_some_and(|d| self.now() >= d);
        }
        kick.wait_for_kick_or_timeout(max_wait);
        kick.is_kicked()
            || kick.has_pending_irr()
            || deadline_tsc.is_some_and(|d| self.now() >= d)
    }

    fn register_node(&self, node: Weak<ApicNode>) {
        if let Ok(mut guard) = self.nodes.lock() {
            guard.push(node);
        }
    }
}

/// Thread-safe shared endpoint for one vCPU's local xAPIC (`IRR` bitmap + kick/wake condvar).
///
/// Cross-vCPU IPIs and external host interrupt/timer kicks target [`ApicNode`] without taking a
/// mutable borrow on the target vCPU's [`LocalApic`].
pub struct ApicNode {
    apic_id: AtomicU8,
    svr: AtomicU32,
    ldr: AtomicU32,
    dfr: AtomicU32,
    irr: [AtomicU32; 8],
    esr_pending: AtomicU32,
    kick_flag: AtomicBool,
    wait_lock: Mutex<u64>,
    wait_cv: Condvar,
}

impl fmt::Debug for ApicNode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ApicNode")
            .field("apic_id", &self.apic_id())
            .field("svr", &self.svr.load(Ordering::Relaxed))
            .field("kicked", &self.is_kicked())
            .finish_non_exhaustive()
    }
}

impl ApicNode {
    /// Creates a new [`ApicNode`] with the given 8-bit `apic_id`.
    #[must_use]
    pub fn new(apic_id: u8) -> Self {
        Self {
            apic_id: AtomicU8::new(apic_id),
            svr: AtomicU32::new(LAPIC_SVR_RESET),
            ldr: AtomicU32::new(0),
            dfr: AtomicU32::new(0xffff_ffff),
            irr: [
                AtomicU32::new(0),
                AtomicU32::new(0),
                AtomicU32::new(0),
                AtomicU32::new(0),
                AtomicU32::new(0),
                AtomicU32::new(0),
                AtomicU32::new(0),
                AtomicU32::new(0),
            ],
            esr_pending: AtomicU32::new(0),
            kick_flag: AtomicBool::new(false),
            wait_lock: Mutex::new(0),
            wait_cv: Condvar::new(),
        }
    }

    /// Returns this local APIC's 8-bit ID (`LAPIC_ID[31:24]`).
    #[must_use]
    pub fn apic_id(&self) -> u8 {
        self.apic_id.load(Ordering::Acquire)
    }

    /// Returns `true` if `SVR[8]` (APIC software enable) is set.
    #[must_use]
    pub fn software_enabled(&self) -> bool {
        (self.svr.load(Ordering::Acquire) & LAPIC_SVR_ENABLE) != 0
    }

    /// Injects a fixed interrupt `vector` into this APIC's `IRR` and kicks any parked waiter.
    ///
    /// Returns `true` if the vector was accepted into `IRR` (`SVR[8] == 1` and `vector >= 16`).
    pub fn inject_interrupt(&self, vector: u8) -> bool {
        if !self.software_enabled() {
            return false;
        }
        if vector < LAPIC_MIN_VALID_VECTOR {
            self.esr_pending
                .fetch_or(LAPIC_ESR_RECEIVE_ILLEGAL_VECTOR, Ordering::AcqRel);
            self.kick();
            return false;
        }
        let word = usize::from(vector >> 5);
        let mask = 1u32 << (vector & 31);
        self.irr[word].fetch_or(mask, Ordering::AcqRel);
        self.kick();
        true
    }

    /// Sets the kick flag and wakes any thread blocked in `wait_for_kick_or_timeout`.
    pub fn kick(&self) {
        self.kick_flag.store(true, Ordering::Release);
        if let Ok(mut epoch) = self.wait_lock.lock() {
            *epoch = epoch.wrapping_add(1);
            self.wait_cv.notify_all();
        }
    }

    /// Wakes any thread blocked in `wait_for_kick_or_timeout` when a manual clock advances.
    pub fn notify_clock_advance(&self) {
        if let Ok(mut epoch) = self.wait_lock.lock() {
            *epoch = epoch.wrapping_add(1);
            self.wait_cv.notify_all();
        }
    }

    /// Returns `true` if a kick has been signaled since the last `take_kick`.
    #[must_use]
    pub fn is_kicked(&self) -> bool {
        self.kick_flag.load(Ordering::Acquire)
    }

    /// Atomically consumes and clears the kick flag.
    pub fn take_kick(&self) -> bool {
        self.kick_flag.swap(false, Ordering::AcqRel)
    }

    /// Returns `true` if any bit in `IRR` is currently pending.
    #[must_use]
    pub fn has_pending_irr(&self) -> bool {
        self.irr.iter().any(|w| w.load(Ordering::Acquire) != 0)
    }

    /// Returns the highest-priority pending vector in `IRR` (`16..=255`), if any.
    #[must_use]
    pub fn highest_irr_vector(&self) -> Option<u8> {
        for idx in (0..8).rev() {
            let word = self.irr[idx].load(Ordering::Acquire);
            if word != 0 {
                let bit = 31 - word.leading_zeros();
                let vec = u8::try_from(idx * 32 + bit as usize).unwrap_or(0);
                if vec >= LAPIC_MIN_VALID_VECTOR {
                    return Some(vec);
                }
            }
        }
        None
    }

    /// Waits on the node's condvar until kicked, an `IRR` bit is set, or `timeout` elapses.
    pub fn wait_for_kick_or_timeout(&self, timeout: Duration) -> bool {
        if self.is_kicked() || self.has_pending_irr() || timeout.is_zero() {
            return self.is_kicked() || self.has_pending_irr();
        }
        let Ok(guard) = self.wait_lock.lock() else {
            return self.is_kicked() || self.has_pending_irr();
        };
        if self.is_kicked() || self.has_pending_irr() {
            return true;
        }
        let start_epoch = *guard;
        let _ = self.wait_cv.wait_timeout_while(guard, timeout, |epoch| {
            *epoch == start_epoch && !self.is_kicked() && !self.has_pending_irr()
        });
        self.is_kicked() || self.has_pending_irr()
    }

    fn matches_logical(&self, dest_mask: u8) -> bool {
        if dest_mask == 0 {
            return false;
        }
        let ldr = (self.ldr.load(Ordering::Acquire) >> 24) as u8;
        let model = (self.dfr.load(Ordering::Acquire) >> 28) & 0xf;
        match model {
            // Flat model (`DFR[31:28] == 0b1111`): bitwise AND of 8-bit logical destination masks.
            0b1111 => (ldr & dest_mask) != 0,
            // Cluster model (`DFR[31:28] == 0b0000`): upper 4 bits cluster address, lower 4 bits mask.
            0b0000 => (ldr >> 4) == (dest_mask >> 4) && ((ldr & 0x0f) & (dest_mask & 0x0f)) != 0,
            _ => false,
        }
    }
}

/// Shared interconnect routing xAPIC `ICR` IPIs between multiple soft vCPUs.
#[derive(Debug, Default)]
pub struct ApicCluster {
    nodes: RwLock<Vec<Arc<ApicNode>>>,
}

impl ApicCluster {
    /// Creates an empty [`ApicCluster`].
    #[must_use]
    pub fn new() -> Self {
        Self {
            nodes: RwLock::new(Vec::new()),
        }
    }

    /// Registers a vCPU's [`ApicNode`] with this cluster (replacing any prior entry with the same
    /// initial `apic_id`).
    pub fn register(&self, node: Arc<ApicNode>) {
        if let Ok(mut guard) = self.nodes.write() {
            let id = node.apic_id();
            if let Some(slot) = guard
                .iter_mut()
                .find(|existing| Arc::ptr_eq(existing, &node) || existing.apic_id() == id)
            {
                *slot = node;
            } else {
                guard.push(node);
            }
        }
    }

    /// Looks up a registered [`ApicNode`] by physical `apic_id`.
    #[must_use]
    pub fn node(&self, apic_id: u8) -> Option<Arc<ApicNode>> {
        let guard = self.nodes.read().ok()?;
        guard.iter().find(|n| n.apic_id() == apic_id).cloned()
    }

    /// Injects a fixed interrupt `vector` into the target `apic_id` and kicks it.
    pub fn send_ipi_physical(&self, dest_apic_id: u8, vector: u8) -> bool {
        let Some(target) = self.node(dest_apic_id) else {
            return false;
        };
        target.inject_interrupt(vector)
    }

    /// Dispatches an architectural `ICR` command issued by `sender_id`.
    ///
    /// Returns the number of target APICs into which `vector` was latched.
    pub fn dispatch_icr(&self, sender: &ApicNode, icr_low: u32, icr_high: u32) -> usize {
        let vector = (icr_low & 0xff) as u8;
        let delivery_mode = icr_low & LAPIC_ICR_DELIVERY_MODE_MASK;
        if delivery_mode != LAPIC_ICR_DELIVERY_FIXED
            && delivery_mode != LAPIC_ICR_DELIVERY_LOWEST_PRIORITY
        {
            return 0;
        }
        // De-assert level-triggered INIT (`level == 0`, `trigger == 1`) is a no-op.
        if (icr_low & LAPIC_ICR_TRIGGER_LEVEL) != 0 && (icr_low & LAPIC_ICR_LEVEL_ASSERT) == 0 {
            return 0;
        }
        let shorthand = icr_low & LAPIC_ICR_SHORTHAND_MASK;
        if shorthand == LAPIC_ICR_SHORTHAND_SELF {
            return usize::from(sender.inject_interrupt(vector));
        }

        let logical = (icr_low & LAPIC_ICR_DEST_MODE_LOGICAL) != 0;
        let dest = (icr_high >> 24) as u8;
        let sender_id = sender.apic_id();

        let targets: Vec<Arc<ApicNode>> = if let Ok(guard) = self.nodes.read() {
            guard.clone()
        } else {
            return 0;
        };

        // If sender is standalone (not registered in cluster), still handle ALL_INCLUDING_SELF /
        // physical self-targeting against `sender`.
        if targets.is_empty() {
            let matches_self = match shorthand {
                LAPIC_ICR_SHORTHAND_ALL_INCLUDING_SELF => true,
                LAPIC_ICR_SHORTHAND_NONE => {
                    if logical {
                        sender.matches_logical(dest)
                    } else {
                        dest == sender_id
                    }
                }
                _ => false,
            };
            return if matches_self {
                usize::from(sender.inject_interrupt(vector))
            } else {
                0
            };
        }

        let mut delivered = 0usize;
        for node in &targets {
            let id = node.apic_id();
            let selected = match shorthand {
                LAPIC_ICR_SHORTHAND_ALL_INCLUDING_SELF => true,
                LAPIC_ICR_SHORTHAND_ALL_EXCLUDING_SELF => id != sender_id,
                LAPIC_ICR_SHORTHAND_NONE => {
                    if logical {
                        node.matches_logical(dest)
                    } else {
                        dest == 0xff || id == dest
                    }
                }
                _ => false,
            };
            if selected && node.inject_interrupt(vector) {
                delivered += 1;
            }
        }
        delivered
    }
}

/// Per-vCPU local xAPIC register file and timer state.
#[derive(Debug)]
pub struct LocalApic {
    node: Arc<ApicNode>,
    cluster: Option<Arc<ApicCluster>>,
    version: u32,
    tpr: u8,
    isr: [u32; 8],
    tmr: [u32; 8],
    esr: u32,
    esr_write_pending: u32,
    icr_low: u32,
    icr_high: u32,
    lvt_cmci: u32,
    lvt_timer: u32,
    lvt_thermal: u32,
    lvt_pmc: u32,
    lvt_lint0: u32,
    lvt_lint1: u32,
    lvt_error: u32,
    lvt_timer_written: bool,
    timer_icr: u32,
    timer_dcr: u32,
    timer_start_tsc: u64,
    timer_target_tsc: u64,
    timer_period_tsc: u64,
    timer_armed: bool,
    delivered_count: u64,
    eoi_count: u64,
    ipi_sent_count: u64,
    timer_fire_count: u64,
}

impl Clone for LocalApic {
    fn clone(&self) -> Self {
        let cloned_node = Arc::new(ApicNode::new(self.node.apic_id()));
        cloned_node
            .svr
            .store(self.node.svr.load(Ordering::Acquire), Ordering::Release);
        cloned_node
            .ldr
            .store(self.node.ldr.load(Ordering::Acquire), Ordering::Release);
        cloned_node
            .dfr
            .store(self.node.dfr.load(Ordering::Acquire), Ordering::Release);
        for (dst, src) in cloned_node.irr.iter().zip(self.node.irr.iter()) {
            dst.store(src.load(Ordering::Acquire), Ordering::Release);
        }
        cloned_node.esr_pending.store(
            self.node.esr_pending.load(Ordering::Acquire),
            Ordering::Release,
        );
        Self {
            node: cloned_node,
            cluster: self.cluster.clone(),
            version: self.version,
            tpr: self.tpr,
            isr: self.isr,
            tmr: self.tmr,
            esr: self.esr,
            esr_write_pending: self.esr_write_pending,
            icr_low: self.icr_low,
            icr_high: self.icr_high,
            lvt_cmci: self.lvt_cmci,
            lvt_timer: self.lvt_timer,
            lvt_thermal: self.lvt_thermal,
            lvt_pmc: self.lvt_pmc,
            lvt_lint0: self.lvt_lint0,
            lvt_lint1: self.lvt_lint1,
            lvt_error: self.lvt_error,
            lvt_timer_written: self.lvt_timer_written,
            timer_icr: self.timer_icr,
            timer_dcr: self.timer_dcr,
            timer_start_tsc: self.timer_start_tsc,
            timer_target_tsc: self.timer_target_tsc,
            timer_period_tsc: self.timer_period_tsc,
            timer_armed: self.timer_armed,
            delivered_count: self.delivered_count,
            eoi_count: self.eoi_count,
            ipi_sent_count: self.ipi_sent_count,
            timer_fire_count: self.timer_fire_count,
        }
    }
}

impl Default for LocalApic {
    fn default() -> Self {
        Self::new(0)
    }
}

impl LocalApic {
    /// Creates a power-on reset [`LocalApic`] with the specified 8-bit `apic_id`.
    #[must_use]
    pub fn new(apic_id: u8) -> Self {
        Self {
            node: Arc::new(ApicNode::new(apic_id)),
            cluster: None,
            version: LAPIC_VERSION_DEFAULT,
            tpr: 0,
            isr: [0; 8],
            tmr: [0; 8],
            esr: 0,
            esr_write_pending: 0,
            icr_low: 0,
            icr_high: 0,
            lvt_cmci: LAPIC_LVT_MASKED,
            lvt_timer: LAPIC_LVT_MASKED,
            lvt_thermal: LAPIC_LVT_MASKED,
            lvt_pmc: LAPIC_LVT_MASKED,
            lvt_lint0: LAPIC_LVT_MASKED,
            lvt_lint1: LAPIC_LVT_MASKED,
            lvt_error: LAPIC_LVT_MASKED,
            lvt_timer_written: false,
            timer_icr: 0,
            timer_dcr: 0,
            timer_start_tsc: 0,
            timer_target_tsc: 0,
            timer_period_tsc: 0,
            timer_armed: false,
            delivered_count: 0,
            eoi_count: 0,
            ipi_sent_count: 0,
            timer_fire_count: 0,
        }
    }

    /// Returns a shared handle to this APIC's [`ApicNode`] for cross-thread kicks and IPIs.
    #[must_use]
    pub fn node(&self) -> Arc<ApicNode> {
        Arc::clone(&self.node)
    }

    /// Attaches this [`LocalApic`] to a shared [`ApicCluster`] and registers its [`ApicNode`].
    pub fn attach_cluster(&mut self, cluster: Arc<ApicCluster>) {
        cluster.register(Arc::clone(&self.node));
        self.cluster = Some(cluster);
    }

    /// Returns the attached [`ApicCluster`], if any.
    #[must_use]
    pub fn cluster(&self) -> Option<&Arc<ApicCluster>> {
        self.cluster.as_ref()
    }

    /// Returns the 8-bit xAPIC ID (`LAPIC_ID[31:24]`).
    #[must_use]
    pub fn apic_id(&self) -> u8 {
        self.node.apic_id()
    }

    /// Sets the 8-bit xAPIC ID (`LAPIC_ID[31:24]`).
    pub fn set_apic_id(&mut self, apic_id: u8) {
        self.node.apic_id.store(apic_id, Ordering::Release);
    }

    /// Returns the 8-bit Task Priority Register (`TPR[7:0]`).
    #[must_use]
    pub const fn tpr(&self) -> u8 {
        self.tpr
    }

    /// Returns the 4-bit `CR8` view of `TPR` (`TPR[7:4]`).
    #[must_use]
    pub const fn cr8(&self) -> u8 {
        self.tpr >> 4
    }

    /// Synchronizes `TPR` from a `MOV to CR8` write (`TPR[7:4] = cr8[3:0]`, `TPR[3:0] = 0`).
    pub fn set_cr8(&mut self, cr8: u8) {
        self.tpr = (cr8 & 0x0f) << 4;
    }

    /// Sets the 8-bit `TPR` directly (`LAPIC_TPR[7:0]`).
    pub fn set_tpr(&mut self, tpr: u8) {
        self.tpr = tpr;
    }

    /// Returns the Spurious Interrupt Vector Register (`SVR`).
    #[must_use]
    pub fn svr(&self) -> u32 {
        self.node.svr.load(Ordering::Acquire)
    }

    /// Returns `true` if `SVR[8]` (software enable) is set.
    #[must_use]
    pub fn software_enabled(&self) -> bool {
        self.node.software_enabled()
    }

    /// Returns the current `LVT_TIMER` register (`0x320`).
    #[must_use]
    pub const fn lvt_timer(&self) -> u32 {
        self.lvt_timer
    }

    /// Returns the decoded [`LapicTimerMode`] from `LVT_TIMER[18:17]`.
    #[must_use]
    pub const fn timer_mode(&self) -> LapicTimerMode {
        LapicTimerMode::from_lvt(self.lvt_timer)
    }

    /// Returns `true` if `LVT_TIMER` was explicitly written via MMIO with a non-TSC-deadline mode.
    #[must_use]
    pub const fn rejects_tsc_deadline_msr(&self) -> bool {
        self.lvt_timer_written && !matches!(self.timer_mode(), LapicTimerMode::TscDeadline)
    }

    /// Returns the highest-priority vector currently in service (`ISR`), if any.
    #[must_use]
    pub fn highest_isr_vector(&self) -> Option<u8> {
        for idx in (0..8).rev() {
            let word = self.isr[idx];
            if word != 0 {
                let bit = 31 - word.leading_zeros();
                return u8::try_from(idx * 32 + bit as usize).ok();
            }
        }
        None
    }

    /// Returns the highest-priority vector currently pending in `IRR`, if any.
    #[must_use]
    pub fn highest_irr_vector(&self) -> Option<u8> {
        self.node.highest_irr_vector()
    }

    /// Computes the architectural Processor Priority Register (`PPR[7:0]`) per Intel SDM Vol. 3A
    /// §10.8.3.1:
    /// `if TPR[7:4] >= ISRV[7:4] { TPR[7:0] } else { ISRV[7:4] << 4 }`.
    #[must_use]
    pub fn ppr(&self) -> u8 {
        let isrv = self.highest_isr_vector().unwrap_or(0);
        if (self.tpr >> 4) >= (isrv >> 4) {
            self.tpr
        } else {
            isrv & 0xf0
        }
    }

    /// Returns `true` if the `vector` bit is set in `IRR`.
    #[must_use]
    pub fn irr_bit(&self, vector: u8) -> bool {
        let word = usize::from(vector >> 5);
        let mask = 1u32 << (vector & 31);
        (self.node.irr[word].load(Ordering::Acquire) & mask) != 0
    }

    /// Returns `true` if the `vector` bit is set in `ISR`.
    #[must_use]
    pub const fn isr_bit(&self, vector: u8) -> bool {
        let word = (vector >> 5) as usize;
        let mask = 1u32 << (vector & 31);
        (self.isr[word] & mask) != 0
    }

    /// Returns the number of interrupts accepted from `IRR` into `ISR`.
    #[must_use]
    pub const fn delivered_count(&self) -> u64 {
        self.delivered_count
    }

    /// Returns the number of `EOI` writes processed.
    #[must_use]
    pub const fn eoi_count(&self) -> u64 {
        self.eoi_count
    }

    /// Returns the number of `ICR` IPI commands issued by this local APIC.
    #[must_use]
    pub const fn ipi_sent_count(&self) -> u64 {
        self.ipi_sent_count
    }

    /// Returns the number of timer expirations observed by this local APIC.
    #[must_use]
    pub const fn timer_fire_count(&self) -> u64 {
        self.timer_fire_count
    }

    /// Injects a fixed interrupt `vector` into this APIC's `IRR` and kicks any parked waiter.
    pub fn inject_interrupt(&self, vector: u8) -> bool {
        self.node.inject_interrupt(vector)
    }

    /// Performs an End-Of-Interrupt (`EOI`): clears the highest-priority bit in `ISR` (and `TMR`).
    pub fn eoi(&mut self) {
        self.eoi_count = self.eoi_count.saturating_add(1);
        if let Some(vec) = self.highest_isr_vector() {
            let word = usize::from(vec >> 5);
            let mask = 1u32 << (vec & 31);
            self.isr[word] &= !mask;
            self.tmr[word] &= !mask;
        }
    }

    /// Returns `true` if an unmasked interrupt in `IRR` outranks `PPR` (`vec[7:4] > PPR[7:4]`).
    #[must_use]
    pub fn has_deliverable_interrupt(&self, apic_hw_enabled: bool) -> bool {
        if !apic_hw_enabled || !self.software_enabled() {
            return false;
        }
        let Some(vec) = self.highest_irr_vector() else {
            return false;
        };
        (vec >> 4) > (self.ppr() >> 4)
    }

    /// Returns `true` if any interrupt is pending in `IRR` while the APIC is enabled (used to
    /// check whether `HLT` has a wakeup condition when `IF` or `TPR` is inspected).
    #[must_use]
    pub fn has_pending_interrupt(&self, apic_hw_enabled: bool) -> bool {
        apic_hw_enabled && self.software_enabled() && self.node.has_pending_irr()
    }

    /// Accepts the highest-priority deliverable interrupt from `IRR`, moving it to `ISR`.
    pub fn accept_interrupt(&mut self, apic_hw_enabled: bool) -> Option<u8> {
        if !apic_hw_enabled || !self.software_enabled() {
            return None;
        }
        let vec = self.highest_irr_vector()?;
        if (vec >> 4) <= (self.ppr() >> 4) {
            return None;
        }
        let word = usize::from(vec >> 5);
        let mask = 1u32 << (vec & 31);
        self.node.irr[word].fetch_and(!mask, Ordering::AcqRel);
        self.isr[word] |= mask;
        self.delivered_count = self.delivered_count.saturating_add(1);
        Some(vec)
    }

    /// Returns the next armed TSC deadline (`IA32_TSC_DEADLINE` or initial-count target TSC), if any.
    #[must_use]
    pub fn next_timer_deadline_tsc(&self, apic_hw_enabled: bool, tsc_deadline_msr: u64) -> Option<u64> {
        if !apic_hw_enabled || !self.software_enabled() {
            return None;
        }
        match self.timer_mode() {
            LapicTimerMode::TscDeadline => (tsc_deadline_msr != 0).then_some(tsc_deadline_msr),
            LapicTimerMode::OneShot | LapicTimerMode::Periodic => {
                self.timer_armed.then_some(self.timer_target_tsc)
            }
            LapicTimerMode::Reserved => None,
        }
    }

    /// Evaluates both `IA32_TSC_DEADLINE` and initial-count APIC timers against `now_tsc`.
    ///
    /// Returns `true` if a timer expired on this poll (disarming `tsc_deadline_msr` in
    /// `TscDeadline` mode and latching `LVT_TIMER[7:0]` into `IRR` when unmasked).
    pub fn poll_timer(
        &mut self,
        apic_hw_enabled: bool,
        now_tsc: u64,
        tsc_deadline_msr: &mut u64,
    ) -> bool {
        if !apic_hw_enabled {
            return false;
        }
        match self.timer_mode() {
            LapicTimerMode::TscDeadline => {
                let deadline = *tsc_deadline_msr;
                if deadline == 0 || now_tsc < deadline {
                    return false;
                }
                // Disarm IA32_TSC_DEADLINE upon expiration per SDM Vol. 3A §10.5.4.1.
                *tsc_deadline_msr = 0;
                self.timer_fire_count = self.timer_fire_count.saturating_add(1);
                if self.software_enabled() && (self.lvt_timer & LAPIC_LVT_MASKED) == 0 {
                    let vector = (self.lvt_timer & 0xff) as u8;
                    self.node.inject_interrupt(vector);
                }
                true
            }
            LapicTimerMode::OneShot => {
                if !self.timer_armed || now_tsc < self.timer_target_tsc {
                    return false;
                }
                self.timer_armed = false;
                self.timer_fire_count = self.timer_fire_count.saturating_add(1);
                if self.software_enabled() && (self.lvt_timer & LAPIC_LVT_MASKED) == 0 {
                    let vector = (self.lvt_timer & 0xff) as u8;
                    self.node.inject_interrupt(vector);
                }
                true
            }
            LapicTimerMode::Periodic => {
                if !self.timer_armed || now_tsc < self.timer_target_tsc {
                    return false;
                }
                let period = self.timer_period_tsc.max(1);
                let elapsed_past = now_tsc.saturating_sub(self.timer_target_tsc);
                let periods = (elapsed_past / period).saturating_add(1);
                self.timer_start_tsc = now_tsc;
                self.timer_target_tsc = self
                    .timer_target_tsc
                    .saturating_add(periods.saturating_mul(period));
                self.timer_fire_count = self.timer_fire_count.saturating_add(1);
                if self.software_enabled() && (self.lvt_timer & LAPIC_LVT_MASKED) == 0 {
                    let vector = (self.lvt_timer & 0xff) as u8;
                    self.node.inject_interrupt(vector);
                }
                true
            }
            LapicTimerMode::Reserved => false,
        }
    }

    #[must_use]
    const fn timer_divisor(&self) -> u64 {
        let dcr = self.timer_dcr;
        let idx = ((dcr & 0b11) | ((dcr >> 1) & 0b100)) & 0b111;
        match idx {
            0b000 => 2,
            0b001 => 4,
            0b010 => 8,
            0b011 => 16,
            0b100 => 32,
            0b101 => 64,
            0b110 => 128,
            _ => 1,
        }
    }

    fn current_timer_ccr(&self, now_tsc: u64) -> u32 {
        if matches!(
            self.timer_mode(),
            LapicTimerMode::TscDeadline | LapicTimerMode::Reserved
        ) || !self.timer_armed
            || self.timer_icr == 0
        {
            return 0;
        }
        if now_tsc >= self.timer_target_tsc {
            return 0;
        }
        let remaining_tsc = self.timer_target_tsc - now_tsc;
        let div = self.timer_divisor();
        let remaining_counts = remaining_tsc.saturating_add(div - 1) / div;
        u32::try_from(remaining_counts.min(u64::from(self.timer_icr))).unwrap_or(self.timer_icr)
    }

    fn record_error(&mut self, bits: u32) {
        self.esr_write_pending |= bits;
        if self.software_enabled() && (self.lvt_error & LAPIC_LVT_MASKED) == 0 {
            let vec = (self.lvt_error & 0xff) as u8;
            if vec >= LAPIC_MIN_VALID_VECTOR {
                self.node.inject_interrupt(vec);
            } else {
                self.esr_write_pending |= LAPIC_ESR_RECEIVE_ILLEGAL_VECTOR;
            }
        }
    }

    fn pull_async_esr(&mut self) {
        let async_bits = self.node.esr_pending.swap(0, Ordering::AcqRel);
        if async_bits != 0 {
            self.esr_write_pending |= async_bits;
        }
    }

    /// Reads a 32-bit architectural xAPIC register at 16-byte-aligned `reg_offset`.
    pub fn read_reg32(&mut self, reg_offset: u16, now_tsc: u64) -> u32 {
        self.pull_async_esr();
        match reg_offset {
            LAPIC_ID_OFFSET => u32::from(self.apic_id()) << 24,
            LAPIC_VERSION_OFFSET => self.version,
            LAPIC_TPR_OFFSET => u32::from(self.tpr),
            LAPIC_APR_OFFSET | LAPIC_RRD_OFFSET => 0,
            LAPIC_PPR_OFFSET => u32::from(self.ppr()),
            LAPIC_EOI_OFFSET => 0,
            LAPIC_LDR_OFFSET => self.node.ldr.load(Ordering::Acquire),
            LAPIC_DFR_OFFSET => self.node.dfr.load(Ordering::Acquire),
            LAPIC_SVR_OFFSET => self.svr(),
            offset if (0x100..=0x170).contains(&offset) && (offset & 0x0f) == 0 => {
                let idx = usize::from((offset - LAPIC_ISR_BASE_OFFSET) >> 4);
                self.isr[idx]
            }
            offset if (0x180..=0x1f0).contains(&offset) && (offset & 0x0f) == 0 => {
                let idx = usize::from((offset - LAPIC_TMR_BASE_OFFSET) >> 4);
                self.tmr[idx]
            }
            offset if (0x200..=0x270).contains(&offset) && (offset & 0x0f) == 0 => {
                let idx = usize::from((offset - LAPIC_IRR_BASE_OFFSET) >> 4);
                self.node.irr[idx].load(Ordering::Acquire)
            }
            LAPIC_ESR_OFFSET => self.esr | self.esr_write_pending,
            LAPIC_LVT_CMCI_OFFSET => self.lvt_cmci,
            LAPIC_ICR_LOW_OFFSET => self.icr_low & !LAPIC_ICR_DELIVERY_STATUS_PENDING,
            LAPIC_ICR_HIGH_OFFSET => self.icr_high,
            LAPIC_LVT_TIMER_OFFSET => self.lvt_timer,
            LAPIC_LVT_THERMAL_OFFSET => self.lvt_thermal,
            LAPIC_LVT_PMC_OFFSET => self.lvt_pmc,
            LAPIC_LVT_LINT0_OFFSET => self.lvt_lint0,
            LAPIC_LVT_LINT1_OFFSET => self.lvt_lint1,
            LAPIC_LVT_ERROR_OFFSET => self.lvt_error,
            LAPIC_TIMER_ICR_OFFSET => self.timer_icr,
            LAPIC_TIMER_CCR_OFFSET => self.current_timer_ccr(now_tsc),
            LAPIC_TIMER_DCR_OFFSET => self.timer_dcr,
            _ => {
                self.record_error(LAPIC_ESR_ILLEGAL_REG_ADDRESS);
                0
            }
        }
    }

    /// Writes a 32-bit architectural xAPIC register at 16-byte-aligned `reg_offset`.
    pub fn write_reg32(
        &mut self,
        reg_offset: u16,
        value: u32,
        now_tsc: u64,
        tsc_deadline_msr: &mut u64,
    ) {
        self.pull_async_esr();
        match reg_offset {
            LAPIC_ID_OFFSET => {
                let new_id = (value >> 24) as u8;
                self.set_apic_id(new_id);
            }
            LAPIC_TPR_OFFSET => {
                self.tpr = (value & 0xff) as u8;
            }
            LAPIC_EOI_OFFSET => {
                self.eoi();
            }
            LAPIC_LDR_OFFSET => {
                self.node
                    .ldr
                    .store(value & 0xff00_0000, Ordering::Release);
            }
            LAPIC_DFR_OFFSET => {
                self.node
                    .dfr
                    .store((value & 0xf000_0000) | 0x0fff_ffff, Ordering::Release);
            }
            LAPIC_SVR_OFFSET => {
                let new_svr = value & 0x0000_13ff;
                self.node.svr.store(new_svr, Ordering::Release);
                if (new_svr & LAPIC_SVR_ENABLE) == 0 {
                    // Software-disabling the local APIC masks all LVT entries per SDM Vol. 3A §10.4.7.2.
                    self.lvt_cmci |= LAPIC_LVT_MASKED;
                    self.lvt_timer |= LAPIC_LVT_MASKED;
                    self.lvt_thermal |= LAPIC_LVT_MASKED;
                    self.lvt_pmc |= LAPIC_LVT_MASKED;
                    self.lvt_lint0 |= LAPIC_LVT_MASKED;
                    self.lvt_lint1 |= LAPIC_LVT_MASKED;
                    self.lvt_error |= LAPIC_LVT_MASKED;
                }
            }
            LAPIC_ESR_OFFSET => {
                // Writing ESR latches accumulated error bits into the readable ESR and clears
                // the pending accumulator.
                self.esr = self.esr_write_pending;
                self.esr_write_pending = 0;
            }
            LAPIC_LVT_CMCI_OFFSET => {
                self.lvt_cmci = value & 0x0001_07ff;
            }
            LAPIC_ICR_HIGH_OFFSET => {
                self.icr_high = value & 0xff00_0000;
            }
            LAPIC_ICR_LOW_OFFSET => {
                self.icr_low = value & !LAPIC_ICR_DELIVERY_STATUS_PENDING;
                self.ipi_sent_count = self.ipi_sent_count.saturating_add(1);
                let vector = (value & 0xff) as u8;
                let delivery_mode = value & LAPIC_ICR_DELIVERY_MODE_MASK;
                if (delivery_mode == LAPIC_ICR_DELIVERY_FIXED
                    || delivery_mode == LAPIC_ICR_DELIVERY_LOWEST_PRIORITY)
                    && vector < LAPIC_MIN_VALID_VECTOR
                {
                    self.record_error(LAPIC_ESR_SEND_ILLEGAL_VECTOR);
                    return;
                }
                if let Some(cluster) = self.cluster.as_ref() {
                    cluster.dispatch_icr(&self.node, self.icr_low, self.icr_high);
                } else {
                    let shorthand = self.icr_low & LAPIC_ICR_SHORTHAND_MASK;
                    let dest = (self.icr_high >> 24) as u8;
                    let logical = (self.icr_low & LAPIC_ICR_DEST_MODE_LOGICAL) != 0;
                    let self_targeted = match shorthand {
                        LAPIC_ICR_SHORTHAND_SELF | LAPIC_ICR_SHORTHAND_ALL_INCLUDING_SELF => true,
                        LAPIC_ICR_SHORTHAND_NONE => {
                            if logical {
                                self.node.matches_logical(dest)
                            } else {
                                dest == self.apic_id()
                            }
                        }
                        _ => false,
                    };
                    if self_targeted {
                        self.node.inject_interrupt(vector);
                    }
                }
            }
            LAPIC_LVT_TIMER_OFFSET => {
                let prev_mode = self.timer_mode();
                let prev_was_written = self.lvt_timer_written;
                self.lvt_timer = value & 0x0007_00ff;
                self.lvt_timer_written = true;
                let next_mode = self.timer_mode();
                // Switching between TSC-deadline and counter modes disarms the timer per SDM Vol. 3A §10.5.4.1.
                if prev_was_written && prev_mode != next_mode {
                    *tsc_deadline_msr = 0;
                    self.timer_icr = 0;
                    self.timer_armed = false;
                    self.timer_target_tsc = 0;
                } else if !matches!(next_mode, LapicTimerMode::TscDeadline) {
                    *tsc_deadline_msr = 0;
                }
            }
            LAPIC_LVT_THERMAL_OFFSET => {
                self.lvt_thermal = value & 0x0001_07ff;
            }
            LAPIC_LVT_PMC_OFFSET => {
                self.lvt_pmc = value & 0x0001_07ff;
            }
            LAPIC_LVT_LINT0_OFFSET => {
                self.lvt_lint0 = value & 0x0001_f7ff;
            }
            LAPIC_LVT_LINT1_OFFSET => {
                self.lvt_lint1 = value & 0x0001_f7ff;
            }
            LAPIC_LVT_ERROR_OFFSET => {
                self.lvt_error = value & 0x0001_00ff;
            }
            LAPIC_TIMER_ICR_OFFSET => {
                self.timer_icr = value;
                if matches!(
                    self.timer_mode(),
                    LapicTimerMode::OneShot | LapicTimerMode::Periodic
                ) {
                    if value == 0 {
                        self.timer_armed = false;
                        self.timer_target_tsc = 0;
                        self.timer_period_tsc = 0;
                    } else {
                        let div = self.timer_divisor();
                        let period = u64::from(value).saturating_mul(div);
                        self.timer_start_tsc = now_tsc;
                        self.timer_period_tsc = period;
                        self.timer_target_tsc = now_tsc.saturating_add(period);
                        self.timer_armed = true;
                    }
                }
            }
            LAPIC_TIMER_DCR_OFFSET => {
                self.timer_dcr = value & 0x0b;
            }
            _ => {
                self.record_error(LAPIC_ESR_ILLEGAL_REG_ADDRESS);
            }
        }
    }

    /// Reads up to 8 bytes from the local xAPIC MMIO page at `offset` (`0..0x1000`).
    pub fn mmio_read(&mut self, offset: u16, size: usize, now_tsc: u64) -> [u8; 8] {
        let mut out = [0u8; 8];
        let clamped_size = size.min(8);
        let reg_base = offset & !0x3;
        let byte_in_word = usize::from(offset & 0x3);
        let word = if (reg_base & 0x0f) == 0 {
            self.read_reg32(reg_base, now_tsc)
        } else {
            0
        };
        let word_bytes = word.to_le_bytes();
        for (i, dst) in out.iter_mut().take(clamped_size).enumerate() {
            if byte_in_word + i < 4 {
                *dst = word_bytes[byte_in_word + i];
            }
        }
        out
    }

    /// Writes `bytes` (`1..=8` bytes) to the local xAPIC MMIO page at `offset` (`0..0x1000`).
    pub fn mmio_write(
        &mut self,
        offset: u16,
        bytes: &[u8],
        now_tsc: u64,
        tsc_deadline_msr: &mut u64,
    ) {
        if bytes.is_empty() {
            return;
        }
        let reg_base = offset & !0x3;
        if (reg_base & 0x0f) != 0 {
            self.record_error(LAPIC_ESR_ILLEGAL_REG_ADDRESS);
            return;
        }
        let mut word_bytes = [0u8; 4];
        let byte_in_word = usize::from(offset & 0x3);
        for (i, &b) in bytes.iter().enumerate() {
            if byte_in_word + i < 4 {
                word_bytes[byte_in_word + i] = b;
            }
        }
        let value = u32::from_le_bytes(word_bytes);
        self.write_reg32(reg_base, value, now_tsc, tsc_deadline_msr);
    }
}
