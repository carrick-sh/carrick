//! The soft AArch64 carrier's in-guest zone (#2645 slice B): the carrier
//! enables the zone for its lifetime, registers its root executor, occupies
//! and publishes its vCPU slot and BINDs the root's address space, so the
//! production EL1 image (`CARRICK_A64_ELF`) serves private futex waits in the
//! ring and parks its idle vCPU until the virtual timer or a kick.
//!
//! The guests are raw A64 words in a static ELF, run on the native arm64
//! [`HostBlockRunner`] through the production soft entry
//! (`run_single_process_with_executor_and_setup`).
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use carrick_hal::GuestVmBackend as _;
use carrick_softcpu_aarch64_host::{
    HostBlockRunner, SoftProcessRun, SoftSingleProcessConfig,
    run_single_process_with_executor_and_setup, sample_el1_served,
};

const CODE_VA: u64 = 0x0040_0000;
const DATA_VA: u64 = 0x0040_1000;

/// The futex word (32 bits, initially 0).
const WORD_OFFSET: u64 = 0x00;
/// A relative `struct timespec` for the timed wait.
const TIMEOUT_OFFSET: u64 = 0x10;

const NR_FUTEX: u16 = 98;
const NR_EXIT_GROUP: u16 = 94;
const FUTEX_WAIT_PRIVATE: u16 = 128;
const LINUX_ETIMEDOUT: i32 = 110;

/// The timed wait's relative timeout: long against the soft EL1's idle path
/// on a cold translation cache, so the vCPU parks before it expires.
const TIMED_WAIT: Duration = Duration::from_secs(1);
/// A wait the witness ends with a wake, never its timeout.
const LONG_WAIT: Duration = Duration::from_secs(60);
/// How long a host thread waits for the guest's vCPU to park.
const PARK_DEADLINE: Duration = Duration::from_secs(120);

const A64_SVC_0: u32 = 0xd400_0001;
const A64_NOP: u32 = 0xd503_201f;

/// C6.2.226 MOVZ (64-bit): `movz xd, #imm16, lsl #(16 * hw)`.
const fn movz(rd: u32, imm16: u16, hw: u32) -> u32 {
    0xd280_0000 | (hw << 21) | ((imm16 as u32) << 5) | rd
}

/// C6.2.225 MOVK (64-bit): `movk xd, #imm16, lsl #(16 * hw)`.
const fn movk(rd: u32, imm16: u16, hw: u32) -> u32 {
    0xf280_0000 | (hw << 21) | ((imm16 as u32) << 5) | rd
}

/// `mov xd, #value` for a value below 2^32.
fn mov32(rd: u32, value: u64) -> [u32; 2] {
    assert!(value >> 32 == 0);
    [movz(rd, value as u16, 0), movk(rd, (value >> 16) as u16, 1)]
}

/// C6.2.231 NEG (shifted register): `neg xd, xm` (`sub xd, xzr, xm`).
const fn neg(rd: u32, rm: u32) -> u32 {
    0xcb00_0000 | (rm << 16) | (31 << 5) | rd
}

/// A static ELF: one page of code at [`CODE_VA`], one RW page at [`DATA_VA`].
fn build_elf(code_words: &[u32], data_init: &[(u64, &[u8])]) -> Vec<u8> {
    let mut elf = vec![0u8; 0x3000];
    elf[0..4].copy_from_slice(b"\x7fELF");
    elf[4] = 2; // ELFCLASS64
    elf[5] = 1; // ELFDATA2LSB
    elf[6] = 1; // EV_CURRENT
    elf[16..18].copy_from_slice(&2u16.to_le_bytes()); // ET_EXEC
    elf[18..20].copy_from_slice(&183u16.to_le_bytes()); // EM_AARCH64
    elf[20..24].copy_from_slice(&1u32.to_le_bytes());
    elf[24..32].copy_from_slice(&CODE_VA.to_le_bytes());
    elf[32..40].copy_from_slice(&64u64.to_le_bytes()); // e_phoff
    elf[52..54].copy_from_slice(&64u16.to_le_bytes()); // e_ehsize
    elf[54..56].copy_from_slice(&56u16.to_le_bytes()); // e_phentsize
    elf[56..58].copy_from_slice(&2u16.to_le_bytes()); // e_phnum
    let phdr = |buf: &mut [u8], base: usize, flags: u32, offset: u64, vaddr: u64| {
        buf[base..base + 4].copy_from_slice(&1u32.to_le_bytes()); // PT_LOAD
        buf[base + 4..base + 8].copy_from_slice(&flags.to_le_bytes());
        buf[base + 8..base + 16].copy_from_slice(&offset.to_le_bytes());
        buf[base + 16..base + 24].copy_from_slice(&vaddr.to_le_bytes());
        buf[base + 24..base + 32].copy_from_slice(&vaddr.to_le_bytes());
        buf[base + 32..base + 40].copy_from_slice(&0x1000u64.to_le_bytes());
        buf[base + 40..base + 48].copy_from_slice(&0x1000u64.to_le_bytes());
        buf[base + 48..base + 56].copy_from_slice(&0x1000u64.to_le_bytes());
    };
    phdr(&mut elf, 64, 5, 0x1000, CODE_VA); // PF_R | PF_X
    phdr(&mut elf, 120, 6, 0x2000, DATA_VA); // PF_R | PF_W
    assert!(code_words.len() <= 0x1000 / 4);
    for i in 0..0x1000 / 4 {
        let at = 0x1000 + i * 4;
        let word = code_words.get(i).copied().unwrap_or(A64_NOP);
        elf[at..at + 4].copy_from_slice(&word.to_le_bytes());
    }
    for &(offset, bytes) in data_init {
        let at = 0x2000 + offset as usize;
        elf[at..at + bytes.len()].copy_from_slice(bytes);
    }
    elf
}

fn timespec(duration: Duration) -> [u8; 16] {
    let mut bytes = [0u8; 16];
    bytes[..8].copy_from_slice(&duration.as_secs().to_le_bytes());
    bytes[8..].copy_from_slice(&u64::from(duration.subsec_nanos()).to_le_bytes());
    bytes
}

static SOFT_CARRIER_TEST_LOCK: Mutex<()> = Mutex::new(());

fn lock_soft_carrier_test() -> std::sync::MutexGuard<'static, ()> {
    SOFT_CARRIER_TEST_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

fn production_el1() -> Vec<u8> {
    std::fs::read(std::env::var_os("CARRICK_A64_ELF").expect("set CARRICK_A64_ELF"))
        .expect("read the production EL1 ELF")
}

/// The zone's scheduler counters of a run's carrier, read through its EL1
/// region after the run.
fn zone_counters(run: &SoftProcessRun<HostBlockRunner>) -> (u64, u64, u64) {
    use carrick_el1_abi::{EL1_REGION_BASE, EL1_REGION_SIZE, EL1_ZONE_OFFSET, ZoneTables};
    let region = run
        .engine
        .backend()
        .host_ptr(EL1_REGION_BASE, EL1_REGION_SIZE as usize)
        .expect("the carrier's EL1 region stays mapped with its engine");
    // SAFETY: the engine keeps its EL1 region mapped; the zone tables are an
    // aligned ABI record inside it, made of atomics.
    let zone = unsafe { &*(region.add(EL1_ZONE_OFFSET as usize).cast::<ZoneTables>()) };
    let read = |counter: &std::sync::atomic::AtomicU64| counter.load(Ordering::Acquire);
    (
        read(&zone.counters.el1_wfi_entries),
        read(&zone.counters.el1_idle_entries),
        read(&zone.counters.el1_idle_exits),
    )
}

/// What a host thread does once the guest's only thread is parked in the
/// zone and its vCPU waits in WFI.
type WhileParked = Box<dyn FnOnce() + Send>;

/// Run `elf` on the production soft entry, timing the run from its first
/// guest instruction. With `while_parked`, a second live thread, on the
/// host, runs it once the vCPU first parks in WFI.
fn run(
    elf: &[u8],
    path: &str,
    while_parked: Option<WhileParked>,
) -> (SoftProcessRun<HostBlockRunner>, Duration) {
    let el1 = production_el1();
    let mut config = SoftSingleProcessConfig::new(elf, path);
    config.el1_elf_override = Some(&el1);
    let started = Arc::new(Mutex::new(None));
    let started_in_setup = Arc::clone(&started);
    let host_thread = Arc::new(Mutex::new(None));
    let host_thread_in_setup = Arc::clone(&host_thread);
    let run = run_single_process_with_executor_and_setup(
        &config,
        HostBlockRunner::new().expect("native arm64 block runner"),
        move |_engine| {
            if let Some(action) = while_parked {
                let zone = carrick_el1_abi::zone_tables().ok_or("the carrier has no zone")?;
                *host_thread_in_setup.lock().unwrap() = Some(std::thread::spawn(move || {
                    let deadline = Instant::now() + PARK_DEADLINE;
                    while zone.counters.el1_wfi_entries.load(Ordering::Acquire) == 0 {
                        assert!(Instant::now() < deadline, "the vCPU never parked in WFI");
                        std::thread::sleep(Duration::from_millis(1));
                    }
                    action();
                }));
            }
            *started_in_setup.lock().unwrap() = Some(Instant::now());
            Ok(())
        },
    )
    .expect("the guest must run to exit on the production soft entry");
    if let Some(thread) = host_thread.lock().unwrap().take() {
        thread.join().expect("the host thread ran to completion");
    }
    let started = started.lock().unwrap().expect("setup ran");
    (run, started.elapsed())
}

/// `futex(FUTEX_WAIT_PRIVATE, &word, 0, &timeout)`, then `exit_group` with
/// the negated result: ETIMEDOUT exits 110, a wake exits 0.
fn timed_wait_elf(timeout: Duration) -> Vec<u8> {
    let mut code = Vec::new();
    code.extend(mov32(0, DATA_VA + WORD_OFFSET));
    code.push(movz(1, FUTEX_WAIT_PRIVATE, 0));
    code.push(movz(2, 0, 0));
    code.extend(mov32(3, DATA_VA + TIMEOUT_OFFSET));
    code.push(movz(8, NR_FUTEX, 0));
    code.push(A64_SVC_0);
    code.push(neg(0, 0));
    code.push(movz(8, NR_EXIT_GROUP, 0));
    code.push(A64_SVC_0);
    build_elf(&code, &[(TIMEOUT_OFFSET, &timespec(timeout))])
}

/// The futex wait was served once in the ring, and never reached the host.
fn assert_served_once_in_ring(run: &SoftProcessRun<HostBlockRunner>) {
    let served = sample_el1_served(&run.engine);
    assert!(
        served
            .iter()
            .any(|&(nr, _, count)| nr == u64::from(NR_FUTEX) && count == 1),
        "the futex wait must be served once in the ring: {served:?}"
    );
    // Only `exit_group` reaches the host.
    assert_eq!(run.syscalls_dispatched, 1, "{:?}", run.reply_census);
}

/// A private futex wait with a relative timeout on the root's only thread:
/// the EL1 ring parks the thread in the zone, the idle vCPU parks in WFI
/// until the virtual timer, and the wait returns `ETIMEDOUT`, without the
/// call ever reaching the host.
#[test]
#[ignore = "requires CARRICK_A64_ELF pointing to the production EL1 ELF (native arm64 host)"]
fn soft_zone_private_futex_timed_wait_expires_on_the_virtual_timer() {
    let _carrier_lock = lock_soft_carrier_test();
    let (run, elapsed) = run(&timed_wait_elf(TIMED_WAIT), "/futex-timed-wait", None);
    let (wfis, idle_entries, idle_exits) = zone_counters(&run);
    println!(
        "timed futex wait: exit={} elapsed={elapsed:?} census={:?} served={:?} idle_parks={} wfis={wfis} idle_entries={idle_entries} idle_exits={idle_exits}",
        run.exit_code,
        run.reply_census,
        sample_el1_served(&run.engine),
        run.engine.vcpu().idle_parks()
    );
    assert_eq!(run.exit_code, LINUX_ETIMEDOUT, "the wait must time out");
    assert!(
        elapsed >= TIMED_WAIT,
        "the wait returned after {elapsed:?}, before its {TIMED_WAIT:?} timeout"
    );
    assert_served_once_in_ring(&run);
    assert!(
        run.engine.vcpu().idle_parks() >= 1 && wfis >= 1,
        "the idle vCPU must park in WFI for the virtual timer"
    );
    assert_eq!(idle_exits, 0, "nothing owed the host an idle exit");
}

/// A kick of the parked vCPU's slot from a second live thread, on the host,
/// while the root's only thread waits in the zone: the vCPU leaves its WFI
/// park, EL1 leaves the idle loop for the host work, and the soft runner
/// serves the idle exit and returns the vCPU to the idle entry, where the
/// parked wait still expires on the virtual timer. The wait is neither ended
/// early nor redispatched.
#[test]
#[ignore = "requires CARRICK_A64_ELF pointing to the production EL1 ELF (native arm64 host)"]
fn soft_zone_kicked_idle_exit_returns_to_the_parked_timed_wait() {
    let _carrier_lock = lock_soft_carrier_test();
    let kick: WhileParked = Box::new(|| {
        carrick_kernel::el1_zone::kick_slot(carrick_el1_abi::SlotId::new(0));
    });
    let (run, elapsed) = run(
        &timed_wait_elf(TIMED_WAIT),
        "/futex-kicked-wait",
        Some(kick),
    );
    let (wfis, idle_entries, idle_exits) = zone_counters(&run);
    println!(
        "kicked timed futex wait: exit={} elapsed={elapsed:?} census={:?} served={:?} idle_parks={} wfis={wfis} idle_entries={idle_entries} idle_exits={idle_exits}",
        run.exit_code,
        run.reply_census,
        sample_el1_served(&run.engine),
        run.engine.vcpu().idle_parks()
    );
    assert_eq!(
        run.exit_code, LINUX_ETIMEDOUT,
        "a kick must not end the wait"
    );
    assert!(
        elapsed >= TIMED_WAIT,
        "the wait returned after {elapsed:?}, before its {TIMED_WAIT:?} timeout"
    );
    assert_served_once_in_ring(&run);
    assert!(
        idle_exits >= 1,
        "the kick's host work must leave the idle loop"
    );
    assert!(
        wfis >= 2 && run.engine.vcpu().idle_parks() >= 2,
        "the vCPU must park again after serving the idle exit"
    );
}

/// A futex wait/wake across the zone: the root's only thread waits in the
/// EL1 ring on a private futex with a long timeout, and a second live
/// thread, on the host, wakes it through the production zone queue (the
/// host half of a FUTEX_WAKE). The wake reaches the parked vCPU, which runs
/// the woken thread, and the wait returns 0 long before its timeout.
#[test]
#[ignore = "requires CARRICK_A64_ELF pointing to the production EL1 ELF (native arm64 host)"]
fn soft_zone_host_futex_wake_reaches_the_parked_ring_waiter() {
    let _carrier_lock = lock_soft_carrier_test();
    let woken = Arc::new(Mutex::new(None));
    let woken_by_host = Arc::clone(&woken);
    let wake: WhileParked = Box::new(move || {
        let zone = carrick_el1_abi::zone_tables().expect("the carrier's zone");
        let mm = carrick_kernel::kernel::MmId::from_raw_u64(
            zone.slot(carrick_el1_abi::SlotId::new(0)).mm(),
        )
        .expect("slot 0 runs the root's address space");
        let queue = carrick_kernel::el1_zone::FutexQueueAuthority::of_mm(mm)
            .zone()
            .expect("the root's private futexes live in the zone");
        let key = carrick_personality_linux::sched::MmFutexKey::private(
            carrick_guest_arch::UserVa::new(DATA_VA + WORD_OFFSET),
        )
        .expect("an aligned futex word");
        let wake = queue.wake(key, u32::MAX, 1);
        carrick_kernel::el1_zone::hand_back(&wake.handed);
        *woken_by_host.lock().unwrap() = Some(wake.count);
    });
    let (run, elapsed) = run(
        &timed_wait_elf(LONG_WAIT),
        "/futex-cross-zone-wake",
        Some(wake),
    );
    let (wfis, idle_entries, idle_exits) = zone_counters(&run);
    println!(
        "cross-zone futex wake: exit={} elapsed={elapsed:?} woken={:?} census={:?} served={:?} idle_parks={} wfis={wfis} idle_entries={idle_entries} idle_exits={idle_exits}",
        run.exit_code,
        woken.lock().unwrap(),
        run.reply_census,
        sample_el1_served(&run.engine),
        run.engine.vcpu().idle_parks()
    );
    assert_eq!(
        *woken.lock().unwrap(),
        Some(1),
        "the host wake found the waiter"
    );
    assert_eq!(run.exit_code, 0, "the woken wait returns 0");
    assert!(
        elapsed < LONG_WAIT,
        "the wake must end the wait before its {LONG_WAIT:?} timeout ({elapsed:?})"
    );
    assert_served_once_in_ring(&run);
}
