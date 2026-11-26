//! The soft AArch64 carrier's in-guest zone (#2645 slice B): the carrier
//! enables the zone for its lifetime, registers its root executor, occupies
//! and publishes its vCPU slot and BINDs the root's address space, so the
//! production EL1 image (`CARRICK_A64_ELF`) serves private futex waits in the
//! ring and parks its idle vCPU until the virtual timer or a kick.
//!
//! Slice C admits the root itself: the carrier binds the kernel's births to
//! the zone's issuers and publishes the root's own namespace PID, so EL1
//! admits a root process owner on the first call, serves its process calls
//! (`set_tid_address`, `prlimit64`, `exit_group`) in the ring, and ends the
//! run through the native root-exit crossing.
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
const NR_SET_TID_ADDRESS: u16 = 96;
const NR_GETTID: u16 = 178;
const NR_PRLIMIT64: u16 = 261;
const NR_RT_SIGACTION: u16 = 134;
const NR_RT_SIGRETURN: u16 = 139;
const NR_KILL: u16 = 129;
const NR_GETPID: u16 = 172;
/// `SA_RESTORER`: the handler returns through `sa_restorer`.
const SA_RESTORER: u64 = 0x0400_0000;
/// Where the caught handler stores the signal number it was given.
const CAUGHT_OFFSET: u64 = 0xe0;
const RLIMIT_STACK: u16 = 3;
const SIGUSR1: u16 = 10;
const SIG_IGN: u64 = 1;
const LINUX_EFAULT: i32 = 14;
const LINUX_ENOSYS: i32 = 38;
const LINUX_EINVAL: i32 = 22;
/// The root's `clear_child_tid` word.
const CLEAR_TID_OFFSET: u64 = 0x20;
/// A `struct rlimit` the ring copies the old limit out to.
const RLIMIT_OFFSET: u64 = 0x40;
/// A `struct sigaction` naming a caught handler.
const SIGACTION_OFFSET: u64 = 0x80;
/// A `struct sigaction` ignoring the signal.
const IGNORE_OFFSET: u64 = 0xa0;
/// A `struct sigaction` the ring copies the old action out to.
const OLD_SIGACTION_OFFSET: u64 = 0xc0;
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

/// C6.2.205 MOV (register): `mov xd, xm` (`orr xd, xzr, xm`).
const fn mov(rd: u32, rm: u32) -> u32 {
    0xaa00_0000 | (rm << 16) | (31 << 5) | rd
}

/// C6.2.4 ADD (shifted register): `add xd, xn, xm`.
const fn add(rd: u32, rn: u32, rm: u32) -> u32 {
    0x8b00_0000 | (rm << 16) | (rn << 5) | rd
}

/// C6.2.308 SUB (shifted register): `sub xd, xn, xm`.
const fn sub(rd: u32, rn: u32, rm: u32) -> u32 {
    0xcb00_0000 | (rm << 16) | (rn << 5) | rd
}

/// C6.2.2 ADD (immediate): `add xd, xn, #imm12`.
const fn add_imm(rd: u32, rn: u32, imm12: u32) -> u32 {
    0x9100_0000 | (imm12 << 10) | (rn << 5) | rd
}

/// C6.2.306 SUB (immediate): `sub xd, xn, #imm12`.
const fn sub_imm(rd: u32, rn: u32, imm12: u32) -> u32 {
    0xd100_0000 | (imm12 << 10) | (rn << 5) | rd
}

/// C6.2.200 LSR (immediate): `lsr xd, xn, #shift` (`ubfm xd, xn, #shift, #63`).
const fn lsr(rd: u32, rn: u32, shift: u32) -> u32 {
    0xd340_fc00 | (shift << 16) | (rn << 5) | rd
}

/// C6.2.170 LDR (immediate, unsigned offset): `ldr xt, [xn, #offset]`.
const fn ldr(rt: u32, rn: u32, offset: u32) -> u32 {
    0xf940_0000 | ((offset / 8) << 10) | (rn << 5) | rt
}

/// C6.2.333 STR (immediate, unsigned offset): `str xt, [xn, #offset]`.
const fn str_imm(rt: u32, rn: u32, offset: u32) -> u32 {
    0xf900_0000 | ((offset / 8) << 10) | (rn << 5) | rt
}

/// C6.2.254 RET: `ret` (to x30).
const A64_RET: u32 = 0xd65f_03c0;

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
    assert_root_served_in_ring(&run, &[NR_FUTEX, NR_EXIT_GROUP]);
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
    assert_root_served_in_ring(&run, &[NR_FUTEX, NR_EXIT_GROUP]);
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
    assert_root_served_in_ring(&run, &[NR_FUTEX, NR_EXIT_GROUP]);
}

/// The ring served each of `calls` once, and nothing reached the host or
/// was refused: the root's process owner answered them all.
fn assert_root_served_in_ring(run: &SoftProcessRun<HostBlockRunner>, calls: &[u16]) {
    let served = sample_el1_served(&run.engine);
    for &nr in calls {
        assert!(
            served
                .iter()
                .any(|&(served_nr, _, count)| served_nr == u64::from(nr) && count == 1),
            "syscall {nr} must be served once in the ring: {served:?}"
        );
    }
    assert_eq!(run.counted_enosys, Vec::new(), "nothing is refused");
    assert_eq!(
        run.reply_census.kernel_dispatched, 0,
        "no call reaches the host: {:?}",
        run.reply_census
    );
}

/// `exit_group` of `code` computed into x0.
fn exit_with_x0(code: &mut Vec<u32>) {
    code.push(movz(8, NR_EXIT_GROUP, 0));
    code.push(A64_SVC_0);
}

/// `prlimit64(0, resource, NULL, old)` with the result in x19.
fn prlimit_query(code: &mut Vec<u32>, resource: u16, old: u64) {
    code.push(movz(0, 0, 0));
    code.push(movz(1, resource, 0));
    code.push(movz(2, 0, 0));
    code.extend(mov32(3, old));
    code.push(movz(8, NR_PRLIMIT64, 0));
    code.push(A64_SVC_0);
    code.push(mov(19, 0));
}

/// The root's first call, `set_tid_address`, returns its own TID: the ring
/// admits the root process owner and answers in the ring, and the TID it
/// returns is positive and the one `gettid` reports. Exits
/// `set_tid_address() - gettid() + (set_tid_address() < 0)`: 0 iff they
/// agree on a positive TID.
#[test]
#[ignore = "requires CARRICK_A64_ELF pointing to the production EL1 ELF (native arm64 host)"]
fn soft_root_set_tid_address_returns_its_own_tid_in_ring() {
    let _carrier_lock = lock_soft_carrier_test();
    let mut code = Vec::new();
    code.extend(mov32(0, DATA_VA + CLEAR_TID_OFFSET));
    code.push(movz(8, NR_SET_TID_ADDRESS, 0));
    code.push(A64_SVC_0);
    code.push(mov(19, 0));
    code.push(movz(8, NR_GETTID, 0));
    code.push(A64_SVC_0);
    code.push(sub(0, 19, 0));
    code.push(lsr(20, 19, 63));
    code.push(add(0, 0, 20));
    exit_with_x0(&mut code);
    let (run, _) = run(&build_elf(&code, &[]), "/set-tid-address", None);
    println!(
        "set_tid_address: exit={} census={:?} served={:?} counted_enosys={:?}",
        run.exit_code,
        run.reply_census,
        sample_el1_served(&run.engine),
        run.counted_enosys
    );
    assert_eq!(run.exit_code, 0, "set_tid_address returns the caller's TID");
    assert_root_served_in_ring(&run, &[NR_SET_TID_ADDRESS, NR_EXIT_GROUP]);
}

/// `prlimit64` queries the root's `RLIMIT_STACK` in the ring and copies it
/// out: the launch's 8 MiB soft limit and an unlimited hard limit, the same
/// limits the host kernel's root task starts with. Exits
/// `ret + (rlim_cur >> 20) - 8 + (rlim_max + 1)`: 0 iff the call succeeded
/// and copied out exactly those limits.
#[test]
#[ignore = "requires CARRICK_A64_ELF pointing to the production EL1 ELF (native arm64 host)"]
fn soft_root_prlimit64_copies_out_the_stack_limit_in_ring() {
    let _carrier_lock = lock_soft_carrier_test();
    let mut code = Vec::new();
    code.extend(mov32(9, DATA_VA + RLIMIT_OFFSET));
    prlimit_query(&mut code, RLIMIT_STACK, DATA_VA + RLIMIT_OFFSET);
    code.push(ldr(20, 9, 0));
    code.push(ldr(21, 9, 8));
    code.push(lsr(20, 20, 20));
    code.push(sub_imm(20, 20, 8));
    code.push(add_imm(21, 21, 1));
    code.push(add(0, 19, 20));
    code.push(add(0, 0, 21));
    exit_with_x0(&mut code);
    let (run, _) = run(&build_elf(&code, &[]), "/prlimit-stack", None);
    println!(
        "prlimit64 RLIMIT_STACK: exit={} census={:?} served={:?} counted_enosys={:?}",
        run.exit_code,
        run.reply_census,
        sample_el1_served(&run.engine),
        run.counted_enosys
    );
    assert_eq!(
        run.exit_code, 0,
        "prlimit64 copies out 8 MiB / RLIM_INFINITY for RLIMIT_STACK"
    );
    assert_root_served_in_ring(&run, &[NR_PRLIMIT64, NR_EXIT_GROUP]);
}

/// The ring refuses a `prlimit64` of an unknown resource with `EINVAL` and
/// an unmapped output pointer with `EFAULT`, as Linux does.
#[test]
#[ignore = "requires CARRICK_A64_ELF pointing to the production EL1 ELF (native arm64 host)"]
fn soft_root_prlimit64_refuses_a_bad_resource_and_a_bad_pointer_in_ring() {
    let _carrier_lock = lock_soft_carrier_test();
    for (resource, old, errno, path) in [
        (
            999,
            DATA_VA + RLIMIT_OFFSET,
            LINUX_EINVAL,
            "/prlimit-einval",
        ),
        (RLIMIT_STACK, 0x10, LINUX_EFAULT, "/prlimit-efault"),
    ] {
        let mut code = Vec::new();
        prlimit_query(&mut code, resource, old);
        code.push(neg(0, 19));
        exit_with_x0(&mut code);
        let (run, _) = run(&build_elf(&code, &[]), path, None);
        println!(
            "prlimit64({resource}, {old:#x}): exit={} census={:?} served={:?} counted_enosys={:?}",
            run.exit_code,
            run.reply_census,
            sample_el1_served(&run.engine),
            run.counted_enosys
        );
        assert_eq!(run.exit_code, errno, "{path}");
        assert_root_served_in_ring(&run, &[NR_PRLIMIT64, NR_EXIT_GROUP]);
    }
}

/// The root's `exit_group` is the ring's: its status crosses to the host
/// through the native root exit, and the run ends with it in full.
#[test]
#[ignore = "requires CARRICK_A64_ELF pointing to the production EL1 ELF (native arm64 host)"]
fn soft_root_exit_group_status_crosses_the_native_root_exit() {
    let _carrier_lock = lock_soft_carrier_test();
    let mut code = vec![movz(0, 7, 0)];
    exit_with_x0(&mut code);
    let (run, _) = run(&build_elf(&code, &[]), "/exit-seven", None);
    println!(
        "exit_group(7): exit={} census={:?} served={:?}",
        run.exit_code,
        run.reply_census,
        sample_el1_served(&run.engine)
    );
    assert_eq!(run.exit_code, 7);
    assert_root_served_in_ring(&run, &[NR_EXIT_GROUP]);
}

/// The soft root's owner cannot publish a caught signal's frame yet (its MM
/// is not portal-admitted, #2645 slice D), so installing a handler stays
/// unrouted, a counted `ENOSYS`, never an accepted handler the ring cannot
/// deliver. Ignore and default dispositions need no frame: the ring serves
/// them, and a query reads the ignore back. Exits
/// `(handler + ENOSYS) + ignore + query + (old - SIG_IGN)`: 0 iff the handler
/// was refused and the ignore was installed and read back.
#[test]
#[ignore = "requires CARRICK_A64_ELF pointing to the production EL1 ELF (native arm64 host)"]
fn soft_root_rt_sigaction_refuses_a_handler_it_cannot_deliver() {
    let _carrier_lock = lock_soft_carrier_test();
    let mut handler = [0u8; 32];
    handler[..8].copy_from_slice(&(CODE_VA + 0x800).to_le_bytes());
    let mut ignore = [0u8; 32];
    ignore[..8].copy_from_slice(&SIG_IGN.to_le_bytes());
    let mut code = Vec::new();
    for (act, old, result) in [
        (Some(SIGACTION_OFFSET), None, 19),
        (Some(IGNORE_OFFSET), None, 20),
        (None, Some(OLD_SIGACTION_OFFSET), 21),
    ] {
        code.push(movz(0, SIGUSR1, 0));
        match act {
            Some(offset) => code.extend(mov32(1, DATA_VA + offset)),
            None => code.push(movz(1, 0, 0)),
        }
        match old {
            Some(offset) => code.extend(mov32(2, DATA_VA + offset)),
            None => code.push(movz(2, 0, 0)),
        }
        code.push(movz(3, 8, 0));
        code.push(movz(8, NR_RT_SIGACTION, 0));
        code.push(A64_SVC_0);
        code.push(mov(result, 0));
    }
    code.extend(mov32(9, DATA_VA + OLD_SIGACTION_OFFSET));
    code.push(ldr(22, 9, 0));
    code.push(sub_imm(22, 22, SIG_IGN as u32));
    code.push(add_imm(0, 19, LINUX_ENOSYS as u32));
    code.push(add(0, 0, 20));
    code.push(add(0, 0, 21));
    code.push(add(0, 0, 22));
    exit_with_x0(&mut code);
    let (run, _) = run(
        &build_elf(
            &code,
            &[(SIGACTION_OFFSET, &handler), (IGNORE_OFFSET, &ignore)],
        ),
        "/rt-sigaction",
        None,
    );
    let served = sample_el1_served(&run.engine);
    println!(
        "rt_sigaction: exit={} census={:?} served={served:?} counted_enosys={:?}",
        run.exit_code, run.reply_census, run.counted_enosys
    );
    assert_eq!(
        run.exit_code, 0,
        "the handler is refused ENOSYS; the ignore is installed and read back"
    );
    assert_eq!(
        run.counted_enosys,
        vec![(u64::from(NR_RT_SIGACTION), "rt_sigaction", 1)],
        "the refused handler is counted"
    );
    assert!(
        served
            .iter()
            .any(|&(nr, _, count)| nr == u64::from(NR_RT_SIGACTION) && count == 2),
        "the ring serves the ignore and the query: {served:?}"
    );
    assert_eq!(
        run.reply_census.kernel_dispatched, 0,
        "no disposition reaches the host's table: {:?}",
        run.reply_census
    );
}

/// The soft root catches a signal it sends itself (#2814): it installs a
/// `SIGUSR1` handler with `SA_RESTORER`, runs `kill(getpid(), SIGUSR1)`, the
/// ring builds the handler's frame on the user stack, the handler stores the
/// signal number it was given, and `rt_sigreturn` through the restorer
/// resumes the interrupted `kill` with its result. Exits
/// `(caught - SIGUSR1) + sigaction + kill`: 0 iff the handler was accepted,
/// ran once with `SIGUSR1`, and both calls returned 0.
///
/// Red while the soft root's MM is not portal-admitted: the handler is
/// refused `ENOSYS`, and the signal's default action ends the process.
#[test]
#[ignore = "requires CARRICK_A64_ELF pointing to the production EL1 ELF (native arm64 host)"]
fn soft_root_delivers_a_caught_sigusr1_and_returns_through_rt_sigreturn() {
    let _carrier_lock = lock_soft_carrier_test();
    const HANDLER_WORD: usize = 0x800 / 4;
    const RESTORER_WORD: usize = 0xc00 / 4;
    let mut action = [0u8; 32];
    action[..8].copy_from_slice(&(CODE_VA + 0x800).to_le_bytes());
    action[8..16].copy_from_slice(&SA_RESTORER.to_le_bytes());
    action[16..24].copy_from_slice(&(CODE_VA + 0xc00).to_le_bytes());
    let mut code = Vec::new();
    code.push(movz(0, SIGUSR1, 0));
    code.extend(mov32(1, DATA_VA + SIGACTION_OFFSET));
    code.push(movz(2, 0, 0));
    code.push(movz(3, 8, 0));
    code.push(movz(8, NR_RT_SIGACTION, 0));
    code.push(A64_SVC_0);
    code.push(mov(19, 0));
    code.push(movz(8, NR_GETPID, 0));
    code.push(A64_SVC_0);
    code.push(movz(1, SIGUSR1, 0));
    code.push(movz(8, NR_KILL, 0));
    code.push(A64_SVC_0);
    code.push(mov(20, 0));
    code.extend(mov32(9, DATA_VA + CAUGHT_OFFSET));
    code.push(ldr(21, 9, 0));
    code.push(sub_imm(0, 21, u32::from(SIGUSR1)));
    code.push(add(0, 0, 19));
    code.push(add(0, 0, 20));
    exit_with_x0(&mut code);
    assert!(code.len() <= HANDLER_WORD);
    code.resize(HANDLER_WORD, A64_NOP);
    // The handler: store x0 (the signal number), return to the restorer.
    code.extend(mov32(9, DATA_VA + CAUGHT_OFFSET));
    code.push(str_imm(0, 9, 0));
    code.push(A64_RET);
    code.resize(RESTORER_WORD, A64_NOP);
    code.push(movz(8, NR_RT_SIGRETURN, 0));
    code.push(A64_SVC_0);
    let (run, _) = run(
        &build_elf(&code, &[(SIGACTION_OFFSET, &action)]),
        "/caught-sigusr1",
        None,
    );
    let served = sample_el1_served(&run.engine);
    println!(
        "caught SIGUSR1: exit={} census={:?} served={served:?} counted_enosys={:?}",
        run.exit_code, run.reply_census, run.counted_enosys
    );
    assert_eq!(
        run.counted_enosys,
        Vec::new(),
        "the handler is accepted, not refused"
    );
    assert_eq!(
        run.exit_code, 0,
        "the handler ran with SIGUSR1 and kill and rt_sigaction returned 0"
    );
    for nr in [NR_RT_SIGACTION, NR_KILL, NR_RT_SIGRETURN] {
        assert!(
            served
                .iter()
                .any(|&(served_nr, _, count)| served_nr == u64::from(nr) && count == 1),
            "syscall {nr} is served once in the ring: {served:?}"
        );
    }
}
