//! Signed proof that a thread the in-guest scheduler (EL1) holds parked in a
//! private futex wait gets its exact registers into the resulting core --
//! attributed to the exact thread by tid AND by a distinctive value pinned
//! in a callee-saved register at the trap. This is the live proof for the
//! open obligation caa966609 closed host-side
//! ("Parked-EL1-thread registers are absent from crash snapshots",
//! docs/superpowers/plans/2026-09-26-el1-completion.md): a
//! `CrashQuorum::el1_parked_registers` read of the thread's EL1 save area,
//! instead of a silently missing `NT_PRSTATUS` note.
//!
//! The guest fixture (`fixtures/linux-aarch64-hello/src/crash_parked_thread.rs`)
//! clones one worker thread that parks forever in `FUTEX_WAIT_PRIVATE` (never
//! woken -- EL1-parked under default `CARRICK_EL1_SCHED`/`CARRICK_EL1_FUTEX`)
//! with a marker pinned in `x20` at the trap, then the main thread reports
//! the worker's tid/marker/resume-pc/stack bounds over stdout and crashes
//! with SIGSEGV. This test reads the resulting ELF core directly (the same
//! wire structs `carrick_kernel::core_dump` writes with, so it checks the
//! actual wire format, not a private guess at it) and cross-checks every
//! field against the fixture's own report.
//!
//! Run ONLY through `scripts/test-signed.sh carrick-embed crash_parked_thread`
//! after `scripts/build-linux-fixtures.sh`: the test executable must carry
//! the hypervisor entitlement, and `HV_DENIED` is a failure, never a skip.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use std::time::Duration;

use carrick_embed::{ContainerBuilder, Signal};
use carrick_image::PullPolicy;
use carrick_kernel::core_dump::{self, wire};

const FIXTURE: &str = "carrick-linux-aarch64-crash-parked-thread";

/// Must match the fixture's own `REPORT_MAGIC`.
const REPORT_MAGIC: [u8; 8] = *b"PARKTID:";
/// Must match the fixture's own `MARKER`.
const MARKER: u64 = 0x5a5a_1eaf_c0de_babe;
/// The fixture pins `MARKER` in `x20` at the trap (see its comments on why
/// not `x19`: LLVM reserves it internally on this target).
const MARKER_GREG_INDEX: usize = 20;

/// Generous relative to guest boot + one crash: the thing under test is
/// register attribution, not speed.
const TEST_BOUND: Duration = Duration::from_secs(120);

/// The fixture's self-report: everything dynamic (tid, resume pc, stack
/// range) that the crash itself could not hand the host any other way.
struct Report {
    tid: u64,
    marker: u64,
    resume_pc: u64,
    stack_lo: u64,
    stack_hi: u64,
}

fn parse_report(stdout: &[u8]) -> Report {
    let at = stdout
        .windows(REPORT_MAGIC.len())
        .position(|window| window == REPORT_MAGIC)
        .unwrap_or_else(|| {
            panic!(
                "fixture report magic {REPORT_MAGIC:?} not found in stdout: {:?}",
                String::from_utf8_lossy(stdout)
            )
        });
    let body = &stdout[at + REPORT_MAGIC.len()..];
    assert!(
        body.len() >= 40,
        "truncated report: {} bytes after magic, need 40",
        body.len()
    );
    let word = |offset: usize| {
        core_dump::read_u64(body, offset)
            .unwrap_or_else(|| panic!("report word at offset {offset} out of bounds"))
    };
    Report {
        tid: word(0),
        marker: word(8),
        resume_pc: word(16),
        stack_lo: word(24),
        stack_hi: word(32),
    }
}

/// One `NT_PRSTATUS` note's identity and register file, read directly off
/// the wire (byte offsets from `core::mem::offset_of!` on the exact structs
/// `carrick_kernel::core_dump` writes with).
struct PrStatus {
    pr_pid: i32,
    /// x0..x30 (31), sp_el0, resume pc, resume pstate -- `AARCH64_GREGS` (34)
    /// entries, the same layout `ThreadRegisters::gregs` writes.
    pr_reg: [u64; core_dump::AARCH64_GREGS],
}

fn align_up(value: usize, align: usize) -> usize {
    value.div_ceil(align) * align
}

/// Walk the core's ELF header and program headers to find `PT_NOTE`, then
/// every `NT_PRSTATUS` note inside it. Every offset read is bounds-checked
/// (`core_dump::read_u32`/`read_u64`), so a malformed core fails an
/// `unwrap_or_else` with a clear message rather than reading out of bounds.
fn prstatus_notes(core: &[u8]) -> Vec<PrStatus> {
    let ident = core.get(0..4).expect("core shorter than an ELF ident");
    assert_eq!(ident, &[0x7f, b'E', b'L', b'F'], "not an ELF file");
    let e_type =
        core_dump::read_u16(core, core::mem::offset_of!(wire::Elf64Ehdr, e_type)).expect("e_type");
    assert_eq!(e_type, core_dump::ET_CORE, "not a core file (e_type)");
    let e_machine = core_dump::read_u16(core, core::mem::offset_of!(wire::Elf64Ehdr, e_machine))
        .expect("e_machine");
    assert_eq!(e_machine, core_dump::EM_AARCH64, "not an aarch64 core");

    let e_phoff = core_dump::read_u64(core, core::mem::offset_of!(wire::Elf64Ehdr, e_phoff))
        .expect("e_phoff");
    let e_phentsize =
        core_dump::read_u16(core, core::mem::offset_of!(wire::Elf64Ehdr, e_phentsize))
            .expect("e_phentsize");
    let e_phnum = core_dump::read_u16(core, core::mem::offset_of!(wire::Elf64Ehdr, e_phnum))
        .expect("e_phnum");
    assert_ne!(
        e_phnum,
        core_dump::PN_XNUM,
        "PN_XNUM overflow unexpected for a 2-thread core"
    );

    let mut notes = Vec::new();
    for index in 0..u64::from(e_phnum) {
        let phdr_at = e_phoff as usize + (index * u64::from(e_phentsize)) as usize;
        let p_type = core_dump::read_u32(
            core,
            phdr_at + core::mem::offset_of!(wire::Elf64Phdr, p_type),
        )
        .expect("p_type");
        if p_type != core_dump::PT_NOTE {
            continue;
        }
        let p_offset = core_dump::read_u64(
            core,
            phdr_at + core::mem::offset_of!(wire::Elf64Phdr, p_offset),
        )
        .expect("p_offset");
        let p_filesz = core_dump::read_u64(
            core,
            phdr_at + core::mem::offset_of!(wire::Elf64Phdr, p_filesz),
        )
        .expect("p_filesz");
        let start = p_offset as usize;
        let end = start + p_filesz as usize;
        let mut cursor = start;
        while cursor + core::mem::size_of::<wire::NoteHeader>() <= end {
            let n_namesz = core_dump::read_u32(
                core,
                cursor + core::mem::offset_of!(wire::NoteHeader, n_namesz),
            )
            .expect("n_namesz");
            let n_descsz = core_dump::read_u32(
                core,
                cursor + core::mem::offset_of!(wire::NoteHeader, n_descsz),
            )
            .expect("n_descsz");
            let n_type = core_dump::read_u32(
                core,
                cursor + core::mem::offset_of!(wire::NoteHeader, n_type),
            )
            .expect("n_type");
            cursor += core::mem::size_of::<wire::NoteHeader>();
            cursor += align_up(n_namesz as usize, core_dump::NOTE_ALIGN);
            let desc_start = cursor;
            if n_type == core_dump::NT_PRSTATUS {
                assert_eq!(
                    n_descsz as usize,
                    core::mem::size_of::<wire::ElfPrStatus>(),
                    "NT_PRSTATUS descriptor size does not match wire::ElfPrStatus"
                );
                let pr_pid = core_dump::read_u32(
                    core,
                    desc_start + core::mem::offset_of!(wire::ElfPrStatus, pr_pid),
                )
                .expect("pr_pid") as i32;
                let mut pr_reg = [0u64; core_dump::AARCH64_GREGS];
                let reg_base = desc_start + core::mem::offset_of!(wire::ElfPrStatus, pr_reg);
                for (register_index, register) in pr_reg.iter_mut().enumerate() {
                    *register = core_dump::read_u64(core, reg_base + register_index * 8)
                        .unwrap_or_else(|| panic!("pr_reg[{register_index}] out of bounds"));
                }
                notes.push(PrStatus { pr_pid, pr_reg });
            }
            cursor = desc_start + align_up(n_descsz as usize, core_dump::NOTE_ALIGN);
        }
    }
    notes
}

#[test]
fn crash_core_attributes_the_el1_parked_sibling_registers() {
    let _guest = common::guest_lock();
    let watchdog = common::Watchdog::start(TEST_BOUND);

    let fixture = common::repo_root().join(format!(
        "fixtures/linux-aarch64-hello/target/aarch64-unknown-linux-musl/release/{FIXTURE}"
    ));
    std::fs::metadata(&fixture).unwrap_or_else(|error| {
        panic!(
            "stat {}: {error}; run scripts/build-linux-fixtures.sh first",
            fixture.display()
        )
    });
    let fixture_dir = fixture
        .parent()
        .expect("fixture directory")
        .to_string_lossy()
        .into_owned();

    let core_dir = tempfile::tempdir().expect("core directory");
    let core_host_path = core_dir.path().join("core");

    let result = common::run_or_fail(
        ContainerBuilder::from_image(common::SMOKE_IMAGE)
            .pull_policy(PullPolicy::Missing)
            .mount_readonly(fixture_dir, "/p")
            .mount(core_dir.path().to_string_lossy().into_owned(), "/coredir")
            .workdir("/coredir")
            .command([format!("/p/{FIXTURE}")])
            .run_blocking(),
    );

    watchdog.disarm();

    assert_eq!(
        result.signal,
        Some(Signal(11)),
        "expected SIGSEGV (11); exit_code={} stdout={:?} stderr={:?}",
        result.exit_code,
        result.stdout_utf8(),
        String::from_utf8_lossy(&result.stderr)
    );

    let report = parse_report(&result.stdout);
    assert_eq!(
        report.marker, MARKER,
        "fixture's own report disagrees with its compiled-in marker: {:#x} vs {MARKER:#x}",
        report.marker
    );

    let core_bytes = std::fs::read(&core_host_path).unwrap_or_else(|error| {
        panic!(
            "read {}: {error}; SIGSEGV must publish a core (RLIMIT_CORE defaults to \
             unlimited: RlimitSet::carrick_defaults leaves LinuxResource::Core unlisted)",
            core_host_path.display()
        )
    });

    let threads = prstatus_notes(&core_bytes);
    assert!(
        threads.len() >= 2,
        "expected at least 2 NT_PRSTATUS notes (the fatal thread and the parked \
         sibling), got {}: tids {:?}",
        threads.len(),
        threads
            .iter()
            .map(|thread| thread.pr_pid)
            .collect::<Vec<_>>()
    );

    let marked: Vec<&PrStatus> = threads
        .iter()
        .filter(|thread| thread.pr_reg[MARKER_GREG_INDEX] == MARKER)
        .collect();
    assert_eq!(
        marked.len(),
        1,
        "expected exactly one thread's x{MARKER_GREG_INDEX} to carry the marker, \
         got {}: tids {:?}",
        marked.len(),
        threads
            .iter()
            .map(|thread| thread.pr_pid)
            .collect::<Vec<_>>()
    );
    let parked = marked[0];

    assert_eq!(
        parked.pr_pid as u64, report.tid,
        "the marked thread's tid must match the tid the fixture itself reported"
    );

    // `ThreadRegisters::gregs` layout (see core_dump.rs): x0..x30 (31), then
    // sp_el0, then the resume pc/pstate pair -- indices 31 and 32.
    let sp = parked.pr_reg[31];
    let pc = parked.pr_reg[32];
    assert_eq!(
        pc, report.resume_pc,
        "parked thread's saved pc must be exactly the instruction after its \
         futex svc (pc={pc:#x} resume_pc={:#x})",
        report.resume_pc
    );
    assert!(
        sp >= report.stack_lo && sp < report.stack_hi,
        "parked thread's sp {sp:#x} is not inside its own worker stack \
         [{:#x}, {:#x})",
        report.stack_lo,
        report.stack_hi
    );

    // The fatal (main) thread's own note must not itself carry the marker:
    // it never touched x20 the parked thread's way, so this also proves the
    // match above is not a false positive from an all-zero/garbage register.
    let fatal_tids: Vec<i32> = threads
        .iter()
        .filter(|thread| thread.pr_pid as u64 != report.tid)
        .map(|thread| thread.pr_pid)
        .collect();
    assert!(
        !fatal_tids.is_empty(),
        "expected at least one thread distinct from the parked sibling's tid"
    );
}
