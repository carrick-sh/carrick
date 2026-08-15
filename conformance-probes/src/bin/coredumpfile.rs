//! Differential proof for the complete HVPatch crash-to-core contract.
//!
//! The parent forks and the child execs this probe again, creates a named
//! file-backed mapping and a recognizable anonymous-memory sample, starts two
//! threads with distinct AArch64 GPR/SIMD values, then faults at one exact
//! store instruction. The parent parses the produced Linux ELF core itself.
//! Every reported observation is therefore line-exact under Carrick and the
//! native arm64 Docker oracle; no Carrick validator is part of the oracle.

use std::sync::atomic::{AtomicI32, AtomicUsize, Ordering};

use conformance_probes::report;

const CHILD_ARG: &str = "--core-crash-child";
const LIMIT_ZERO_ARG: &str = "--core-limit-zero";
const LIMIT_SMALL_ARG: &str = "--core-limit-small";
const EXPECT_NO_CORE_ARG: &str = "--expect-no-core";
const ARCHIVE_CORE_ARG_PREFIX: &str = "--archive-core=";
const PROBE_PATH: &str = "/tmp/p";
const CORE_DIR: &str = "/tmp/coredumpfile";
const MAPPED_PATH: &str = "/tmp/coredumpfile/mapped.bin";

const MAIN_MARKER: u64 = 0x4d41_494e_434f_5245;
const RUNNING_MARKER: u64 = 0x5255_4e4e_494e_4731;
const BLOCKED_MARKER: u64 = 0x424c_4f43_4b45_4432;
const MAIN_TLS: u64 = 0x1111_2222_3333_4444;
const RUNNING_TLS: u64 = 0x5555_6666_7777_8888;
const BLOCKED_TLS: u64 = 0x9999_aaaa_bbbb_cccc;
const MAIN_FPCR: u64 = 0x00c0_0000;
const RUNNING_FPCR: u64 = 0x0040_0000;
const BLOCKED_FPCR: u64 = 0x0080_0000;
const MAIN_FPSR: u64 = 1;
const RUNNING_FPSR: u64 = 2;
const BLOCKED_FPSR: u64 = 4;
const FAULT_INSTRUCTION: u32 = 0xf900_0013; // `str x19, [x0]`
const PRIVATE_ADDR: usize = 0x67_0000_0000;
const SHARED_ADDR: usize = 0x67_0010_0000;
const FILE_ADDR: usize = 0x67_0020_0000;
const ANON_EXEC_ADDR: usize = 0x67_0030_0000;
const SAMPLE_LEN: usize = 32;
const PAGE: usize = 4096;

const PT_LOAD: u32 = 1;
const PT_NOTE: u32 = 4;
const NT_PRSTATUS: u32 = 1;
const NT_PRPSINFO: u32 = 3;
const NT_AUXV: u32 = 6;
const NT_SIGINFO: u32 = 0x5349_4749;
const NT_FILE: u32 = 0x4649_4c45;
const NT_FPREGSET: u32 = 2;
const NT_ARM_TLS: u32 = 0x401;

static READY: AtomicUsize = AtomicUsize::new(0);
static BLOCK_READ_FD: AtomicI32 = AtomicI32::new(-1);
static mut BLOCK_BYTE: u8 = 0;

#[derive(Default)]
struct ThreadObservation {
    tid: i32,
    x19: u64,
    sp: u64,
    pc: u64,
    v0: Option<[u64; 2]>,
    tls: Option<u64>,
    fpsr: Option<u32>,
    fpcr: Option<u32>,
}

struct LoadObservation {
    vaddr: u64,
    offset: usize,
    filesz: usize,
    memsz: u64,
}

struct FileObservation {
    start: u64,
    end: u64,
    file_page_offset: u64,
    path: String,
}

#[derive(Default)]
struct CoreObservations {
    valid_elf_aarch64: bool,
    process_pid: i32,
    process_ppid: i32,
    process_pgrp: i32,
    process_session: i32,
    signal: i32,
    signal_code: i32,
    signal_addr: u64,
    auxv_entries: usize,
    file_mappings: Vec<FileObservation>,
    fault_instruction: bool,
    threads: Vec<ThreadObservation>,
    loads: Vec<LoadObservation>,
}

fn read_u16(bytes: &[u8], offset: usize) -> Option<u16> {
    Some(u16::from_le_bytes(
        bytes.get(offset..offset + 2)?.try_into().ok()?,
    ))
}

fn read_u32(bytes: &[u8], offset: usize) -> Option<u32> {
    Some(u32::from_le_bytes(
        bytes.get(offset..offset + 4)?.try_into().ok()?,
    ))
}

fn read_i32(bytes: &[u8], offset: usize) -> Option<i32> {
    Some(i32::from_le_bytes(
        bytes.get(offset..offset + 4)?.try_into().ok()?,
    ))
}

fn read_u64(bytes: &[u8], offset: usize) -> Option<u64> {
    Some(u64::from_le_bytes(
        bytes.get(offset..offset + 8)?.try_into().ok()?,
    ))
}

fn align4(value: usize) -> Option<usize> {
    value.checked_add(3).map(|value| value & !3)
}

fn memory_marker(pid: i32, tag: u8) -> [u8; SAMPLE_LEN] {
    let seed = (pid as u64) ^ 0x9e37_79b9_7f4a_7c15 ^ (u64::from(tag) << 48);
    let mut marker = [0_u8; SAMPLE_LEN];
    for (index, byte) in marker.iter_mut().enumerate() {
        *byte = seed
            .rotate_left(u32::try_from(index).unwrap_or(0))
            .wrapping_add((index as u64).wrapping_mul(37)) as u8;
    }
    marker
}

fn find_core_path(pattern: &str) -> Option<std::path::PathBuf> {
    let exact = std::path::Path::new(CORE_DIR).join(pattern);
    if exact.is_file() {
        return Some(exact);
    }
    std::fs::read_dir(CORE_DIR)
        .ok()?
        .flatten()
        .find_map(|entry| {
            entry
                .file_name()
                .to_string_lossy()
                .starts_with(&format!("{pattern}."))
                .then_some(entry.path())
        })
}

fn parse_note_segment(bytes: &[u8], observations: &mut CoreObservations) -> Option<()> {
    let mut cursor = 0_usize;
    let mut current_thread = None;
    while cursor.checked_add(12)? <= bytes.len() {
        let name_size = usize::try_from(read_u32(bytes, cursor)?).ok()?;
        let desc_size = usize::try_from(read_u32(bytes, cursor + 4)?).ok()?;
        let note_type = read_u32(bytes, cursor + 8)?;
        let name_at = cursor.checked_add(12)?;
        let desc_at = name_at.checked_add(align4(name_size)?)?;
        let next = desc_at.checked_add(align4(desc_size)?)?;
        let desc = bytes.get(desc_at..desc_at.checked_add(desc_size)?)?;
        match note_type {
            NT_PRSTATUS if desc.len() == 0x188 => {
                observations.threads.push(ThreadObservation {
                    tid: read_i32(desc, 32)?,
                    x19: read_u64(desc, 112 + 19 * 8)?,
                    sp: read_u64(desc, 112 + 31 * 8)?,
                    pc: read_u64(desc, 112 + 32 * 8)?,
                    ..ThreadObservation::default()
                });
                current_thread = Some(observations.threads.len() - 1);
            }
            NT_PRPSINFO if desc.len() == 0x88 => {
                observations.process_pid = read_i32(desc, 24)?;
                observations.process_ppid = read_i32(desc, 28)?;
                observations.process_pgrp = read_i32(desc, 32)?;
                observations.process_session = read_i32(desc, 36)?;
            }
            NT_SIGINFO if desc.len() == 0x80 => {
                observations.signal = read_i32(desc, 0)?;
                observations.signal_code = read_i32(desc, 8)?;
                observations.signal_addr = read_u64(desc, 16)?;
            }
            NT_FILE => {
                let count = usize::try_from(read_u64(desc, 0)?).ok()?;
                let paths_at = 16_usize.checked_add(count.checked_mul(24)?)?;
                let mut paths = desc.get(paths_at..)?;
                for index in 0..count {
                    let end = paths.iter().position(|byte| *byte == 0)?;
                    let path = std::str::from_utf8(paths.get(..end)?).ok()?.to_owned();
                    paths = paths.get(end + 1..)?;
                    let triple = 16_usize.checked_add(index.checked_mul(24)?)?;
                    observations.file_mappings.push(FileObservation {
                        start: read_u64(desc, triple)?,
                        end: read_u64(desc, triple + 8)?,
                        file_page_offset: read_u64(desc, triple + 16)?,
                        path,
                    });
                }
            }
            NT_AUXV => {
                observations.auxv_entries = desc
                    .chunks_exact(16)
                    .take_while(|entry| read_u64(entry, 0) != Some(0))
                    .count();
            }
            NT_FPREGSET if desc.len() == 0x210 => {
                if let Some(index) = current_thread {
                    observations.threads[index].v0 = Some([read_u64(desc, 0)?, read_u64(desc, 8)?]);
                    observations.threads[index].fpsr = Some(read_u32(desc, 512)?);
                    observations.threads[index].fpcr = Some(read_u32(desc, 516)?);
                }
            }
            NT_ARM_TLS if desc.len() == 0x10 => {
                if let Some(index) = current_thread {
                    observations.threads[index].tls = Some(read_u64(desc, 0)?);
                }
            }
            _ => {}
        }
        cursor = next;
    }
    Some(())
}

fn instruction_at_vaddr(elf: &[u8], address: u64) -> Option<u32> {
    let phoff = usize::try_from(read_u64(elf, 32)?).ok()?;
    let phentsize = usize::from(read_u16(elf, 54)?);
    let phnum = usize::from(read_u16(elf, 56)?);
    for index in 0..phnum {
        let header = phoff.checked_add(index.checked_mul(phentsize)?)?;
        if read_u32(elf, header)? != PT_LOAD {
            continue;
        }
        let offset = usize::try_from(read_u64(elf, header + 8)?).ok()?;
        let vaddr = read_u64(elf, header + 16)?;
        let filesz = usize::try_from(read_u64(elf, header + 32)?).ok()?;
        let relative = usize::try_from(address.checked_sub(vaddr)?).ok()?;
        if relative.checked_add(4).is_some_and(|end| end <= filesz) {
            return read_u32(elf, offset.checked_add(relative)?);
        }
    }
    None
}

fn parse_core(bytes: &[u8], executable: &[u8]) -> Option<CoreObservations> {
    let mut observations = CoreObservations {
        valid_elf_aarch64: bytes.get(..4) == Some(b"\x7fELF")
            && bytes.get(4) == Some(&2)
            && read_u16(bytes, 16)? == 4
            && read_u16(bytes, 18)? == 183,
        ..CoreObservations::default()
    };
    let phoff = usize::try_from(read_u64(bytes, 32)?).ok()?;
    let phentsize = usize::from(read_u16(bytes, 54)?);
    let phnum = usize::from(read_u16(bytes, 56)?);
    for index in 0..phnum {
        let header = phoff.checked_add(index.checked_mul(phentsize)?)?;
        let kind = read_u32(bytes, header)?;
        let offset = usize::try_from(read_u64(bytes, header + 8)?).ok()?;
        let filesz = usize::try_from(read_u64(bytes, header + 32)?).ok()?;
        let payload = bytes.get(offset..offset.checked_add(filesz)?)?;
        match kind {
            PT_NOTE => parse_note_segment(payload, &mut observations)?,
            PT_LOAD => {
                observations.loads.push(LoadObservation {
                    vaddr: read_u64(bytes, header + 16)?,
                    offset,
                    filesz,
                    memsz: read_u64(bytes, header + 40)?,
                });
            }
            _ => {}
        }
    }
    if let Some(crash) = observations.threads.first() {
        observations.fault_instruction =
            instruction_at_vaddr(executable, crash.pc) == Some(FAULT_INSTRUCTION);
    }
    Some(observations)
}

fn core_bytes_at<'a>(
    core: &'a [u8],
    loads: &[LoadObservation],
    address: u64,
    length: usize,
) -> Option<&'a [u8]> {
    for load in loads {
        let Some(relative) = address.checked_sub(load.vaddr) else {
            continue;
        };
        let Ok(relative) = usize::try_from(relative) else {
            continue;
        };
        if relative
            .checked_add(length)
            .is_some_and(|end| end <= load.filesz)
        {
            let at = load.offset.checked_add(relative)?;
            return core.get(at..at.checked_add(length)?);
        }
    }
    None
}

#[cfg(target_arch = "aarch64")]
extern "C" fn running_worker(arg: *mut libc::c_void) -> *mut libc::c_void {
    let marker = arg as usize as u64;
    READY.fetch_add(1, Ordering::SeqCst);
    unsafe {
        core::arch::asm!(
            "mov x19, {marker}",
            "dup v0.2d, x19",
            "msr tpidr_el0, {tls}",
            "msr fpcr, {fpcr}",
            "msr fpsr, {fpsr}",
            "2:",
            "yield",
            "b 2b",
            marker = in(reg) marker,
            tls = in(reg) RUNNING_TLS,
            fpcr = in(reg) RUNNING_FPCR,
            fpsr = in(reg) RUNNING_FPSR,
            options(noreturn, nostack)
        );
    }
}

#[cfg(target_arch = "aarch64")]
extern "C" fn blocked_worker(arg: *mut libc::c_void) -> *mut libc::c_void {
    let marker = arg as usize as u64;
    let fd = u64::try_from(BLOCK_READ_FD.load(Ordering::SeqCst)).unwrap_or(u64::MAX);
    let buffer = std::ptr::addr_of_mut!(BLOCK_BYTE) as u64;
    READY.fetch_add(1, Ordering::SeqCst);
    unsafe {
        core::arch::asm!(
            "mov x19, {marker}",
            "dup v0.2d, x19",
            "msr tpidr_el0, {tls}",
            "msr fpcr, {fpcr}",
            "msr fpsr, {fpsr}",
            "mov x0, {fd}",
            "mov x1, {buffer}",
            "mov x2, #1",
            "mov x8, #63",
            "svc #0",
            "3:",
            "b 3b",
            marker = in(reg) marker,
            tls = in(reg) BLOCKED_TLS,
            fpcr = in(reg) BLOCKED_FPCR,
            fpsr = in(reg) BLOCKED_FPSR,
            fd = in(reg) fd,
            buffer = in(reg) buffer,
            options(noreturn, nostack)
        );
    }
}

unsafe fn fixed_mapping(address: usize, flags: i32, fd: i32, offset: libc::off_t) -> *mut u8 {
    libc::mmap(
        address as *mut libc::c_void,
        PAGE,
        libc::PROT_READ | libc::PROT_WRITE,
        flags | libc::MAP_FIXED_NOREPLACE,
        fd,
        offset,
    )
    .cast()
}

#[cfg(target_arch = "aarch64")]
unsafe fn crash_child() -> ! {
    let private = fixed_mapping(PRIVATE_ADDR, libc::MAP_PRIVATE | libc::MAP_ANONYMOUS, -1, 0);
    let shared = fixed_mapping(SHARED_ADDR, libc::MAP_SHARED | libc::MAP_ANONYMOUS, -1, 0);
    let anon_exec = fixed_mapping(
        ANON_EXEC_ADDR,
        libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
        -1,
        0,
    );
    let path = std::ffi::CString::new(MAPPED_PATH).unwrap_or_default();
    let fd = libc::open(
        path.as_ptr(),
        libc::O_CREAT | libc::O_TRUNC | libc::O_RDWR,
        0o644,
    );
    if fd >= 0 && libc::ftruncate(fd, (2 * PAGE) as libc::off_t) != 0 {
        libc::_exit(121);
    }
    let file = fixed_mapping(FILE_ADDR, libc::MAP_PRIVATE, fd, PAGE as libc::off_t);
    if private == libc::MAP_FAILED.cast()
        || shared == libc::MAP_FAILED.cast()
        || file == libc::MAP_FAILED.cast()
        || anon_exec == libc::MAP_FAILED.cast()
    {
        libc::_exit(122);
    }
    std::ptr::write_unaligned(anon_exec.cast::<u32>(), 0xd65f_03c0); // ret
    if libc::mprotect(anon_exec.cast(), PAGE, libc::PROT_READ | libc::PROT_EXEC) != 0 {
        libc::_exit(128);
    }
    let crash_pid = libc::getpid();
    std::ptr::copy_nonoverlapping(
        memory_marker(crash_pid, b'S').as_ptr(),
        shared.add(128),
        SAMPLE_LEN,
    );

    // Fork after all mapping classes contain recognizable bytes. The helper
    // exits; this task reaps it, then writes both private mappings and crashes.
    // That forces the private-anonymous and private-file Task-4 COW paths
    // without depending on subreaper semantics.
    let nested = libc::fork();
    if nested == 0 {
        libc::_exit(0);
    }
    if nested < 0 {
        libc::_exit(123);
    }
    let mut nested_status = 0;
    if libc::waitpid(nested, &mut nested_status, 0) != nested
        || !libc::WIFEXITED(nested_status)
        || libc::WEXITSTATUS(nested_status) != 0
    {
        libc::_exit(127);
    }

    std::ptr::copy_nonoverlapping(memory_marker(crash_pid, b'P').as_ptr(), private, SAMPLE_LEN);
    std::ptr::copy_nonoverlapping(memory_marker(crash_pid, b'F').as_ptr(), file, SAMPLE_LEN);

    let stack_marker = memory_marker(crash_pid, b'K');
    let heap_marker = Box::new(memory_marker(crash_pid, b'H'));
    let stack_address = stack_marker.as_ptr() as u64;
    let heap_address = heap_marker.as_ptr() as u64;
    std::ptr::write_unaligned(shared.cast::<u64>(), 0x434f_5245_4d41_5053);
    std::ptr::write_unaligned(shared.add(8).cast::<u64>(), stack_address);
    std::ptr::write_unaligned(shared.add(16).cast::<u64>(), heap_address);
    std::hint::black_box(&stack_marker);
    let _ = Box::leak(heap_marker);

    let mut pipe = [-1; 2];
    if libc::pipe(pipe.as_mut_ptr()) != 0 {
        libc::_exit(124);
    }
    BLOCK_READ_FD.store(pipe[0], Ordering::SeqCst);

    let mut running: libc::pthread_t = std::mem::zeroed();
    let mut blocked: libc::pthread_t = std::mem::zeroed();
    let _ = libc::pthread_create(
        &mut running,
        std::ptr::null(),
        running_worker,
        RUNNING_MARKER as usize as *mut libc::c_void,
    );
    let _ = libc::pthread_create(
        &mut blocked,
        std::ptr::null(),
        blocked_worker,
        BLOCKED_MARKER as usize as *mut libc::c_void,
    );
    for _ in 0..100_000 {
        if READY.load(Ordering::SeqCst) == 2 {
            break;
        }
        libc::sched_yield();
    }

    core::arch::asm!(
        "mov x19, {marker}",
        "dup v0.2d, x19",
        "msr tpidr_el0, {tls}",
        "msr fpcr, {fpcr}",
        "msr fpsr, {fpsr}",
        "mov x0, xzr",
        "str x19, [x0]",
        marker = in(reg) MAIN_MARKER,
        tls = in(reg) MAIN_TLS,
        fpcr = in(reg) MAIN_FPCR,
        fpsr = in(reg) MAIN_FPSR,
        options(noreturn, nostack)
    );
}

#[cfg(not(target_arch = "aarch64"))]
unsafe fn crash_child() -> ! {
    libc::_exit(125)
}

fn core_pattern() -> String {
    std::fs::read_to_string("/proc/sys/kernel/core_pattern")
        .unwrap_or_default()
        .trim()
        .to_string()
}

fn pattern_is_plain_file(pattern: &str) -> bool {
    !pattern.is_empty()
        && !pattern.starts_with('|')
        && !pattern.starts_with('/')
        && !pattern.contains('%')
}

fn thread_registers_match(
    thread: &ThreadObservation,
    marker: u64,
    tls: u64,
    fpsr: u32,
    fpcr: u32,
) -> bool {
    thread.x19 == marker
        && thread.v0 == Some([marker, marker])
        && thread.tls == Some(tls)
        && thread.fpsr == Some(fpsr)
        && thread.fpcr == Some(fpcr)
        && thread.sp != 0
}

fn main() {
    let arguments = std::env::args().collect::<Vec<_>>();
    if arguments.iter().any(|arg| arg == CHILD_ARG) {
        unsafe { crash_child() }
    }
    let requested_limit = if arguments.iter().any(|arg| arg == LIMIT_ZERO_ARG) {
        0
    } else if arguments.iter().any(|arg| arg == LIMIT_SMALL_ARG) {
        4096
    } else {
        64 * 1024 * 1024
    };
    let expect_no_core = arguments.iter().any(|arg| arg == EXPECT_NO_CORE_ARG);
    let archive_core = arguments
        .iter()
        .find_map(|arg| arg.strip_prefix(ARCHIVE_CORE_ARG_PREFIX));

    unsafe {
        let _ = std::fs::remove_dir_all(CORE_DIR);
        let made_dir = std::fs::create_dir_all(CORE_DIR).is_ok();
        let chdir_ok = std::env::set_current_dir(CORE_DIR).is_ok();
        let limit = libc::rlimit {
            rlim_cur: requested_limit,
            rlim_max: requested_limit,
        };
        let raised = libc::setrlimit(libc::RLIMIT_CORE, &limit) == 0;
        let pattern = core_pattern();
        let plain = pattern_is_plain_file(&pattern);
        let parent = libc::getpid();
        let child = libc::fork();
        if child == 0 {
            let path = std::ffi::CString::new(PROBE_PATH).unwrap_or_default();
            let arg0 = std::ffi::CString::new("coredumpfile").unwrap_or_default();
            let arg1 = std::ffi::CString::new(CHILD_ARG).unwrap_or_default();
            let argv = [arg0.as_ptr(), arg1.as_ptr(), std::ptr::null()];
            libc::execv(path.as_ptr(), argv.as_ptr());
            libc::_exit(126);
        }
        let crash_pid = child;
        let mut crash_status = 0;
        let reaped = child > 0 && libc::waitpid(child, &mut crash_status, 0) == child;
        let signaled = libc::WIFSIGNALED(crash_status);
        let by_sigsegv = signaled && libc::WTERMSIG(crash_status) == libc::SIGSEGV;
        let core_bit = signaled && (crash_status & 0x80) != 0;
        let core_path = find_core_path(if plain { &pattern } else { "core" });
        let core_bytes = core_path
            .as_ref()
            .and_then(|path| std::fs::read(path).ok())
            .unwrap_or_default();
        if let Some(archive_path) = archive_core {
            if std::fs::write(archive_path, &core_bytes).is_err() {
                std::process::exit(129);
            }
        }
        if requested_limit != 64 * 1024 * 1024 || expect_no_core {
            let no_temporary = std::fs::read_dir(CORE_DIR).is_ok_and(|entries| {
                entries.flatten().all(|entry| {
                    !entry
                        .file_name()
                        .to_string_lossy()
                        .contains(".carrick-tmp-")
                })
            });
            if expect_no_core {
                report!(
                    failpoint_mode = true,
                    requested_limit_applied = raised,
                    reaped = reaped,
                    child_died_of_sigsegv = by_sigsegv,
                    wcoredump_clear = !core_bit,
                    no_published_core = core_bytes.is_empty(),
                    no_temporary_core = no_temporary,
                );
            } else {
                report!(
                    limit_zero_mode = requested_limit == 0,
                    limit_too_small_mode = requested_limit == 4096,
                    requested_limit_applied = raised,
                    reaped = reaped,
                    child_died_of_sigsegv = by_sigsegv,
                    wcoredump_clear = !core_bit,
                    no_published_core = core_bytes.is_empty(),
                    no_temporary_core = no_temporary,
                );
            }
            return;
        }
        let executable = std::fs::read(PROBE_PATH).unwrap_or_default();
        let parsed = parse_core(&core_bytes, &executable).unwrap_or_default();
        let main_thread = parsed.threads.iter().find(|thread| {
            thread_registers_match(
                thread,
                MAIN_MARKER,
                MAIN_TLS,
                MAIN_FPSR as u32,
                MAIN_FPCR as u32,
            )
        });
        let running_thread = parsed.threads.iter().find(|thread| {
            thread_registers_match(
                thread,
                RUNNING_MARKER,
                RUNNING_TLS,
                RUNNING_FPSR as u32,
                RUNNING_FPCR as u32,
            )
        });
        let blocked_thread = parsed.threads.iter().find(|thread| {
            thread_registers_match(
                thread,
                BLOCKED_MARKER,
                BLOCKED_TLS,
                BLOCKED_FPSR as u32,
                BLOCKED_FPCR as u32,
            )
        });
        let boot_mapping_path_exact = parsed
            .file_mappings
            .iter()
            .any(|mapping| mapping.path == PROBE_PATH);
        let nonzero_offset_file_mapping_exact = parsed.file_mappings.iter().any(|mapping| {
            mapping.start == FILE_ADDR as u64
                && mapping.end == (FILE_ADDR + PAGE) as u64
                && mapping.file_page_offset == 1
                && mapping.path == MAPPED_PATH
        });
        let anonymous_exec_not_file_labeled = parsed.file_mappings.iter().all(|mapping| {
            ANON_EXEC_ADDR as u64 >= mapping.end || (ANON_EXEC_ADDR + PAGE) as u64 <= mapping.start
        });
        let nt_file_symbolizer_truth = parsed.threads.first().is_some_and(|crash| {
            parsed.file_mappings.iter().any(|mapping| {
                if mapping.path != PROBE_PATH || crash.pc < mapping.start || crash.pc >= mapping.end
                {
                    return false;
                }
                mapping
                    .file_page_offset
                    .checked_mul(PAGE as u64)
                    .and_then(|file_base| file_base.checked_add(crash.pc - mapping.start))
                    .and_then(|file_offset| usize::try_from(file_offset).ok())
                    .and_then(|file_offset| read_u32(&executable, file_offset))
                    == Some(FAULT_INSTRUCTION)
            })
        });
        let pt_load_vmas_nonoverlapping = {
            let mut ranges = parsed
                .loads
                .iter()
                .filter(|load| load.memsz != 0)
                .map(|load| load.vaddr.checked_add(load.memsz).map(|end| (load.vaddr, end)))
                .collect::<Option<Vec<_>>>();
            ranges.as_mut().is_some_and(|ranges| {
                ranges.sort_unstable();
                ranges.windows(2).all(|pair| pair[0].1 <= pair[1].0)
            })
        };
        let stack_pointers_distinct = parsed.threads.len() == 3
            && parsed
                .threads
                .iter()
                .all(|thread| core_bytes_at(&core_bytes, &parsed.loads, thread.sp, 1).is_some())
            && parsed.threads.iter().enumerate().all(|(index, thread)| {
                parsed.threads[..index]
                    .iter()
                    .all(|prior| prior.sp != thread.sp)
            });
        let instruction_at_pc = |thread: &ThreadObservation| {
            core_bytes_at(&core_bytes, &parsed.loads, thread.pc, 4)
                .and_then(|bytes| read_u32(bytes, 0))
                .or_else(|| instruction_at_vaddr(&executable, thread.pc))
        };
        let running_pc = running_thread
            .and_then(&instruction_at_pc)
            .is_some_and(|instruction| {
                instruction == 0xd503_203f || instruction & 0xfc00_0000 == 0x1400_0000
            });
        let blocked_pc = blocked_thread
            .and_then(instruction_at_pc)
            .is_some_and(|instruction| {
                instruction == 0xd400_0001 || instruction & 0xfc00_0000 == 0x1400_0000
            });

        let private_sample =
            core_bytes_at(&core_bytes, &parsed.loads, PRIVATE_ADDR as u64, SAMPLE_LEN)
                == Some(memory_marker(crash_pid, b'P').as_slice());
        let shared_layout = core_bytes_at(&core_bytes, &parsed.loads, SHARED_ADDR as u64, 24);
        let shared_sample = core_bytes_at(
            &core_bytes,
            &parsed.loads,
            (SHARED_ADDR + 128) as u64,
            SAMPLE_LEN,
        ) == Some(memory_marker(crash_pid, b'S').as_slice());
        let file_sample = core_bytes_at(&core_bytes, &parsed.loads, FILE_ADDR as u64, SAMPLE_LEN)
            == Some(memory_marker(crash_pid, b'F').as_slice());
        let layout_valid = shared_layout.and_then(|layout| {
            (read_u64(layout, 0)? == 0x434f_5245_4d41_5053)
                .then_some((read_u64(layout, 8)?, read_u64(layout, 16)?))
        });
        let stack_sample = layout_valid.is_some_and(|(stack, _)| {
            core_bytes_at(&core_bytes, &parsed.loads, stack, SAMPLE_LEN)
                == Some(memory_marker(crash_pid, b'K').as_slice())
        });
        let heap_sample = layout_valid.is_some_and(|(_, heap)| {
            core_bytes_at(&core_bytes, &parsed.loads, heap, SAMPLE_LEN)
                == Some(memory_marker(crash_pid, b'H').as_slice())
        });

        report!(
            made_dir = made_dir,
            chdir_ok = chdir_ok,
            raised_rlimit_core = raised,
            reaped = reaped,
            child_was_signaled = signaled,
            child_exited_normally = libc::WIFEXITED(crash_status),
            child_exit_status_zero =
                libc::WIFEXITED(crash_status) && libc::WEXITSTATUS(crash_status) == 0,
            child_died_of_sigsegv = by_sigsegv,
            wcoredump_set = core_bit,
            core_pattern_is_plain_file = plain,
            core_file_exists_when_bit_set = !(plain && core_bit) || !core_bytes.is_empty(),
            core_is_elf64_aarch64 = parsed.valid_elf_aarch64,
            fork_exec_identity_exact =
                parsed.process_pid == crash_pid && parsed.process_ppid == parent,
            low_process_group_session_identity = parsed.process_pgrp > 0
                && parsed.process_pgrp < 1024
                && parsed.process_session > 0
                && parsed.process_session < 1024,
            crash_signal_code_addr_exact = parsed.signal == libc::SIGSEGV
                && parsed.signal_code == 1 // SEGV_MAPERR
                && parsed.signal_addr == 0,
            crash_pc_fault_instruction_exact = parsed.fault_instruction,
            three_threads_captured = parsed.threads.len() == 3,
            thread_ids_distinct = parsed.threads.iter().enumerate().all(|(index, thread)| {
                thread.tid > 0
                    && parsed.threads[..index]
                        .iter()
                        .all(|prior| prior.tid != thread.tid)
            }),
            thread_register_markers_exact =
                main_thread.is_some() && running_thread.is_some() && blocked_thread.is_some(),
            thread_stack_pointers_distinct = stack_pointers_distinct,
            running_and_blocked_pcs_exact = running_pc && blocked_pc,
            boot_mapping_path_exact = boot_mapping_path_exact,
            nonzero_offset_file_mapping_exact = nonzero_offset_file_mapping_exact,
            anonymous_exec_not_file_labeled = anonymous_exec_not_file_labeled,
            nt_file_symbolizer_truth = nt_file_symbolizer_truth,
            pt_load_vmas_nonoverlapping = pt_load_vmas_nonoverlapping,
            auxv_present = parsed.auxv_entries > 0,
            private_cow_sample_present = private_sample,
            shared_sample_present = shared_sample,
            stack_sample_present = stack_sample,
            heap_sample_present = heap_sample,
            file_mapping_sample_present = file_sample,
        );
    }
}
