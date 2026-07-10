//! Darwin-native execution backend.
//!
//! Same-ISA Linux ELFs are loaded into a forked host child, their `svc #0`
//! instructions are patched to synchronous `brk` traps, and those traps are
//! dispatched through the existing Linux syscall layer. OCI/container setup is
//! shared with the other runtime backends; this module owns only image loading
//! details and the native run loop. Unsupported dispatcher outcomes fail
//! explicitly rather than falling back to HVF.

use std::collections::{BTreeMap, BTreeSet};
use std::io::Read;
use std::os::fd::{FromRawFd, RawFd};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use crate::compat::{CompatReport, CompatReporter, SyscallArgs};
use crate::dispatch::{
    DispatchOutcome, GuestMemory, HostSyscallResult, MemoryError, MemoryLayout, SyscallDispatcher,
    SyscallRequest,
};
use crate::memory::{AddressSpace, AddressSpaceError, MemoryRegion};
use crate::page_profile::{
    ExecutionPlan, HostPageState, MixedPageReason, PageBacking, PagePerms, SubpageState,
    classify_host_page_state,
};
use crate::runtime::{RunResult, RuntimeError, maybe_dump_debug_state};
use carrick_guest_mem::protections::MemoryProtections;
use carrick_hal::{ForkOutcome, RawSyscall, Reg, RegAccess, SysReg, SyscallTrap, TrapError};
use goblin::elf::Elf;
use goblin::elf::header::ET_DYN;
use goblin::elf::reloc::{R_AARCH64_NONE, R_AARCH64_RELATIVE};

const SVC_0: u32 = 0xd400_0001;
const MRS_TPIDR_EL0: u32 = 0xd53b_d040;
const MSR_TPIDR_EL0: u32 = 0xd51b_d040;
const MRS_CTR_EL0: u32 = 0xd53b_0020;
const MRS_DCZID_EL0: u32 = 0xd53b_00e0;
const DC_ZVA: u32 = 0xd50b_7420;
const DC_CVAU: u32 = 0xd50b_7b20;
const IC_IVAU: u32 = 0xd50b_7520;
const SYSTEM_REGISTER_RT_MASK: u32 = 0x1f;
const BRK_NATIVE_SYSCALL_IMM: u16 = 0xf000;
const BRK_NATIVE_MRS_TPIDR_IMM_BASE: u16 = 0xe000;
const BRK_NATIVE_MSR_TPIDR_IMM_BASE: u16 = 0xe100;
const BRK_NATIVE_MRS_CTR_IMM_BASE: u16 = 0xe200;
const BRK_NATIVE_MRS_DCZID_IMM_BASE: u16 = 0xe300;
const BRK_NATIVE_DC_ZVA_IMM_BASE: u16 = 0xe400;
const BRK_NATIVE_SYSCALL: u32 = brk_instruction(BRK_NATIVE_SYSCALL_IMM);
const AARCH64_NOP: u32 = 0xd503_201f;
const NATIVE_CTR_EL0: u64 = 0x8444_4004;
const NATIVE_DCZID_EL0: u64 = 0x4;
const NATIVE_DC_ZVA_BLOCK_SIZE: usize = 64;
const NATIVE_DARWIN_PIE_BASE: u64 = 0x4_0000_0000;
const NATIVE_DARWIN_SIGRETURN_TRAMPOLINE_BASE: u64 = 0x7_0000_0000;
const NATIVE_DARWIN_HEAP_BASE: u64 = 0x8_0000_0000;
const NATIVE_DARWIN_HEAP_SIZE: u64 = 128 * 1024 * 1024;
// Darwin places randomized malloc zones in 0x70_0000_0000..0x80_0000_0000.
// MAP_FIXED would silently replace them, corrupting the host process. Keep the
// native direct-mapped arena above Carrick's shared/private aperture windows.
const NATIVE_DARWIN_MMAP_BASE: u64 = 0xa0_0000_0000;
const NATIVE_DARWIN_MMAP_SIZE: u64 = 32 * 1024 * 1024 * 1024;
const NATIVE_DARWIN_HARD_PAGEZERO_END: u64 = 0x1_0000_0000;
const NATIVE_DARWIN_RESUME_BUCKET_SIZE: u64 = 128 * 1024 * 1024;
const NATIVE_WAIT_BACKSTOP: Duration = Duration::from_millis(50);
const VM_INHERIT_SHARE: libc::c_int = 0;
const VM_INHERIT_COPY: libc::c_int = 1;

type SharedNativeMemory = Arc<parking_lot::Mutex<NativeMappedMemory>>;

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct NativeUcontextSnapshot {
    x: [u64; 31],
    sp: u64,
    pc: u64,
    pstate: u64,
    v: [[u8; 16]; 32],
    fpsr: u32,
    fpcr: u32,
    signal: libc::c_int,
    signal_code: libc::c_int,
    fault_address: u64,
    esr: u64,
    far: u64,
}

#[derive(Clone, Copy)]
struct NativeRelativeRelocation {
    address: u64,
    value: u64,
}

struct NativeForkRequest {
    pidfd_out: Option<u64>,
    clone_parent: bool,
    parent_tid_addr: Option<u64>,
    child_tid_addr: Option<u64>,
    exit_signal: u32,
    child_stack: u64,
    vfork: Option<u64>,
}

struct NativeVforkCompletion {
    fd: RawFd,
}

impl NativeVforkCompletion {
    fn notify(&mut self) {
        if self.fd < 0 {
            return;
        }
        let byte = [1_u8];
        let _ = unsafe { libc::write(self.fd, byte.as_ptr().cast(), byte.len()) };
        close_fd(self.fd);
        self.fd = -1;
    }
}

impl Drop for NativeVforkCompletion {
    fn drop(&mut self) {
        self.notify();
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum NativeTrap {
    Syscall { resume_pc: u64 },
    ReadTpidr { rt: u32, resume_pc: u64 },
    WriteTpidr { rt: u32, resume_pc: u64 },
    ReadConstant { rt: u32, value: u64, resume_pc: u64 },
    DcZva { rt: u32, resume_pc: u64 },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum NativeWaitResult {
    Ready,
    TimedOut,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum NativeSignalWaitResult {
    Ready,
    Interrupted,
    TimedOut,
}

unsafe extern "C" {
    fn carrick_native_install_trap_handler() -> libc::c_int;
    #[cfg(test)]
    fn carrick_native_seed_ucontext(snapshot: *const NativeUcontextSnapshot) -> libc::c_int;
    fn carrick_native_enter(entry: u64, sp: u64) -> libc::c_int;
    fn carrick_native_resume() -> libc::c_int;
    fn carrick_native_resume_detached_context() -> libc::c_int;
    fn carrick_native_snapshot_ucontext(out: *mut NativeUcontextSnapshot) -> libc::c_int;
    fn carrick_native_set_return(value: u64);
    fn carrick_native_set_pc(pc: u64);
    fn carrick_native_set_sp(sp: u64);
    fn carrick_native_set_register(index: u32, value: u64);
    fn carrick_native_set_vector(index: u32, value: *const u8);
    fn carrick_native_clear_icache(start: *mut libc::c_void, len: usize);
    fn carrick_native_reset_resume_pads();
    fn carrick_native_register_resume_page(
        bucket: u64,
        base: *mut libc::c_void,
        page_size: usize,
    ) -> libc::c_int;
}

const fn brk_instruction(imm: u16) -> u32 {
    0xd420_0000 | ((imm as u32) << 5)
}

pub(crate) fn run_static_elf<A, E>(
    path: &Path,
    mut dispatcher: SyscallDispatcher,
    argv: A,
    env: E,
    max_traps: usize,
    debug_state_path: Option<&PathBuf>,
    plan: &ExecutionPlan,
) -> Result<RunResult, RuntimeError>
where
    A: IntoIterator<Item = String>,
    E: IntoIterator<Item = String>,
{
    let Some(geometry) = plan.page_geometry.native_geometry() else {
        return Err(RuntimeError::Unsupported(
            "native Darwin run-elf selected without native page geometry".to_string(),
        ));
    };

    dispatcher.set_page_geometry(plan.page_geometry);
    dispatcher.set_memory_layout(native_memory_layout());
    let argv: Vec<String> = argv.into_iter().collect();
    let env: Vec<String> = env.into_iter().collect();
    let identity = argv
        .first()
        .cloned()
        .unwrap_or_else(|| canonical_host_executable_path(path));
    dispatcher.set_executable_identity(
        identity,
        argv.clone(),
        env.iter().map(|s| s.as_bytes().to_vec()).collect(),
    );

    let file = std::fs::read(path).map_err(AddressSpaceError::Io)?;
    let relative_relocations = native_relative_relocations(&file, NATIVE_DARWIN_PIE_BASE)?;
    let image = AddressSpace::load_elf_bytes_with_reader_at_pie_base_without_runtime_regions(
        &file,
        &|p| {
            dispatcher
                .read_exec_file(p)
                .or_else(|| std::fs::read(p).ok())
        },
        NATIVE_DARWIN_PIE_BASE,
        geometry.host_page_size,
    )?
    .with_vdso_auxv(false)
    .with_linux_initial_stack_page_size(argv, env, geometry.linux_page_size)?;
    maybe_dump_debug_state(&image, debug_state_path);

    run_image_in_child(image, dispatcher, max_traps, relative_relocations, plan)
}

pub(crate) fn run_elf_from_dispatcher_debug<A, E>(
    path: &str,
    mut dispatcher: SyscallDispatcher,
    argv: A,
    env: E,
    max_traps: usize,
    debug_state_path: Option<&PathBuf>,
    plan: &ExecutionPlan,
) -> Result<RunResult, RuntimeError>
where
    A: IntoIterator<Item = String>,
    E: IntoIterator<Item = String>,
{
    let Some(geometry) = plan.page_geometry.native_geometry() else {
        return Err(RuntimeError::Unsupported(
            "native Darwin container launch selected without native page geometry".to_string(),
        ));
    };

    dispatcher.set_page_geometry(plan.page_geometry);
    dispatcher.set_memory_layout(native_memory_layout());
    let argv: Vec<String> = argv.into_iter().collect();
    let env: Vec<String> = env.into_iter().collect();
    let argv_for_cmdline = argv.clone();
    let argv_bytes = argv.into_iter().map(String::into_bytes).collect();
    let (resolved, argv) =
        crate::exec_helpers::resolve_entrypoint_program(path, &env, argv_bytes, &dispatcher)
            .map_err(|_| {
                RuntimeError::AddressSpace(AddressSpaceError::Io(std::io::Error::new(
                    std::io::ErrorKind::NotFound,
                    path.to_owned(),
                )))
            })?;
    dispatcher.set_executable_identity(
        resolved.clone(),
        argv_for_cmdline,
        env.iter().map(|value| value.as_bytes().to_vec()).collect(),
    );
    let file = dispatcher.read_exec_file(&resolved).ok_or_else(|| {
        RuntimeError::AddressSpace(AddressSpaceError::Io(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            resolved.clone(),
        )))
    })?;
    let relative_relocations = native_relative_relocations(&file, NATIVE_DARWIN_PIE_BASE)?;
    let image = AddressSpace::load_elf_bytes_with_reader_at_pie_base_without_runtime_regions(
        &file,
        &|interpreter| dispatcher.read_exec_file(interpreter),
        NATIVE_DARWIN_PIE_BASE,
        geometry.host_page_size,
    )?
    .with_vdso_auxv(false)
    .with_linux_initial_stack_page_size(argv, env, geometry.linux_page_size)?;
    maybe_dump_debug_state(&image, debug_state_path);

    run_image_in_child(image, dispatcher, max_traps, relative_relocations, plan)
}

fn load_native_execve_image(
    dispatcher: &SyscallDispatcher,
    path: &str,
    argv: Vec<Vec<u8>>,
    env: Vec<Vec<u8>>,
    plan: &ExecutionPlan,
) -> Result<(AddressSpace, Vec<NativeRelativeRelocation>, String), crate::linux_abi::LinuxErrno> {
    let geometry = plan
        .page_geometry
        .native_geometry()
        .ok_or(crate::linux_abi::LINUX_ENOEXEC)?;
    let argv = if argv.is_empty() {
        vec![path.as_bytes().to_vec()]
    } else {
        argv
    };
    let absolute = dispatcher.resolve_exec_path(path);
    dispatcher.check_exec_target(&absolute)?;
    let (resolved, argv) = crate::exec_helpers::resolve_shebang(dispatcher, absolute, argv)?;
    let host_fallback = dispatcher.exec_host_fs_fallback();
    let host_read = |candidate: &str| {
        if host_fallback {
            std::fs::read(candidate).ok()
        } else {
            None
        }
    };
    let file = dispatcher
        .read_exec_file(&resolved)
        .or_else(|| host_read(&resolved))
        .ok_or(crate::linux_abi::LINUX_ENOENT)?;
    let relative_relocations = native_relative_relocations(&file, NATIVE_DARWIN_PIE_BASE)
        .map_err(|_| crate::linux_abi::LINUX_ENOEXEC)?;
    let image = AddressSpace::load_elf_bytes_with_reader_at_pie_base_without_runtime_regions(
        &file,
        &|interpreter| {
            dispatcher
                .read_exec_file(interpreter)
                .or_else(|| host_read(interpreter))
        },
        NATIVE_DARWIN_PIE_BASE,
        geometry.host_page_size,
    )
    .map_err(|_| crate::linux_abi::LINUX_ENOEXEC)?
    .with_vdso_auxv(false)
    .with_linux_initial_stack_execfn_page_size(
        argv,
        env,
        resolved.as_bytes(),
        geometry.linux_page_size,
    )
    .map_err(|_| crate::linux_abi::LINUX_ENOENT)?;
    Ok((image, relative_relocations, resolved))
}

fn native_memory_layout() -> MemoryLayout {
    MemoryLayout {
        heap_base: NATIVE_DARWIN_HEAP_BASE,
        heap_size: NATIVE_DARWIN_HEAP_SIZE,
        mmap_base: NATIVE_DARWIN_MMAP_BASE,
        mmap_size: NATIVE_DARWIN_MMAP_SIZE,
    }
}

fn canonical_host_executable_path(path: &Path) -> String {
    path.canonicalize()
        .unwrap_or_else(|_| path.to_path_buf())
        .to_string_lossy()
        .into_owned()
}

fn native_relative_relocations(
    file: &[u8],
    load_bias: u64,
) -> Result<Vec<NativeRelativeRelocation>, RuntimeError> {
    let elf = Elf::parse(file).map_err(|err| {
        RuntimeError::Unsupported(format!(
            "native Darwin failed to parse ELF relocations: {err}"
        ))
    })?;
    if !native_image_needs_eager_relocations(&elf) {
        return Ok(Vec::new());
    }

    let mut relocations = Vec::new();
    for reloc in elf.dynrelas.iter().chain(elf.dynrels.iter()) {
        match reloc.r_type {
            R_AARCH64_RELATIVE => {
                let addend = reloc.r_addend.ok_or_else(|| {
                    RuntimeError::Unsupported(format!(
                        "native Darwin REL relocation without addend at 0x{:x}",
                        reloc.r_offset
                    ))
                })?;
                relocations.push(NativeRelativeRelocation {
                    address: checked_add_u64(load_bias, reloc.r_offset, "relocation address")?,
                    value: add_load_bias(load_bias, addend)?,
                });
            }
            R_AARCH64_NONE => {}
            other => {
                return Err(RuntimeError::Unsupported(format!(
                    "native Darwin ET_DYN relocation type {other} at 0x{:x} is not supported",
                    reloc.r_offset
                )));
            }
        }
    }
    Ok(relocations)
}

fn native_image_needs_eager_relocations(elf: &Elf<'_>) -> bool {
    elf.header.e_type == ET_DYN && elf.interpreter.is_none()
}

fn checked_add_u64(a: u64, b: u64, context: &str) -> Result<u64, RuntimeError> {
    a.checked_add(b).ok_or_else(|| {
        RuntimeError::Unsupported(format!("native Darwin {context} overflow: 0x{a:x}+0x{b:x}"))
    })
}

fn align_up_u64(value: u64, align: u64, context: &str) -> Result<u64, RuntimeError> {
    if align == 0 || !align.is_power_of_two() {
        return Err(RuntimeError::Unsupported(format!(
            "native Darwin {context} invalid alignment: {align}"
        )));
    }
    value
        .checked_add(align - 1)
        .map(|v| v & !(align - 1))
        .ok_or_else(|| {
            RuntimeError::Unsupported(format!(
                "native Darwin {context} overflow: 0x{value:x} align 0x{align:x}"
            ))
        })
}

fn add_load_bias(load_bias: u64, addend: i64) -> Result<u64, RuntimeError> {
    if addend >= 0 {
        load_bias.checked_add(addend as u64).ok_or_else(|| {
            RuntimeError::Unsupported(format!(
                "native Darwin relocation value overflow: 0x{load_bias:x}+0x{addend:x}"
            ))
        })
    } else {
        let magnitude = addend.unsigned_abs();
        load_bias.checked_sub(magnitude).ok_or_else(|| {
            RuntimeError::Unsupported(format!(
                "native Darwin relocation value underflow: 0x{load_bias:x}-0x{magnitude:x}"
            ))
        })
    }
}

fn apply_native_relative_relocations(
    memory: &mut NativeMappedMemory,
    relocations: &[NativeRelativeRelocation],
) -> Result<(), RuntimeError> {
    for relocation in relocations {
        memory.write_u64(relocation.address, relocation.value)?;
    }
    Ok(())
}

fn run_image_in_child(
    image: AddressSpace,
    dispatcher: SyscallDispatcher,
    max_traps: usize,
    relative_relocations: Vec<NativeRelativeRelocation>,
    plan: &ExecutionPlan,
) -> Result<RunResult, RuntimeError> {
    let stdout_pipe = pipe_pair()?;
    let stderr_pipe = pipe_pair()?;
    let pid = unsafe { libc::fork() };
    if pid < 0 {
        close_fd(stdout_pipe.0);
        close_fd(stdout_pipe.1);
        close_fd(stderr_pipe.0);
        close_fd(stderr_pipe.1);
        return Err(last_io_error("fork native Darwin child"));
    }

    if pid == 0 {
        close_fd(stdout_pipe.0);
        close_fd(stderr_pipe.0);
        child_dup2_or_exit(stdout_pipe.1, libc::STDOUT_FILENO);
        child_dup2_or_exit(stderr_pipe.1, libc::STDERR_FILENO);
        close_fd(stdout_pipe.1);
        close_fd(stderr_pipe.1);

        match run_image_in_current_process(
            image,
            dispatcher,
            max_traps,
            &relative_relocations,
            plan,
        ) {
            Ok(code) => unsafe { libc::_exit(code) },
            Err(err) => {
                child_write_stderr(format!("native Darwin child error: {err}\n").as_bytes());
                unsafe { libc::_exit(125) };
            }
        }
    }

    close_fd(stdout_pipe.1);
    close_fd(stderr_pipe.1);
    let stdout_reader = thread::spawn(move || read_pipe_to_end(stdout_pipe.0));
    let stderr_reader = thread::spawn(move || read_pipe_to_end(stderr_pipe.0));
    let status = waitpid_blocking(pid)?;
    let stdout = join_reader(stdout_reader, "stdout")?;
    let stderr = join_reader(stderr_reader, "stderr")?;

    let exit_code = if libc::WIFEXITED(status) {
        libc::WEXITSTATUS(status)
    } else if libc::WIFSIGNALED(status) {
        128 + libc::WTERMSIG(status)
    } else {
        125
    };

    Ok(RunResult {
        exit_code,
        stdout,
        stderr,
        traps: 0,
        report: CompatReport::default(),
        trap_limit_hit: false,
    })
}

fn run_image_in_current_process(
    image: AddressSpace,
    dispatcher: SyscallDispatcher,
    max_traps: usize,
    relative_relocations: &[NativeRelativeRelocation],
    plan: &ExecutionPlan,
) -> Result<i32, RuntimeError> {
    let initial_sp = image.initial_stack_pointer().ok_or_else(|| {
        RuntimeError::Unsupported("native Darwin image has no initial stack".to_string())
    })?;
    let entry = image.entry();
    let memory = Arc::new(parking_lot::Mutex::new(NativeMappedMemory::map(
        &image,
        native_memory_layout(),
        plan.page_geometry.host_page_size,
        plan.page_geometry.linux_page_size,
    )?));
    {
        let mut memory = memory.lock();
        apply_native_relative_relocations(&mut memory, relative_relocations)?;
    }
    let _ = crate::ulock::preinit_waiter_table();
    carrick_signal_core::xsig::xsig_init();
    carrick_signal_core::fasync::fasync_init();
    let reporter = CompatReporter::default();
    let trace_syscalls = std::env::var_os("CARRICK_NATIVE_TRACE_SYSCALLS").is_some();
    let mut guest_tpidr_el0 = 0u64;
    let mut thread_runtime = NativeThreadRuntime::new_current();
    let mut vfork_completion: Option<NativeVforkCompletion> = None;

    let install = unsafe { carrick_native_install_trap_handler() };
    if install != 0 {
        return Err(last_io_error("install native Darwin trap handler"));
    }

    let mut traps = 0usize;
    let entered = unsafe { carrick_native_enter(entry, initial_sp) };
    if entered != 1 {
        return Err(RuntimeError::Unsupported(
            "native Darwin failed to enter guest".to_string(),
        ));
    }

    loop {
        traps = traps.saturating_add(1);
        if traps > max_traps {
            return Err(RuntimeError::TrapLimitExceeded { max_traps });
        }

        let mut snapshot = snapshot_ucontext()?;
        if snapshot.signal == libc::SIGSEGV || snapshot.signal == libc::SIGBUS {
            let fault_address = if snapshot.fault_address != 0 {
                snapshot.fault_address
            } else {
                snapshot.far
            };
            let resident_fault_plan = dispatcher.resident_fault_plan(fault_address);
            let resident_fault_resolved = if let Some((page, prot)) = resident_fault_plan {
                let mut memory = memory.lock();
                let linux_page_size = memory.linux_page_size as usize;
                memory.protect_range(page, linux_page_size, prot).is_ok()
            } else {
                false
            };
            if let Some((page, _)) = resident_fault_plan
                && resident_fault_resolved
            {
                dispatcher.commit_resident_fault(page);
                resume_guest_snapshot(&snapshot)?;
                continue;
            }
            {
                let mut memory = memory.lock();
                emulate_linux4k_guarded_fault(&mut memory, &mut snapshot)?;
            }
            resume_guest_snapshot(&snapshot)?;
            continue;
        }
        if snapshot.signal != libc::SIGTRAP {
            return Err(RuntimeError::Unsupported(format!(
                "native Darwin trapped unexpected signal {} code={} pc=0x{:x} addr=0x{:x} esr=0x{:x}",
                snapshot.signal,
                snapshot.signal_code,
                snapshot.pc,
                snapshot.fault_address,
                snapshot.esr
            )));
        }
        let native_trap = {
            let memory = memory.lock();
            decode_native_trap(&memory, snapshot.pc)?
        };
        match native_trap {
            NativeTrap::ReadTpidr { rt, resume_pc } => {
                if trace_syscalls {
                    child_write_stderr(
                        format!(
                            "native trace pid={} trap={traps} pc=0x{:x} read_tpidr rt={} value=0x{:x} lr=0x{:x}\n",
                            unsafe { libc::getpid() },
                            snapshot.pc, rt, guest_tpidr_el0, snapshot.x[30]
                        )
                        .as_bytes(),
                    );
                }
                set_guest_register(rt, guest_tpidr_el0);
                resume_guest_at(resume_pc)?;
            }
            NativeTrap::WriteTpidr { rt, resume_pc } => {
                guest_tpidr_el0 = snapshot_register(&snapshot, rt);
                if trace_syscalls {
                    child_write_stderr(
                        format!(
                            "native trace pid={} trap={traps} pc=0x{:x} write_tpidr rt={} value=0x{:x}\n",
                            unsafe { libc::getpid() },
                            snapshot.pc, rt, guest_tpidr_el0
                        )
                        .as_bytes(),
                    );
                }
                resume_guest_at(resume_pc)?;
            }
            NativeTrap::ReadConstant {
                rt,
                value,
                resume_pc,
            } => {
                if trace_syscalls {
                    child_write_stderr(
                        format!(
                            "native trace pid={} trap={traps} pc=0x{:x} read_const rt={} value=0x{:x}\n",
                            unsafe { libc::getpid() },
                            snapshot.pc, rt, value
                        )
                        .as_bytes(),
                    );
                }
                set_guest_register(rt, value);
                resume_guest_at(resume_pc)?;
            }
            NativeTrap::DcZva { rt, resume_pc } => {
                let address = snapshot_register(&snapshot, rt);
                {
                    let mut memory = memory.lock();
                    native_dc_zva(&mut memory, address)?;
                }
                resume_guest_at(resume_pc)?;
            }
            NativeTrap::Syscall { resume_pc } => {
                let request = SyscallRequest::new(
                    snapshot.x[8],
                    SyscallArgs([
                        snapshot.x[0],
                        snapshot.x[1],
                        snapshot.x[2],
                        snapshot.x[3],
                        snapshot.x[4],
                        snapshot.x[5],
                    ]),
                )
                .with_current_guest_sp(Some(snapshot.sp));
                if trace_syscalls {
                    child_write_stderr(
                        format!(
                            "native trace pid={} trap={traps} pc=0x{:x} sp=0x{:x} nr={} args={:x},{:x},{:x},{:x},{:x},{:x}\n",
                            unsafe { libc::getpid() },
                            snapshot.pc,
                            snapshot.sp,
                            snapshot.x[8],
                            snapshot.x[0],
                            snapshot.x[1],
                            snapshot.x[2],
                            snapshot.x[3],
                            snapshot.x[4],
                            snapshot.x[5],
                        )
                        .as_bytes(),
                    );
                }

                let outcome = dispatch_native_syscall(
                    &dispatcher,
                    request,
                    &memory,
                    &thread_runtime,
                    &reporter,
                    trace_syscalls,
                )?;
                match outcome {
                    DispatchOutcome::Returned { value } => {
                        if let Some(code) = resume_guest_after_syscall(
                            &dispatcher,
                            &memory,
                            snapshot,
                            resume_pc,
                            value,
                            request.number.raw(),
                        )? {
                            return Ok(code);
                        }
                    }
                    DispatchOutcome::Errno { errno } => {
                        if let Some(code) = resume_guest_after_syscall(
                            &dispatcher,
                            &memory,
                            snapshot,
                            resume_pc,
                            errno.guest_retval(),
                            request.number.raw(),
                        )? {
                            return Ok(code);
                        }
                    }
                    DispatchOutcome::SigReturn => {
                        resume_guest_from_sigreturn(&dispatcher, &memory, snapshot)?;
                    }
                    DispatchOutcome::SignalDeath { signum } => return Ok(128 + signum),
                    DispatchOutcome::Fork {
                        pidfd_out,
                        clone_parent,
                        parent_tid_addr,
                        child_tid_addr,
                        exit_signal,
                        child_stack,
                        vfork,
                    } => {
                        let request = NativeForkRequest {
                            pidfd_out,
                            clone_parent,
                            parent_tid_addr,
                            child_tid_addr,
                            exit_signal,
                            child_stack,
                            vfork,
                        };
                        handle_native_fork(
                            &dispatcher,
                            &memory,
                            &mut thread_runtime,
                            &mut vfork_completion,
                            request,
                            resume_pc,
                        )?;
                    }
                    DispatchOutcome::Execve { path, argv, env } => {
                        let proc_argv: Vec<String> = argv
                            .iter()
                            .map(|value| String::from_utf8_lossy(value).into_owned())
                            .collect();
                        let proc_env = env.clone();
                        match load_native_execve_image(&dispatcher, &path, argv, env, plan) {
                            Ok((image, relative_relocations, resolved)) => {
                                let entry = image.entry();
                                let initial_sp =
                                    image.initial_stack_pointer().ok_or_else(|| {
                                        RuntimeError::Unsupported(
                                            "native Darwin execve image has no initial stack"
                                                .to_string(),
                                        )
                                    })?;
                                dispatcher.reset_memory_state_on_execve();
                                dispatcher.reset_signal_handlers_on_execve();
                                dispatcher.set_executable_identity(
                                    resolved.clone(),
                                    proc_argv.clone(),
                                    proc_env,
                                );
                                crate::vcpu_loop::apply_image_proc_state(&dispatcher, &image);
                                dispatcher.close_cloexec_fds();
                                memory
                                    .lock()
                                    .replace_image(&image, &relative_relocations, plan)?;
                                crate::namespace::pid::mark_self_execed();
                                let cmdline = proc_argv.join(" ");
                                crate::dispatch::set_host_process_name(cmdline.as_bytes());
                                if let Some(mut completion) = vfork_completion.take() {
                                    completion.notify();
                                }
                                guest_tpidr_el0 = 0;
                                for index in 0..31 {
                                    set_guest_register(index, 0);
                                }
                                unsafe { carrick_native_set_sp(initial_sp) };
                                resume_guest_at(entry)?;
                            }
                            Err(errno) => {
                                if let Some(code) = resume_guest_after_syscall(
                                    &dispatcher,
                                    &memory,
                                    snapshot,
                                    resume_pc,
                                    errno.guest_retval(),
                                    request.number.raw(),
                                )? {
                                    return Ok(code);
                                }
                            }
                        }
                    }
                    DispatchOutcome::MapHostAlias {
                        va,
                        ipa: _,
                        len,
                        payload,
                        file,
                        prot_none,
                    } => {
                        memory
                            .lock()
                            .map_host_alias(va.raw(), len, &payload, file, prot_none)?;
                        resume_guest(va.raw(), resume_pc)?;
                    }
                    DispatchOutcome::Exit { code } => return Ok(code),
                    other => {
                        return Err(RuntimeError::Unsupported(format!(
                            "native Darwin run-elf does not yet support dispatcher outcome {other:?}"
                        )));
                    }
                }
            }
        }
    }
}

fn resume_guest_after_syscall(
    dispatcher: &SyscallDispatcher,
    memory: &SharedNativeMemory,
    snapshot: NativeUcontextSnapshot,
    resume_pc: u64,
    return_value: i64,
    syscall_nr: u64,
) -> Result<Option<i32>, RuntimeError> {
    let tid = crate::thread::ThreadId::main_from_host_pid();
    let pc = {
        let mut memory = memory.lock();
        let mut trap = NativeSignalTrap::new(&mut memory, snapshot, Some(syscall_nr));
        trap.complete_syscall(return_value)?;
        trap.set_pc(resume_pc);
        let action = crate::vcpu_loop::deliver_pending_signal(
            &mut trap,
            dispatcher,
            Some(return_value),
            tid,
            None,
        )?;
        if let Some(action) = action {
            if let Some(signum) = action.term_signal {
                return Ok(Some(128 + signum));
            }
            if let Some(signum) = action.stop_signal {
                return Ok(Some(128 + signum));
            }
        }
        let pc = trap.pc();
        trap.commit();
        pc
    };
    resume_guest_at(pc)?;
    Ok(None)
}

fn resume_guest_from_sigreturn(
    dispatcher: &SyscallDispatcher,
    memory: &SharedNativeMemory,
    snapshot: NativeUcontextSnapshot,
) -> Result<(), RuntimeError> {
    let tid = crate::thread::ThreadId::main_from_host_pid();
    let pc = {
        let mut memory = memory.lock();
        let mut trap = NativeSignalTrap::new(&mut memory, snapshot, None);
        let restored_sigmask = trap.restore_from_sigframe()?;
        dispatcher.restore_signal_mask(tid, carrick_abi::SigSet::from_raw(restored_sigmask));
        let pc = trap.pc();
        trap.commit();
        pc
    };
    resume_guest_at(pc)
}

struct NativeSignalTrap<'a> {
    memory: &'a mut NativeMappedMemory,
    regs: NativeUcontextSnapshot,
    orig_x0: u64,
    last_syscall_nr: Option<u64>,
}

struct NativeThreadRuntime {
    tid: crate::thread::ThreadId,
    registry: Arc<crate::thread::ThreadRegistry>,
    futex: Arc<crate::thread::FutexTable>,
    platform_futex: Arc<dyn carrick_hal::PlatformFutex>,
}

impl NativeThreadRuntime {
    fn new_current() -> Self {
        let tid = crate::thread::ThreadId::main_from_host_pid();
        let registry = Arc::new(crate::thread::ThreadRegistry::new(tid));
        crate::thread::set_current_registry(Arc::clone(&registry));
        let futex = Arc::new(crate::thread::FutexTable::new());
        let platform_futex = Arc::new(crate::threaded_impl::hvf_futex(Arc::clone(&futex)))
            as Arc<dyn carrick_hal::PlatformFutex>;
        Self {
            tid,
            registry,
            futex,
            platform_futex,
        }
    }

    fn reset_after_fork_child(&mut self) {
        *self = Self::new_current();
    }

    fn tid(&self) -> crate::thread::ThreadId {
        self.tid
    }
}

impl<'a> NativeSignalTrap<'a> {
    fn new(
        memory: &'a mut NativeMappedMemory,
        regs: NativeUcontextSnapshot,
        last_syscall_nr: Option<u64>,
    ) -> Self {
        Self {
            memory,
            regs,
            orig_x0: regs.x[0],
            last_syscall_nr,
        }
    }

    fn pc(&self) -> u64 {
        self.regs.pc
    }

    fn set_pc(&mut self, pc: u64) {
        self.regs.pc = pc;
    }

    fn commit(&self) {
        for (index, value) in self.regs.x.iter().enumerate() {
            set_guest_register(index as u32, *value);
        }
        for (index, value) in self.regs.v.iter().enumerate() {
            set_guest_vector(index as u32, value);
        }
        unsafe {
            carrick_native_set_sp(self.regs.sp);
            carrick_native_set_pc(self.regs.pc);
        }
    }
}

impl GuestMemory for NativeSignalTrap<'_> {
    fn protections(&self) -> Option<&MemoryProtections> {
        self.memory.protections()
    }

    fn read_bytes_raw(&self, address: u64, length: usize) -> Result<Vec<u8>, MemoryError> {
        self.memory.read_bytes_raw(address, length)
    }

    fn write_bytes_raw(&mut self, address: u64, bytes: &[u8]) -> Result<(), MemoryError> {
        self.memory.write_bytes_raw(address, bytes)
    }

    fn write_bytes_unchecked(&mut self, address: u64, bytes: &[u8]) -> Result<(), MemoryError> {
        self.memory.write_bytes_raw(address, bytes)
    }

    fn guest_range_is_writable(&self, address: u64, length: usize) -> bool {
        self.memory.guest_range_is_writable(address, length)
    }
}

impl RegAccess for NativeSignalTrap<'_> {
    fn get_reg(&self, reg: Reg) -> Result<u64, carrick_hal::OsError> {
        Ok(match reg {
            Reg::X(index) => usize::try_from(index)
                .ok()
                .and_then(|i| self.regs.x.get(i).copied())
                .unwrap_or(0),
            Reg::Sp => self.regs.sp,
            Reg::Pc | Reg::ElrEl1 => self.regs.pc,
            Reg::Pstate | Reg::SpsrEl1 => self.regs.pstate,
            Reg::SpEl1 => 0,
            _ => 0,
        })
    }

    fn set_reg(&mut self, reg: Reg, value: u64) -> Result<(), carrick_hal::OsError> {
        match reg {
            Reg::X(index) => {
                if let Ok(i) = usize::try_from(index)
                    && let Some(slot) = self.regs.x.get_mut(i)
                {
                    *slot = value;
                }
            }
            Reg::Sp => self.regs.sp = value,
            Reg::Pc | Reg::ElrEl1 => self.regs.pc = value,
            Reg::Pstate | Reg::SpsrEl1 => self.regs.pstate = value,
            Reg::SpEl1 => {}
            _ => {}
        }
        Ok(())
    }

    fn get_sys_reg(&self, _reg: SysReg) -> Result<u64, carrick_hal::OsError> {
        Ok(0)
    }

    fn set_sys_reg(&mut self, _reg: SysReg, _value: u64) -> Result<(), carrick_hal::OsError> {
        Ok(())
    }

    fn get_vreg(&self, n: u32) -> Result<u128, carrick_hal::OsError> {
        Ok(usize::try_from(n)
            .ok()
            .and_then(|index| self.regs.v.get(index))
            .map_or(0, |value| u128::from_le_bytes(*value)))
    }

    fn set_vreg(&mut self, n: u32, value: u128) -> Result<(), carrick_hal::OsError> {
        if let Ok(index) = usize::try_from(n)
            && let Some(slot) = self.regs.v.get_mut(index)
        {
            *slot = value.to_le_bytes();
        }
        Ok(())
    }

    fn get_fpcr(&self) -> Result<u64, carrick_hal::OsError> {
        Ok(u64::from(self.regs.fpcr))
    }

    fn set_fpcr(&mut self, value: u64) -> Result<(), carrick_hal::OsError> {
        self.regs.fpcr = value as u32;
        Ok(())
    }

    fn get_fpsr(&self) -> Result<u64, carrick_hal::OsError> {
        Ok(u64::from(self.regs.fpsr))
    }

    fn set_fpsr(&mut self, value: u64) -> Result<(), carrick_hal::OsError> {
        self.regs.fpsr = value as u32;
        Ok(())
    }
}

impl SyscallTrap for NativeSignalTrap<'_> {
    fn next_syscall(&mut self) -> Result<Option<RawSyscall>, TrapError> {
        Err(TrapError::Hypervisor(
            "native Darwin signal adapter cannot enter guest".to_string(),
        ))
    }

    fn current_pc(&self) -> Result<u64, TrapError> {
        Ok(self.regs.pc)
    }

    fn complete_syscall(&mut self, return_value: i64) -> Result<(), TrapError> {
        self.regs.x[0] = return_value as u64;
        Ok(())
    }

    fn fork(&mut self) -> Result<ForkOutcome, TrapError> {
        Err(TrapError::Hypervisor(
            "native Darwin signal adapter cannot fork".to_string(),
        ))
    }

    fn execve_into(&mut self, _new_image: &AddressSpace) -> Result<(), TrapError> {
        Err(TrapError::Hypervisor(
            "native Darwin signal adapter cannot execve".to_string(),
        ))
    }

    fn inject_signal(
        &mut self,
        signum: i32,
        handler: u64,
        sa_restorer: u64,
        pending_syscall_retval: Option<i64>,
        interrupted_pc: Option<u64>,
        altstack: Option<(u64, u64)>,
        saved_sigmask: u64,
        fault_siginfo: Option<(i32, u64)>,
        queued_siginfo: Option<carrick_abi::LinuxSiginfo>,
        restart_syscall: bool,
    ) -> Result<(), TrapError> {
        let params = carrick_hal::sigframe::InjectParams {
            signum,
            handler,
            sa_restorer,
            pending_syscall_retval,
            interrupted_pc: interrupted_pc.or(Some(self.regs.pc)),
            altstack,
            saved_sigmask,
            fault_siginfo,
            queued_siginfo,
            restart_syscall,
            pstate_source: self.regs.pstate & !0xf,
            orig_x0: self.orig_x0,
            fault_esr: 0,
            fpsimd_enabled: false,
            sigreturn_trampoline_base: NATIVE_DARWIN_SIGRETURN_TRAMPOLINE_BASE,
        };
        carrick_hal::sigframe::build_sigframe(self, params)?;
        Ok(())
    }

    fn last_syscall_nr(&self) -> Option<u64> {
        self.last_syscall_nr
    }

    fn restore_from_sigframe(&mut self) -> Result<u64, TrapError> {
        let restored = carrick_hal::sigframe::restore_sigframe(self, false)?;
        self.regs.pc = restored.saved_pc;
        Ok(restored.sigmask)
    }
}

fn dispatch_native_syscall(
    dispatcher: &SyscallDispatcher,
    request: SyscallRequest,
    memory: &SharedNativeMemory,
    thread_runtime: &NativeThreadRuntime,
    reporter: &CompatReporter,
    trace_syscalls: bool,
) -> Result<DispatchOutcome, RuntimeError> {
    let mut signal_wait_deadline = None;
    loop {
        let outcome = {
            let mut memory = memory.lock();
            dispatcher.dispatch_threaded(
                request,
                &mut *memory,
                reporter,
                thread_runtime.tid(),
                &thread_runtime.registry,
                &thread_runtime.futex,
            )?
        };
        if trace_syscalls {
            child_write_stderr(
                format!("native trace pid={} outcome={outcome:?}\n", unsafe {
                    libc::getpid()
                })
                .as_bytes(),
            );
        }
        match outcome {
            DispatchOutcome::WaitOnFds {
                fds,
                timeout,
                on_timeout,
                sig_mask,
            }
            | DispatchOutcome::WaitOnPollFds {
                fds,
                timeout,
                on_timeout,
                sig_mask,
            } => match wait_native_fds(dispatcher, &fds, timeout, sig_mask) {
                Ok(NativeWaitResult::Ready) => continue,
                Ok(NativeWaitResult::TimedOut) => {
                    return Ok(DispatchOutcome::Returned { value: on_timeout });
                }
                Err(errno) => return Ok(DispatchOutcome::Errno { errno }),
            },
            DispatchOutcome::WaitOnFdsSelect {
                fds,
                timeout,
                sig_mask,
                clear_on_timeout,
            } => match wait_native_fds(dispatcher, &fds, timeout, sig_mask) {
                Ok(NativeWaitResult::Ready) => continue,
                Ok(NativeWaitResult::TimedOut) => {
                    let mut memory = memory.lock();
                    for (addr, len) in &clear_on_timeout {
                        let _ = memory.zero_guest_range(*addr, *len);
                    }
                    return Ok(DispatchOutcome::Returned { value: 0 });
                }
                Err(errno) => return Ok(DispatchOutcome::Errno { errno }),
            },
            DispatchOutcome::WaitOnSignals {
                wait_set,
                block_mask,
                timeout,
            } => match wait_native_signals(
                dispatcher,
                wait_set,
                block_mask,
                timeout,
                &mut signal_wait_deadline,
            ) {
                NativeSignalWaitResult::Ready => continue,
                NativeSignalWaitResult::Interrupted => {
                    return Ok(DispatchOutcome::Errno {
                        errno: crate::linux_abi::LINUX_EINTR,
                    });
                }
                NativeSignalWaitResult::TimedOut => {
                    return Ok(DispatchOutcome::Errno {
                        errno: crate::linux_abi::LINUX_EAGAIN,
                    });
                }
            },
            DispatchOutcome::FutexWait { wait, timeout } => {
                return Ok(DispatchOutcome::Returned {
                    value: wait_native_futex(dispatcher, thread_runtime, wait, timeout, 0),
                });
            }
            DispatchOutcome::FutexWaitv {
                wait,
                timeout,
                index,
            } => {
                return Ok(DispatchOutcome::Returned {
                    value: wait_native_futex(dispatcher, thread_runtime, wait, timeout, index),
                });
            }
            DispatchOutcome::SharedFutexWait {
                location,
                waiter_key,
                value,
                timeout,
            } => {
                return Ok(DispatchOutcome::Returned {
                    value: wait_native_shared_futex(
                        dispatcher,
                        thread_runtime,
                        location,
                        waiter_key,
                        value,
                        timeout,
                        0,
                    ),
                });
            }
            DispatchOutcome::SharedFutexWaitv {
                location,
                waiter_key,
                value,
                timeout,
                index,
            } => {
                return Ok(DispatchOutcome::Returned {
                    value: wait_native_shared_futex(
                        dispatcher,
                        thread_runtime,
                        location,
                        waiter_key,
                        value,
                        timeout,
                        index,
                    ),
                });
            }
            DispatchOutcome::SharedFutexWake {
                location,
                waiter_key,
                count,
            } => {
                let woke = thread_runtime
                    .platform_futex
                    .shared_wake(location, waiter_key, count);
                return Ok(DispatchOutcome::Returned { value: woke.max(0) });
            }
            DispatchOutcome::SharedFutexRequeue {
                from,
                from_key,
                to,
                to_key,
                wake,
                requeue,
            } => {
                let (woken, requeued) = thread_runtime
                    .platform_futex
                    .shared_requeue(from, from_key, to, to_key, wake, requeue);
                return Ok(DispatchOutcome::Returned {
                    value: i64::from(woken + requeued),
                });
            }
            DispatchOutcome::BlockingHostWrite(mut write) => loop {
                match crate::dispatch::drive_blocking_host_write(&mut write) {
                    crate::dispatch::BlockingHostWriteStep::Done(outcome) => {
                        return Ok(crate::vcpu_loop::raise_sigpipe_for_blocking_write(
                            dispatcher, &write, outcome,
                        ));
                    }
                    crate::dispatch::BlockingHostWriteStep::Wait => {
                        match wait_native_fds(
                            dispatcher,
                            &[crate::io_wait::WaitFd::raw(write.host_fd(), libc::POLLOUT)],
                            None,
                            carrick_abi::WaitSigMask::NONE,
                        ) {
                            Ok(NativeWaitResult::Ready) => continue,
                            Ok(NativeWaitResult::TimedOut) => {
                                return Ok(DispatchOutcome::Returned {
                                    value: write.offset() as i64,
                                });
                            }
                            Err(errno) => {
                                if write.offset() > 0 {
                                    return Ok(DispatchOutcome::Returned {
                                        value: write.offset() as i64,
                                    });
                                }
                                return Ok(DispatchOutcome::Errno { errno });
                            }
                        }
                    }
                }
            },
            DispatchOutcome::WaitOnProcExit { pid, sig_mask } => {
                match wait_native_proc_exit(dispatcher, pid, sig_mask) {
                    Ok(NativeWaitResult::Ready) | Ok(NativeWaitResult::TimedOut) => continue,
                    Err(errno) => return Ok(DispatchOutcome::Errno { errno }),
                }
            }
            DispatchOutcome::WaitOnSleep {
                duration,
                remaining,
            } => {
                let deadline = Instant::now() + duration;
                match wait_native_sleep_until(dispatcher, deadline) {
                    Ok(()) => return Ok(DispatchOutcome::Returned { value: 0 }),
                    Err(crate::linux_abi::LINUX_EINTR) => {
                        let mut memory = memory.lock();
                        return Ok(crate::dispatch::complete_interrupted_sleep(
                            &mut *memory,
                            remaining,
                            deadline.saturating_duration_since(Instant::now()),
                        ));
                    }
                    Err(errno) => return Ok(DispatchOutcome::Errno { errno }),
                }
            }
            other => return Ok(other),
        }
    }
}

fn wait_native_futex(
    dispatcher: &SyscallDispatcher,
    thread_runtime: &NativeThreadRuntime,
    wait: crate::thread::FutexWait,
    timeout: Option<Duration>,
    woken_value: i64,
) -> i64 {
    match thread_runtime.futex.wait_prepared_for_thread(
        wait,
        timeout,
        thread_runtime.tid(),
        &|| {
            native_wait_should_interrupt(
                dispatcher,
                thread_runtime.tid(),
                carrick_abi::WaitSigMask::NONE,
            )
        },
    ) {
        crate::thread::FutexWaitOutcome::Woken => woken_value,
        crate::thread::FutexWaitOutcome::TimedOut => {
            crate::linux_abi::LINUX_ETIMEDOUT.guest_retval()
        }
        crate::thread::FutexWaitOutcome::Interrupted => {
            crate::linux_abi::LINUX_EINTR.guest_retval()
        }
    }
}

fn wait_native_shared_futex(
    dispatcher: &SyscallDispatcher,
    thread_runtime: &NativeThreadRuntime,
    location: carrick_guest_mem::SharedFutexLocation,
    waiter_key: usize,
    value: u32,
    timeout: Option<Duration>,
    woken_value: i64,
) -> i64 {
    let interrupted = || {
        native_wait_should_interrupt(
            dispatcher,
            thread_runtime.tid(),
            carrick_abi::WaitSigMask::NONE,
        )
    };
    let wait_enrolled = || {};
    let retval = thread_runtime.platform_futex.shared_wait(
        location,
        waiter_key,
        value,
        timeout,
        &interrupted,
        &wait_enrolled,
    );
    if retval == 0 { woken_value } else { retval }
}

fn wait_native_signals(
    dispatcher: &SyscallDispatcher,
    wait_set: carrick_abi::SigSet,
    block_mask: carrick_abi::SigBlockMask,
    timeout: Option<Duration>,
    deadline: &mut Option<Instant>,
) -> NativeSignalWaitResult {
    let tid = crate::thread::ThreadId::main_from_host_pid();
    loop {
        let Some(slice) = crate::vcpu_loop::signal_wait_slice(deadline, timeout) else {
            return NativeSignalWaitResult::TimedOut;
        };
        if let Some(result) = native_signal_wait_pending(dispatcher, tid, wait_set, block_mask) {
            return result;
        }
        thread::sleep(slice);
        if crate::vcpu_loop::signal_wait_expired(*deadline) {
            return NativeSignalWaitResult::TimedOut;
        }
    }
}

fn native_signal_wait_pending(
    dispatcher: &SyscallDispatcher,
    tid: crate::thread::ThreadId,
    wait_set: carrick_abi::SigSet,
    block_mask: carrick_abi::SigBlockMask,
) -> Option<NativeSignalWaitResult> {
    native_poll_child_exit_watches();
    dispatcher.drain_xsignals_process_directed();
    if crate::host_signal::has_unblocked_pending_for(
        tid.raw(),
        carrick_abi::SigBlockMask::blocking_all_of(wait_set.complement()),
    ) {
        return Some(NativeSignalWaitResult::Ready);
    }
    if dispatcher.has_deliverable_dispatch_pending_for_wait(
        tid,
        carrick_abi::WaitSigMask::Replace(carrick_abi::SigSet::from_raw(block_mask.raw())),
    ) {
        return Some(NativeSignalWaitResult::Ready);
    }
    if dispatcher.signal_wait_should_eintr(tid, wait_set, block_mask) {
        return Some(NativeSignalWaitResult::Interrupted);
    }
    None
}

fn wait_native_fds(
    dispatcher: &SyscallDispatcher,
    fds: &[crate::io_wait::WaitFd],
    timeout: Option<Duration>,
    sig_mask: carrick_abi::WaitSigMask,
) -> Result<NativeWaitResult, crate::linux_abi::LinuxErrno> {
    let tid = crate::thread::ThreadId::main_from_host_pid();
    let mut pollfds: Vec<libc::pollfd> = fds
        .iter()
        .map(|fd| libc::pollfd {
            fd: fd.fd(),
            events: fd.events(),
            revents: 0,
        })
        .collect();
    let nfds = libc::nfds_t::try_from(pollfds.len()).map_err(|_| crate::linux_abi::LINUX_EINVAL)?;
    let deadline = timeout.and_then(|duration| Instant::now().checked_add(duration));
    loop {
        if native_wait_should_interrupt(dispatcher, tid, sig_mask) {
            return Err(crate::linux_abi::LINUX_EINTR);
        }
        let timeout_ms = poll_slice_timeout_ms(deadline);
        let rc = unsafe { libc::poll(pollfds.as_mut_ptr(), nfds, timeout_ms) };
        match rc.host_syscall_errno() {
            Ok(0) => {
                if deadline.is_some_and(|instant| Instant::now() >= instant) {
                    return Ok(NativeWaitResult::TimedOut);
                }
                if native_wait_should_interrupt(dispatcher, tid, sig_mask) {
                    return Err(crate::linux_abi::LINUX_EINTR);
                }
            }
            Ok(_) => return Ok(NativeWaitResult::Ready),
            Err(errno) if errno == crate::linux_abi::LINUX_EINTR => {
                if native_wait_should_interrupt(dispatcher, tid, sig_mask) {
                    return Err(crate::linux_abi::LINUX_EINTR);
                }
                if deadline.is_some_and(|instant| Instant::now() >= instant) {
                    return Ok(NativeWaitResult::TimedOut);
                }
            }
            Err(errno) => return Err(errno),
        }
    }
}

fn poll_slice_timeout_ms(deadline: Option<Instant>) -> libc::c_int {
    let now = Instant::now();
    let slice = match deadline {
        Some(deadline) if now >= deadline => return 0,
        Some(deadline) => deadline.duration_since(now).min(NATIVE_WAIT_BACKSTOP),
        None => NATIVE_WAIT_BACKSTOP,
    };
    let millis = slice.as_millis();
    if millis > libc::c_int::MAX as u128 {
        libc::c_int::MAX
    } else {
        millis as libc::c_int
    }
}

fn wait_native_proc_exit(
    dispatcher: &SyscallDispatcher,
    pid: i32,
    sig_mask: carrick_abi::WaitSigMask,
) -> Result<NativeWaitResult, crate::linux_abi::LinuxErrno> {
    let tid = crate::thread::ThreadId::main_from_host_pid();
    while !native_child_status_ready(pid) {
        if native_wait_should_interrupt(dispatcher, tid, sig_mask) {
            return Err(crate::linux_abi::LINUX_EINTR);
        }
        std::thread::sleep(Duration::from_millis(10));
        if native_wait_should_interrupt(dispatcher, tid, sig_mask) {
            return Err(crate::linux_abi::LINUX_EINTR);
        }
    }
    Ok(NativeWaitResult::Ready)
}

fn wait_native_sleep_until(
    dispatcher: &SyscallDispatcher,
    deadline: Instant,
) -> Result<(), crate::linux_abi::LinuxErrno> {
    let tid = crate::thread::ThreadId::main_from_host_pid();
    loop {
        if native_wait_should_interrupt(dispatcher, tid, carrick_abi::WaitSigMask::NONE) {
            return Err(crate::linux_abi::LINUX_EINTR);
        }
        let now = Instant::now();
        if now >= deadline {
            return Ok(());
        }
        let remaining = (deadline - now).min(NATIVE_WAIT_BACKSTOP);
        let request = libc::timespec {
            tv_sec: remaining.as_secs().try_into().unwrap_or(libc::time_t::MAX),
            tv_nsec: remaining.subsec_nanos().into(),
        };
        let rc = unsafe { libc::nanosleep(&request, std::ptr::null_mut()) };
        match rc.host_syscall_errno() {
            Ok(_) => {}
            Err(errno) if errno == crate::linux_abi::LINUX_EINTR => {
                if native_wait_should_interrupt(dispatcher, tid, carrick_abi::WaitSigMask::NONE) {
                    return Err(crate::linux_abi::LINUX_EINTR);
                }
            }
            Err(errno) => return Err(errno),
        }
    }
}

fn native_wait_should_interrupt(
    dispatcher: &SyscallDispatcher,
    tid: crate::thread::ThreadId,
    sig_mask: carrick_abi::WaitSigMask,
) -> bool {
    native_poll_child_exit_watches();
    dispatcher.drain_xsignals_process_directed();
    let block_mask = native_wait_block_mask(dispatcher, tid, sig_mask);
    crate::host_signal::has_unblocked_pending_for(tid.raw(), block_mask)
        || dispatcher.has_deliverable_dispatch_pending_for_wait(tid, sig_mask)
}

fn native_wait_block_mask(
    dispatcher: &SyscallDispatcher,
    tid: crate::thread::ThreadId,
    sig_mask: carrick_abi::WaitSigMask,
) -> carrick_abi::SigBlockMask {
    let effective = match sig_mask {
        carrick_abi::WaitSigMask::Replace(mask) => mask,
        carrick_abi::WaitSigMask::Additive(mask) => dispatcher.signal_mask_for(tid).union(mask),
    };
    carrick_abi::SigBlockMask::blocking_all_of(effective)
}

fn native_child_status_ready(pid: i32) -> bool {
    let (idtype, id) = if pid > 0 {
        (libc::P_PID, pid as libc::id_t)
    } else {
        (libc::P_ALL, 0 as libc::id_t)
    };
    let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
    let rc = unsafe {
        libc::waitid(
            idtype,
            id,
            &mut info,
            libc::WEXITED | libc::WNOWAIT | libc::WNOHANG,
        )
    };
    if rc == 0 {
        const CLD_EXITED: i32 = 1;
        const CLD_KILLED: i32 = 2;
        const CLD_DUMPED: i32 = 3;
        let si_pid = carrick_portable::si_pid(&info);
        return si_pid != 0 && matches!(info.si_code, CLD_EXITED | CLD_KILLED | CLD_DUMPED);
    }
    std::io::Error::last_os_error().raw_os_error() == Some(libc::ECHILD)
}

fn handle_native_fork(
    dispatcher: &SyscallDispatcher,
    memory: &SharedNativeMemory,
    thread_runtime: &mut NativeThreadRuntime,
    vfork_completion: &mut Option<NativeVforkCompletion>,
    request: NativeForkRequest,
    resume_pc: u64,
) -> Result<(), RuntimeError> {
    if request.clone_parent {
        return Err(RuntimeError::Unsupported(
            "native Darwin run-elf fork does not yet support CLONE_PARENT".to_string(),
        ));
    }
    let vfork_pipe = if request.vfork.is_some() {
        memory.lock().set_fork_inheritance(true);
        Some(pipe_pair()?)
    } else {
        None
    };
    let child_parent = std::process::id();
    let child_subreaper = dispatcher.subreaper_for_fork_child();
    let child_ns_pid = crate::namespace::pid::allocate_child_ns_pid_pre_fork();
    let prepared_child_record = match crate::guest_cpu::prepare_child_record_pre_fork(
        child_parent,
        child_subreaper,
        child_ns_pid.unwrap_or(0),
        false,
        0,
    ) {
        Ok(record) => record,
        Err(_) => {
            if let Some((read_fd, write_fd)) = vfork_pipe {
                close_fd(read_fd);
                close_fd(write_fd);
                memory.lock().set_fork_inheritance(false);
            }
            return resume_guest(
                crate::linux_abi::LINUX_EAGAIN.guest_retval() as u64,
                resume_pc,
            );
        }
    };
    let child = unsafe { libc::fork() };
    if child < 0 {
        crate::guest_cpu::abort_prepared_child_record();
        if let Some((read_fd, write_fd)) = vfork_pipe {
            close_fd(read_fd);
            close_fd(write_fd);
            memory.lock().set_fork_inheritance(false);
        }
        return resume_guest(
            crate::linux_abi::LINUX_EAGAIN.guest_retval() as u64,
            resume_pc,
        );
    }
    if child == 0 {
        if let Some((read_fd, write_fd)) = vfork_pipe {
            close_fd(read_fd);
            *vfork_completion = Some(NativeVforkCompletion { fd: write_fd });
        }
        native_trace_fork_phase("child-guard-installed");
        native_after_fork_child(dispatcher);
        native_trace_fork_phase("child-dispatcher-reset");
        thread_runtime.reset_after_fork_child();
        native_trace_fork_phase("child-thread-runtime-reset");
        crate::guest_cpu::reset();
        crate::guest_cpu::complete_child_record_post_fork_child();
        crate::run_state::reinit_booting_after_fork();
        let self_tid = (crate::namespace::pid::self_ns_pid() as i32).to_le_bytes();
        if let Some(addr) = request.parent_tid_addr {
            let _ = memory.lock().write_bytes(addr, &self_tid);
        }
        if let Some(addr) = request.child_tid_addr {
            let _ = memory.lock().write_bytes(addr, &self_tid);
        }
        if request.child_stack != 0 {
            unsafe {
                carrick_native_set_sp(request.child_stack);
            }
        }
        native_trace_fork_phase("child-resume");
        return resume_guest_detached(0, resume_pc);
    }
    if let Some((read_fd, write_fd)) = vfork_pipe {
        close_fd(write_fd);
        wait_native_vfork_completion(read_fd)?;
        close_fd(read_fd);
        memory.lock().set_fork_inheritance(false);
    }
    crate::guest_cpu::publish_prepared_child_record_parent_ref(prepared_child_record, child as u32);
    crate::namespace::pid::notify_child_registered();
    crate::run_state::publish_child_booting(child as u32);
    if let Some(addr) = request.pidfd_out {
        let fd = dispatcher.install_child_pidfd(child).unwrap_or(-1);
        let _ = memory.lock().write_bytes(addr, &fd.to_le_bytes());
    }
    let guest_child_pid = child_ns_pid.unwrap_or(child as u32) as i32;
    if let Some(addr) = request.parent_tid_addr {
        let tid = guest_child_pid.to_le_bytes();
        let _ = memory.lock().write_bytes(addr, &tid);
    }
    native_register_child_exit_watch(dispatcher, child, request.exit_signal);
    resume_guest(guest_child_pid as u64, resume_pc)
}

fn native_trace_fork_phase(phase: &str) {
    if std::env::var_os("CARRICK_NATIVE_TRACE_SYSCALLS").is_some() {
        child_write_stderr(
            format!("native trace pid={} fork-phase={phase}\n", unsafe {
                libc::getpid()
            })
            .as_bytes(),
        );
    }
}

fn wait_native_vfork_completion(fd: RawFd) -> Result<(), RuntimeError> {
    let mut byte = [0_u8; 1];
    loop {
        let rc = unsafe { libc::read(fd, byte.as_mut_ptr().cast(), byte.len()) };
        if rc >= 0 {
            return Ok(());
        }
        let err = std::io::Error::last_os_error();
        if err.raw_os_error() != Some(libc::EINTR) {
            return Err(RuntimeError::FsBackend(anyhow::anyhow!(
                "native Darwin vfork completion read failed: {err}"
            )));
        }
    }
}

fn native_register_child_exit_watch(dispatcher: &SyscallDispatcher, child: i32, exit_signal: u32) {
    let tid = crate::thread::ThreadId::main_from_host_pid();
    let _ = dispatcher;
    if exit_signal == 0 {
        return;
    }
    let signum = i32::try_from(exit_signal).unwrap_or(crate::linux_abi::LINUX_SIGCHLD);
    if std::env::var_os("CARRICK_NATIVE_TRACE_SYSCALLS").is_some() {
        child_write_stderr(
            format!(
                "native trace pid={} register-child-exit child={} parent_tid={} signum={}\n",
                unsafe { libc::getpid() },
                child,
                tid.raw(),
                signum
            )
            .as_bytes(),
        );
    }
    crate::host_signal::register_child_exit_watch(child, tid.raw(), signum);
}

fn native_poll_child_exit_watches() {
    for child in carrick_signal_core::child_watch::tracked_pids() {
        if !native_child_status_ready(child) {
            continue;
        }
        if std::env::var_os("CARRICK_NATIVE_TRACE_SYSCALLS").is_some() {
            child_write_stderr(
                format!(
                    "native trace pid={} child-exit-ready child={}\n",
                    unsafe { libc::getpid() },
                    child
                )
                .as_bytes(),
            );
        }
        let Some((parent_tid, exit_signal)) = crate::host_signal::take_child_exit_parent(child)
        else {
            continue;
        };
        if exit_signal != 0 {
            crate::host_signal::publish_pending_for(parent_tid, exit_signal);
        }
    }
}

fn native_after_fork_child(dispatcher: &SyscallDispatcher) {
    dispatcher.clear_output_buffers();
    crate::event_ring::reinit_after_fork();
    crate::host_signal::reinit_after_fork();
    crate::dispatch::reset_fifo_beacons_after_fork_child();
    dispatcher.epoll_after_fork_child();
    dispatcher.proc_after_fork_child();
    dispatcher.mem_after_fork_child();
    dispatcher.sysv_after_fork_child();
}

fn snapshot_ucontext() -> Result<NativeUcontextSnapshot, RuntimeError> {
    let mut snapshot = NativeUcontextSnapshot::default();
    let rc = unsafe { carrick_native_snapshot_ucontext(&mut snapshot) };
    if rc == 0 {
        Ok(snapshot)
    } else {
        Err(RuntimeError::Unsupported(format!(
            "native Darwin failed to snapshot trap context: {rc}"
        )))
    }
}

fn resume_guest(value: u64, pc: u64) -> Result<(), RuntimeError> {
    unsafe {
        carrick_native_set_return(value);
    }
    resume_guest_at(pc)
}

fn resume_guest_snapshot(snapshot: &NativeUcontextSnapshot) -> Result<(), RuntimeError> {
    for (index, value) in snapshot.x.iter().enumerate() {
        set_guest_register(index as u32, *value);
    }
    for (index, value) in snapshot.v.iter().enumerate() {
        set_guest_vector(index as u32, value);
    }
    unsafe {
        carrick_native_set_sp(snapshot.sp);
    }
    resume_guest_at(snapshot.pc)
}

fn resume_guest_detached(value: u64, pc: u64) -> Result<(), RuntimeError> {
    unsafe {
        carrick_native_set_return(value);
        carrick_native_set_pc(pc);
    }
    if std::env::var_os("CARRICK_NATIVE_TRACE_SYSCALLS").is_some()
        && let Ok(snapshot) = snapshot_ucontext()
    {
        child_write_stderr(
            format!(
                "native trace pid={} detached-resume pc=0x{:x} x0=0x{:x}\n",
                unsafe { libc::getpid() },
                snapshot.pc,
                snapshot.x[0]
            )
            .as_bytes(),
        );
    }
    let install = unsafe { carrick_native_install_trap_handler() };
    if install != 0 {
        return Err(last_io_error(
            "reinstall native Darwin detached trap handler",
        ));
    }
    let rc = unsafe { carrick_native_resume_detached_context() };
    if rc == 1 {
        Ok(())
    } else if rc < 0 {
        Err(last_io_error(&format!(
            "detached-resume native Darwin guest at 0x{pc:x}"
        )))
    } else {
        Err(RuntimeError::Unsupported(format!(
            "native Darwin failed to detached-resume guest: {rc}"
        )))
    }
}

fn set_guest_register(index: u32, value: u64) {
    if index < 31 {
        unsafe {
            carrick_native_set_register(index, value);
        }
    }
}

fn set_guest_vector(index: u32, value: &[u8; 16]) {
    if index < 32 {
        unsafe {
            carrick_native_set_vector(index, value.as_ptr());
        }
    }
}

fn snapshot_register(snapshot: &NativeUcontextSnapshot, index: u32) -> u64 {
    usize::try_from(index)
        .ok()
        .and_then(|idx| snapshot.x.get(idx).copied())
        .unwrap_or(0)
}

fn native_dc_zva(memory: &mut NativeMappedMemory, address: u64) -> Result<(), RuntimeError> {
    let start = address & !(NATIVE_DC_ZVA_BLOCK_SIZE as u64 - 1);
    memory
        .write_bytes(start, &[0; NATIVE_DC_ZVA_BLOCK_SIZE])
        .map_err(|error| {
            RuntimeError::Unsupported(format!(
                "native Darwin DC ZVA failed at 0x{address:x}: {error}"
            ))
        })
}

fn resume_guest_at(pc: u64) -> Result<(), RuntimeError> {
    unsafe {
        carrick_native_set_pc(pc);
    }
    let install = unsafe { carrick_native_install_trap_handler() };
    if install != 0 {
        return Err(last_io_error("reinstall native Darwin trap handler"));
    }
    let rc = unsafe { carrick_native_resume() };
    if rc == 1 {
        Ok(())
    } else if rc < 0 {
        Err(last_io_error(&format!(
            "resume native Darwin guest at 0x{pc:x}"
        )))
    } else {
        Err(RuntimeError::Unsupported(format!(
            "native Darwin failed to resume guest: {rc}"
        )))
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum NativeScalarAccessKind {
    Load { sign_extend: bool },
    Store,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct NativeScalarAccess {
    kind: NativeScalarAccessKind,
    width: usize,
    destination_width: usize,
}

fn bad64_gpr_index(reg: bad64::Reg) -> Option<(usize, usize)> {
    let raw = reg as u32;
    let w0 = bad64::Reg::W0 as u32;
    let w30 = bad64::Reg::W30 as u32;
    if (w0..=w30).contains(&raw) {
        return Some(((raw - w0) as usize, 4));
    }
    let x0 = bad64::Reg::X0 as u32;
    let x30 = bad64::Reg::X30 as u32;
    if (x0..=x30).contains(&raw) {
        return Some(((raw - x0) as usize, 8));
    }
    None
}

fn bad64_transfer_width(reg: bad64::Reg) -> Option<usize> {
    bad64_gpr_index(reg).map(|(_, width)| width).or_else(|| {
        if reg == bad64::Reg::WZR {
            Some(4)
        } else if reg == bad64::Reg::XZR {
            Some(8)
        } else {
            None
        }
    })
}

fn native_snapshot_read_reg(snapshot: &NativeUcontextSnapshot, reg: bad64::Reg) -> Option<u64> {
    if let Some((index, width)) = bad64_gpr_index(reg) {
        let value = snapshot.x.get(index).copied()?;
        return Some(if width == 4 {
            value & u64::from(u32::MAX)
        } else {
            value
        });
    }
    if reg == bad64::Reg::WZR || reg == bad64::Reg::XZR {
        return Some(0);
    }
    if reg == bad64::Reg::SP || reg == bad64::Reg::WSP {
        return Some(snapshot.sp);
    }
    None
}

fn native_snapshot_write_reg(
    snapshot: &mut NativeUcontextSnapshot,
    reg: bad64::Reg,
    value: u64,
) -> bool {
    if let Some((index, width)) = bad64_gpr_index(reg) {
        let Some(slot) = snapshot.x.get_mut(index) else {
            return false;
        };
        *slot = if width == 4 {
            value & u64::from(u32::MAX)
        } else {
            value
        };
        return true;
    }
    if reg == bad64::Reg::WZR || reg == bad64::Reg::XZR {
        return true;
    }
    if reg == bad64::Reg::SP || reg == bad64::Reg::WSP {
        snapshot.sp = value;
        return true;
    }
    false
}

fn add_bad64_imm(base: u64, imm: bad64::Imm) -> u64 {
    match imm {
        bad64::Imm::Signed(value) => base.wrapping_add_signed(value),
        bad64::Imm::Unsigned(value) => base.wrapping_add(value),
    }
}

fn extend_bad64_index(value: u64, shift: Option<bad64::Shift>) -> Option<u64> {
    match shift {
        None => Some(value),
        Some(bad64::Shift::LSL(amount) | bad64::Shift::UXTX(amount)) => {
            Some(value.wrapping_shl(amount))
        }
        Some(bad64::Shift::SXTX(amount)) => Some((value as i64 as u64).wrapping_shl(amount)),
        Some(bad64::Shift::UXTW(amount)) => Some(u64::from(value as u32).wrapping_shl(amount)),
        Some(bad64::Shift::SXTW(amount)) => {
            Some((value as u32 as i32 as i64 as u64).wrapping_shl(amount))
        }
        _ => None,
    }
}

fn decode_native_scalar_address(
    snapshot: &NativeUcontextSnapshot,
    operand: bad64::Operand,
) -> Option<(u64, Option<(bad64::Reg, u64)>)> {
    match operand {
        bad64::Operand::MemReg(base) => Some((native_snapshot_read_reg(snapshot, base)?, None)),
        bad64::Operand::MemOffset {
            reg: base,
            offset,
            mul_vl: false,
            arrspec: None,
        } => Some((
            add_bad64_imm(native_snapshot_read_reg(snapshot, base)?, offset),
            None,
        )),
        bad64::Operand::MemPreIdx { reg: base, imm } => {
            let address = add_bad64_imm(native_snapshot_read_reg(snapshot, base)?, imm);
            Some((address, Some((base, address))))
        }
        bad64::Operand::MemPostIdxImm { reg: base, imm } => {
            let address = native_snapshot_read_reg(snapshot, base)?;
            Some((address, Some((base, add_bad64_imm(address, imm)))))
        }
        bad64::Operand::MemExt {
            regs: [base, index],
            shift,
            arrspec: None,
        } => {
            let base = native_snapshot_read_reg(snapshot, base)?;
            let index = native_snapshot_read_reg(snapshot, index)?;
            Some((base.wrapping_add(extend_bad64_index(index, shift)?), None))
        }
        _ => None,
    }
}

fn decode_native_scalar_access(op: bad64::Op, transfer_width: usize) -> Option<NativeScalarAccess> {
    use bad64::Op;

    let access = match op {
        Op::LDR | Op::LDUR => NativeScalarAccess {
            kind: NativeScalarAccessKind::Load { sign_extend: false },
            width: transfer_width,
            destination_width: transfer_width,
        },
        Op::LDRB | Op::LDURB => NativeScalarAccess {
            kind: NativeScalarAccessKind::Load { sign_extend: false },
            width: 1,
            destination_width: transfer_width,
        },
        Op::LDRH | Op::LDURH => NativeScalarAccess {
            kind: NativeScalarAccessKind::Load { sign_extend: false },
            width: 2,
            destination_width: transfer_width,
        },
        Op::LDRSB | Op::LDURSB => NativeScalarAccess {
            kind: NativeScalarAccessKind::Load { sign_extend: true },
            width: 1,
            destination_width: transfer_width,
        },
        Op::LDRSH | Op::LDURSH => NativeScalarAccess {
            kind: NativeScalarAccessKind::Load { sign_extend: true },
            width: 2,
            destination_width: transfer_width,
        },
        Op::LDRSW | Op::LDURSW if transfer_width == 8 => NativeScalarAccess {
            kind: NativeScalarAccessKind::Load { sign_extend: true },
            width: 4,
            destination_width: 8,
        },
        Op::STR | Op::STUR => NativeScalarAccess {
            kind: NativeScalarAccessKind::Store,
            width: transfer_width,
            destination_width: transfer_width,
        },
        Op::STRB | Op::STURB => NativeScalarAccess {
            kind: NativeScalarAccessKind::Store,
            width: 1,
            destination_width: transfer_width,
        },
        Op::STRH | Op::STURH => NativeScalarAccess {
            kind: NativeScalarAccessKind::Store,
            width: 2,
            destination_width: transfer_width,
        },
        _ => return None,
    };
    Some(access)
}

fn native_load_value(bytes: &[u8], sign_extend: bool, destination_width: usize) -> u64 {
    let mut value = 0u64;
    for (index, byte) in bytes.iter().enumerate() {
        value |= u64::from(*byte) << (index * 8);
    }
    if sign_extend && !bytes.is_empty() && bytes.len() < std::mem::size_of::<u64>() {
        let shift = 64 - bytes.len() * 8;
        value = ((value << shift) as i64 >> shift) as u64;
    }
    if destination_width == 4 {
        value & u64::from(u32::MAX)
    } else {
        value
    }
}

fn bad64_single_vector_index(operand: bad64::Operand) -> Option<usize> {
    let bad64::Operand::MultiReg {
        regs,
        arrspec: Some(bad64::ArrSpec::SixteenBytes(None)),
    } = operand
    else {
        return None;
    };
    let reg = regs[0]?;
    if regs[1..].iter().any(Option::is_some) {
        return None;
    }
    let raw = reg as u32;
    let first = bad64::Reg::V0 as u32;
    let last = bad64::Reg::V31 as u32;
    (first..=last)
        .contains(&raw)
        .then_some((raw - first) as usize)
}

fn bad64_vector_index_and_width(reg: bad64::Reg) -> Option<(usize, usize)> {
    let raw = reg as u32;
    let classes = [
        (bad64::Reg::B0 as u32, bad64::Reg::B31 as u32, 1),
        (bad64::Reg::H0 as u32, bad64::Reg::H31 as u32, 2),
        (bad64::Reg::S0 as u32, bad64::Reg::S31 as u32, 4),
        (bad64::Reg::D0 as u32, bad64::Reg::D31 as u32, 8),
        (bad64::Reg::Q0 as u32, bad64::Reg::Q31 as u32, 16),
        (bad64::Reg::V0 as u32, bad64::Reg::V31 as u32, 16),
    ];
    classes.iter().find_map(|(first, last, width)| {
        (*first..=*last)
            .contains(&raw)
            .then(|| ((raw - *first) as usize, *width))
    })
}

fn emulate_linux4k_guarded_vector_register_access(
    memory: &mut NativeMappedMemory,
    snapshot: &mut NativeUcontextSnapshot,
    instruction: &bad64::Instruction,
    vector_reg: bad64::Reg,
    memory_operand: bad64::Operand,
    fault_address: u64,
) -> Result<(), RuntimeError> {
    let (vector_index, width) = bad64_vector_index_and_width(vector_reg).ok_or_else(|| {
        RuntimeError::Unsupported(format!(
            "native linux4k guarded vector fault does not support register {vector_reg}"
        ))
    })?;
    let write = match instruction.op() {
        bad64::Op::LDR | bad64::Op::LDUR => false,
        bad64::Op::STR | bad64::Op::STUR => true,
        _ => {
            return Err(RuntimeError::Unsupported(format!(
                "native linux4k guarded vector fault does not support {instruction}"
            )));
        }
    };
    let (address, writeback) =
        decode_native_scalar_address(snapshot, memory_operand).ok_or_else(|| {
            RuntimeError::Unsupported(format!(
                "native linux4k guarded vector fault does not support addressing for {instruction}"
            ))
        })?;
    let access_end = address.checked_add(width as u64).ok_or_else(|| {
        RuntimeError::Unsupported("native linux4k guarded vector access overflow".to_string())
    })?;
    if fault_address < address || fault_address >= access_end {
        return Err(RuntimeError::Unsupported(format!(
            "native linux4k guarded fault address 0x{fault_address:x} is outside {instruction} access 0x{address:x}..0x{access_end:x}"
        )));
    }
    if !memory.linux4k_range_allows(address, width, write) {
        return Err(RuntimeError::Unsupported(format!(
            "native linux4k guarded {instruction} violates guest permissions at 0x{address:x}"
        )));
    }
    let slot = snapshot.v.get_mut(vector_index).ok_or_else(|| {
        RuntimeError::Unsupported(format!(
            "native linux4k guarded vector index {vector_index} is out of range"
        ))
    })?;
    if write {
        memory
            .write_bytes_raw(address, &slot[..width])
            .map_err(|error| {
                RuntimeError::Unsupported(format!(
                    "native linux4k guarded vector store failed at 0x{address:x}: {error}"
                ))
            })?;
    } else {
        let bytes = memory.read_bytes_raw(address, width).map_err(|error| {
            RuntimeError::Unsupported(format!(
                "native linux4k guarded vector load failed at 0x{address:x}: {error}"
            ))
        })?;
        slot.fill(0);
        slot[..width].copy_from_slice(&bytes);
    }
    if let Some((base, value)) = writeback
        && !native_snapshot_write_reg(snapshot, base, value)
    {
        return Err(RuntimeError::Unsupported(format!(
            "native linux4k guarded vector fault could not update base register {base}"
        )));
    }
    snapshot.pc = snapshot.pc.checked_add(4).ok_or_else(|| {
        RuntimeError::Unsupported("native linux4k guarded vector PC overflow".to_string())
    })?;
    Ok(())
}

fn emulate_linux4k_guarded_pair_access(
    memory: &mut NativeMappedMemory,
    snapshot: &mut NativeUcontextSnapshot,
    instruction: &bad64::Instruction,
    fault_address: u64,
) -> Result<(), RuntimeError> {
    let [
        bad64::Operand::Reg {
            reg: first_reg,
            arrspec: None,
        },
        bad64::Operand::Reg {
            reg: second_reg,
            arrspec: None,
        },
        memory_operand,
    ] = instruction.operands()
    else {
        return Err(RuntimeError::Unsupported(format!(
            "native linux4k guarded pair fault does not support operands for {instruction}"
        )));
    };
    let write = matches!(instruction.op(), bad64::Op::STP | bad64::Op::STNP);
    if !matches!(
        instruction.op(),
        bad64::Op::LDP | bad64::Op::LDNP | bad64::Op::LDPSW | bad64::Op::STP | bad64::Op::STNP
    ) {
        return Err(RuntimeError::Unsupported(format!(
            "native linux4k guarded pair fault does not support {instruction}"
        )));
    }
    let vector_regs =
        bad64_vector_index_and_width(*first_reg).zip(bad64_vector_index_and_width(*second_reg));
    let gpr_regs = bad64_transfer_width(*first_reg).zip(bad64_transfer_width(*second_reg));
    let element_width = if let Some(((first_index, first_width), (second_index, second_width))) =
        vector_regs
    {
        if first_width != second_width || instruction.op() == bad64::Op::LDPSW {
            return Err(RuntimeError::Unsupported(format!(
                "native linux4k guarded pair has incompatible vector registers for {instruction}"
            )));
        }
        let _ = (first_index, second_index);
        first_width
    } else if let Some((first_width, second_width)) = gpr_regs {
        if first_width != second_width {
            return Err(RuntimeError::Unsupported(format!(
                "native linux4k guarded pair has incompatible GPR widths for {instruction}"
            )));
        }
        if instruction.op() == bad64::Op::LDPSW {
            if first_width != 8 {
                return Err(RuntimeError::Unsupported(format!(
                    "native linux4k guarded LDPSW requires X registers: {instruction}"
                )));
            }
            4
        } else {
            first_width
        }
    } else {
        return Err(RuntimeError::Unsupported(format!(
            "native linux4k guarded pair requires matching GPR or vector registers: {instruction}"
        )));
    };
    let (address, writeback) =
        decode_native_scalar_address(snapshot, *memory_operand).ok_or_else(|| {
            RuntimeError::Unsupported(format!(
                "native linux4k guarded pair fault does not support addressing for {instruction}"
            ))
        })?;
    let total_width = element_width * 2;
    let access_end = address.checked_add(total_width as u64).ok_or_else(|| {
        RuntimeError::Unsupported("native linux4k guarded pair access overflow".to_string())
    })?;
    if fault_address < address || fault_address >= access_end {
        return Err(RuntimeError::Unsupported(format!(
            "native linux4k guarded fault address 0x{fault_address:x} is outside {instruction} access 0x{address:x}..0x{access_end:x}"
        )));
    }
    if !memory.linux4k_range_allows(address, total_width, write) {
        return Err(RuntimeError::Unsupported(format!(
            "native linux4k guarded {instruction} violates guest permissions at 0x{address:x}"
        )));
    }
    if let Some((base, _)) = writeback {
        let base_index = bad64_gpr_index(base).map(|(index, _)| index);
        if base_index == bad64_gpr_index(*first_reg).map(|(index, _)| index)
            || base_index == bad64_gpr_index(*second_reg).map(|(index, _)| index)
        {
            return Err(RuntimeError::Unsupported(format!(
                "native linux4k guarded pair rejects overlapping writeback for {instruction}"
            )));
        }
    }

    if let Some(((first_index, _), (second_index, _))) = vector_regs {
        if write {
            let first = snapshot.v[first_index];
            let second = snapshot.v[second_index];
            memory
                .write_bytes_raw(address, &first[..element_width])
                .and_then(|()| {
                    memory.write_bytes_raw(
                        address.saturating_add(element_width as u64),
                        &second[..element_width],
                    )
                })
                .map_err(|error| {
                    RuntimeError::Unsupported(format!(
                        "native linux4k guarded vector pair store failed at 0x{address:x}: {error}"
                    ))
                })?;
        } else {
            let bytes = memory
                .read_bytes_raw(address, total_width)
                .map_err(|error| {
                    RuntimeError::Unsupported(format!(
                        "native linux4k guarded vector pair load failed at 0x{address:x}: {error}"
                    ))
                })?;
            snapshot.v[first_index].fill(0);
            snapshot.v[first_index][..element_width].copy_from_slice(&bytes[..element_width]);
            snapshot.v[second_index].fill(0);
            snapshot.v[second_index][..element_width].copy_from_slice(&bytes[element_width..]);
        }
    } else if write {
        let first = native_snapshot_read_reg(snapshot, *first_reg).ok_or_else(|| {
            RuntimeError::Unsupported(format!(
                "native linux4k guarded pair could not read {first_reg}"
            ))
        })?;
        let second = native_snapshot_read_reg(snapshot, *second_reg).ok_or_else(|| {
            RuntimeError::Unsupported(format!(
                "native linux4k guarded pair could not read {second_reg}"
            ))
        })?;
        memory
            .write_bytes_raw(address, &first.to_le_bytes()[..element_width])
            .and_then(|()| {
                memory.write_bytes_raw(
                    address.saturating_add(element_width as u64),
                    &second.to_le_bytes()[..element_width],
                )
            })
            .map_err(|error| {
                RuntimeError::Unsupported(format!(
                    "native linux4k guarded GPR pair store failed at 0x{address:x}: {error}"
                ))
            })?;
    } else {
        let bytes = memory
            .read_bytes_raw(address, total_width)
            .map_err(|error| {
                RuntimeError::Unsupported(format!(
                    "native linux4k guarded GPR pair load failed at 0x{address:x}: {error}"
                ))
            })?;
        let sign_extend = instruction.op() == bad64::Op::LDPSW;
        let first = native_load_value(&bytes[..element_width], sign_extend, 8);
        let second = native_load_value(&bytes[element_width..], sign_extend, 8);
        if !native_snapshot_write_reg(snapshot, *first_reg, first)
            || !native_snapshot_write_reg(snapshot, *second_reg, second)
        {
            return Err(RuntimeError::Unsupported(format!(
                "native linux4k guarded pair could not update registers for {instruction}"
            )));
        }
    }
    if let Some((base, value)) = writeback
        && !native_snapshot_write_reg(snapshot, base, value)
    {
        return Err(RuntimeError::Unsupported(format!(
            "native linux4k guarded pair could not update base register {base}"
        )));
    }
    snapshot.pc = snapshot.pc.checked_add(4).ok_or_else(|| {
        RuntimeError::Unsupported("native linux4k guarded pair PC overflow".to_string())
    })?;
    Ok(())
}

fn emulate_linux4k_guarded_vector_access(
    memory: &mut NativeMappedMemory,
    snapshot: &mut NativeUcontextSnapshot,
    instruction: &bad64::Instruction,
    fault_address: u64,
) -> Result<(), RuntimeError> {
    let [vector_operand, memory_operand] = instruction.operands() else {
        return Err(RuntimeError::Unsupported(format!(
            "native linux4k guarded vector fault does not support operands for {instruction}"
        )));
    };
    let vector_index = bad64_single_vector_index(*vector_operand).ok_or_else(|| {
        RuntimeError::Unsupported(format!(
            "native linux4k guarded vector fault supports one .16b register, got {instruction}"
        ))
    })?;
    let (address, writeback) =
        decode_native_scalar_address(snapshot, *memory_operand).ok_or_else(|| {
            RuntimeError::Unsupported(format!(
                "native linux4k guarded vector fault does not support addressing for {instruction}"
            ))
        })?;
    let access_end = address.checked_add(16).ok_or_else(|| {
        RuntimeError::Unsupported("native linux4k guarded vector access overflow".to_string())
    })?;
    if fault_address < address || fault_address >= access_end {
        return Err(RuntimeError::Unsupported(format!(
            "native linux4k guarded fault address 0x{fault_address:x} is outside {instruction} access 0x{address:x}..0x{access_end:x}"
        )));
    }
    let write = instruction.op() == bad64::Op::ST1;
    if !memory.linux4k_range_allows(address, 16, write) {
        return Err(RuntimeError::Unsupported(format!(
            "native linux4k guarded {instruction} violates guest permissions at 0x{address:x}"
        )));
    }
    match instruction.op() {
        bad64::Op::LD1 => {
            let bytes = memory.read_bytes_raw(address, 16).map_err(|error| {
                RuntimeError::Unsupported(format!(
                    "native linux4k guarded vector load failed at 0x{address:x}: {error}"
                ))
            })?;
            let Some(slot) = snapshot.v.get_mut(vector_index) else {
                return Err(RuntimeError::Unsupported(format!(
                    "native linux4k guarded vector index {vector_index} is out of range"
                )));
            };
            slot.copy_from_slice(&bytes);
        }
        bad64::Op::ST1 => {
            let value = snapshot.v.get(vector_index).ok_or_else(|| {
                RuntimeError::Unsupported(format!(
                    "native linux4k guarded vector index {vector_index} is out of range"
                ))
            })?;
            memory.write_bytes_raw(address, value).map_err(|error| {
                RuntimeError::Unsupported(format!(
                    "native linux4k guarded vector store failed at 0x{address:x}: {error}"
                ))
            })?;
        }
        _ => {
            return Err(RuntimeError::Unsupported(format!(
                "native linux4k guarded vector fault does not support {instruction}"
            )));
        }
    }
    if let Some((base, value)) = writeback
        && !native_snapshot_write_reg(snapshot, base, value)
    {
        return Err(RuntimeError::Unsupported(format!(
            "native linux4k guarded vector fault could not update base register {base}"
        )));
    }
    snapshot.pc = snapshot.pc.checked_add(4).ok_or_else(|| {
        RuntimeError::Unsupported("native linux4k guarded vector PC overflow".to_string())
    })?;
    Ok(())
}

fn exclusive_access_width(op: bad64::Op, transfer_reg: bad64::Reg) -> Option<usize> {
    match op {
        bad64::Op::LDAXRB | bad64::Op::LDXRB | bad64::Op::STLXRB | bad64::Op::STXRB => Some(1),
        bad64::Op::LDAXRH | bad64::Op::LDXRH | bad64::Op::STLXRH | bad64::Op::STXRH => Some(2),
        bad64::Op::LDAXR | bad64::Op::LDXR | bad64::Op::STLXR | bad64::Op::STXR => {
            bad64_transfer_width(transfer_reg)
        }
        _ => None,
    }
}

fn emulate_linux4k_guarded_exclusive_access(
    memory: &mut NativeMappedMemory,
    snapshot: &mut NativeUcontextSnapshot,
    instruction: &bad64::Instruction,
    fault_address: u64,
) -> Result<(), RuntimeError> {
    let load = matches!(
        instruction.op(),
        bad64::Op::LDAXR
            | bad64::Op::LDAXRB
            | bad64::Op::LDAXRH
            | bad64::Op::LDXR
            | bad64::Op::LDXRB
            | bad64::Op::LDXRH
    );
    let acquire = matches!(
        instruction.op(),
        bad64::Op::LDAXR | bad64::Op::LDAXRB | bad64::Op::LDAXRH
    );
    let release = matches!(
        instruction.op(),
        bad64::Op::STLXR | bad64::Op::STLXRB | bad64::Op::STLXRH
    );

    let (status_reg, transfer_reg, memory_operand) = if load {
        let [
            bad64::Operand::Reg {
                reg: transfer_reg,
                arrspec: None,
            },
            memory_operand,
        ] = instruction.operands()
        else {
            return Err(RuntimeError::Unsupported(format!(
                "native linux4k exclusive load does not support operands for {instruction}"
            )));
        };
        (None, *transfer_reg, *memory_operand)
    } else {
        let [
            bad64::Operand::Reg {
                reg: status_reg,
                arrspec: None,
            },
            bad64::Operand::Reg {
                reg: transfer_reg,
                arrspec: None,
            },
            memory_operand,
        ] = instruction.operands()
        else {
            return Err(RuntimeError::Unsupported(format!(
                "native linux4k exclusive store does not support operands for {instruction}"
            )));
        };
        (Some(*status_reg), *transfer_reg, *memory_operand)
    };
    let width = exclusive_access_width(instruction.op(), transfer_reg).ok_or_else(|| {
        RuntimeError::Unsupported(format!(
            "native linux4k exclusive access does not support width for {instruction}"
        ))
    })?;
    let (address, writeback) =
        decode_native_scalar_address(snapshot, memory_operand).ok_or_else(|| {
            RuntimeError::Unsupported(format!(
                "native linux4k exclusive access does not support addressing for {instruction}"
            ))
        })?;
    if writeback.is_some() {
        return Err(RuntimeError::Unsupported(format!(
            "native linux4k exclusive access rejects writeback for {instruction}"
        )));
    }
    let access_end = address.checked_add(width as u64).ok_or_else(|| {
        RuntimeError::Unsupported("native linux4k exclusive access overflow".to_string())
    })?;
    if fault_address < address || fault_address >= access_end {
        return Err(RuntimeError::Unsupported(format!(
            "native linux4k guarded fault address 0x{fault_address:x} is outside {instruction} access 0x{address:x}..0x{access_end:x}"
        )));
    }
    if !memory.linux4k_range_allows(address, width, !load) {
        return Err(RuntimeError::Unsupported(format!(
            "native linux4k guarded {instruction} violates guest permissions at 0x{address:x}"
        )));
    }

    if load {
        let value = memory
            .exclusive_load(address, width, acquire)
            .map_err(|error| {
                RuntimeError::Unsupported(format!(
                    "native linux4k exclusive load failed at 0x{address:x}: {error}"
                ))
            })?;
        if !native_snapshot_write_reg(snapshot, transfer_reg, value) {
            return Err(RuntimeError::Unsupported(format!(
                "native linux4k exclusive load could not write {transfer_reg}"
            )));
        }
    } else {
        let value = native_snapshot_read_reg(snapshot, transfer_reg).ok_or_else(|| {
            RuntimeError::Unsupported(format!(
                "native linux4k exclusive store could not read {transfer_reg}"
            ))
        })?;
        let stored = memory
            .exclusive_store(address, width, value, release)
            .map_err(|error| {
                RuntimeError::Unsupported(format!(
                    "native linux4k exclusive store failed at 0x{address:x}: {error}"
                ))
            })?;
        let status_reg = status_reg.ok_or_else(|| {
            RuntimeError::Unsupported(format!(
                "native linux4k exclusive store lacks status register for {instruction}"
            ))
        })?;
        if !native_snapshot_write_reg(snapshot, status_reg, u64::from(!stored)) {
            return Err(RuntimeError::Unsupported(format!(
                "native linux4k exclusive store could not write {status_reg}"
            )));
        }
    }
    snapshot.pc = snapshot.pc.checked_add(4).ok_or_else(|| {
        RuntimeError::Unsupported("native linux4k exclusive PC overflow".to_string())
    })?;
    Ok(())
}

fn emulate_linux4k_guarded_fault(
    memory: &mut NativeMappedMemory,
    snapshot: &mut NativeUcontextSnapshot,
) -> Result<(), RuntimeError> {
    let fault_address = if snapshot.fault_address != 0 {
        snapshot.fault_address
    } else {
        snapshot.far
    };
    if !memory.linux4k_address_is_guarded(fault_address) {
        return Err(RuntimeError::Unsupported(format!(
            "native Darwin signal {} at 0x{fault_address:x} was not a guarded linux4k page (pc=0x{:x} sp=0x{:x} lr=0x{:x} x16=0x{:x} x17=0x{:x} x18=0x{:x} esr=0x{:x})",
            snapshot.signal,
            snapshot.pc,
            snapshot.sp,
            snapshot.x[30],
            snapshot.x[16],
            snapshot.x[17],
            snapshot.x[18],
            snapshot.esr
        )));
    }
    let word = memory.read_u32(snapshot.pc)?;
    let instruction = bad64::decode(word, snapshot.pc).map_err(|error| {
        RuntimeError::Unsupported(format!(
            "native linux4k guarded fault could not decode instruction 0x{word:08x} at 0x{:x}: {error}",
            snapshot.pc
        ))
    })?;
    if std::env::var_os("CARRICK_NATIVE_TRACE_SYSCALLS").is_some() {
        child_write_stderr(
            format!(
                "native trace pid={} guarded pc=0x{:x} addr=0x{fault_address:x} esr=0x{:x} word=0x{word:08x} instruction={instruction}\n",
                unsafe { libc::getpid() },
                snapshot.pc,
                snapshot.esr
            )
            .as_bytes(),
        );
    }
    if matches!(
        instruction.op(),
        bad64::Op::LDAXR
            | bad64::Op::LDAXRB
            | bad64::Op::LDAXRH
            | bad64::Op::LDXR
            | bad64::Op::LDXRB
            | bad64::Op::LDXRH
            | bad64::Op::STLXR
            | bad64::Op::STLXRB
            | bad64::Op::STLXRH
            | bad64::Op::STXR
            | bad64::Op::STXRB
            | bad64::Op::STXRH
    ) {
        return emulate_linux4k_guarded_exclusive_access(
            memory,
            snapshot,
            &instruction,
            fault_address,
        );
    }
    if matches!(instruction.op(), bad64::Op::LD1 | bad64::Op::ST1) {
        return emulate_linux4k_guarded_vector_access(
            memory,
            snapshot,
            &instruction,
            fault_address,
        );
    }
    if matches!(
        instruction.op(),
        bad64::Op::LDP | bad64::Op::LDNP | bad64::Op::LDPSW | bad64::Op::STP | bad64::Op::STNP
    ) {
        return emulate_linux4k_guarded_pair_access(memory, snapshot, &instruction, fault_address);
    }
    if let [
        bad64::Operand::Reg {
            reg: vector_reg,
            arrspec: None,
        },
        memory_operand,
    ] = instruction.operands()
        && bad64_vector_index_and_width(*vector_reg).is_some()
    {
        return emulate_linux4k_guarded_vector_register_access(
            memory,
            snapshot,
            &instruction,
            *vector_reg,
            *memory_operand,
            fault_address,
        );
    }
    let [transfer_operand, memory_operand] = instruction.operands() else {
        return Err(RuntimeError::Unsupported(format!(
            "native linux4k guarded fault does not support operands for {instruction} at 0x{:x}",
            snapshot.pc
        )));
    };
    let bad64::Operand::Reg {
        reg: transfer_reg,
        arrspec: None,
    } = *transfer_operand
    else {
        return Err(RuntimeError::Unsupported(format!(
            "native linux4k guarded fault requires a scalar GPR transfer for {instruction} at 0x{:x}",
            snapshot.pc
        )));
    };
    let transfer_width = bad64_transfer_width(transfer_reg).ok_or_else(|| {
        RuntimeError::Unsupported(format!(
            "native linux4k guarded fault does not support transfer register {transfer_reg} for {instruction}"
        ))
    })?;
    let access =
        decode_native_scalar_access(instruction.op(), transfer_width).ok_or_else(|| {
            RuntimeError::Unsupported(format!(
                "native linux4k guarded fault does not support instruction {instruction} at 0x{:x}",
                snapshot.pc
            ))
        })?;
    let (address, writeback) = decode_native_scalar_address(snapshot, *memory_operand)
        .ok_or_else(|| {
            RuntimeError::Unsupported(format!(
                "native linux4k guarded fault does not support addressing for {instruction} at 0x{:x}",
                snapshot.pc
            ))
        })?;
    let access_end = address.checked_add(access.width as u64).ok_or_else(|| {
        RuntimeError::Unsupported("native linux4k guarded access overflow".to_string())
    })?;
    if fault_address < address || fault_address >= access_end {
        return Err(RuntimeError::Unsupported(format!(
            "native linux4k guarded fault address 0x{fault_address:x} is outside {instruction} access 0x{address:x}..0x{access_end:x}"
        )));
    }
    let write = matches!(access.kind, NativeScalarAccessKind::Store);
    if !memory.linux4k_range_allows(address, access.width, write) {
        return Err(RuntimeError::Unsupported(format!(
            "native linux4k guarded {instruction} violates guest permissions at 0x{address:x}"
        )));
    }
    if let Some((base, _)) = writeback
        && bad64_gpr_index(base).map(|(index, _)| index)
            == bad64_gpr_index(transfer_reg).map(|(index, _)| index)
    {
        return Err(RuntimeError::Unsupported(format!(
            "native linux4k guarded fault rejects overlapping writeback for {instruction}"
        )));
    }

    match access.kind {
        NativeScalarAccessKind::Load { sign_extend } => {
            let bytes = memory
                .read_bytes_raw(address, access.width)
                .map_err(|error| {
                    RuntimeError::Unsupported(format!(
                        "native linux4k guarded load failed at 0x{address:x}: {error}"
                    ))
                })?;
            let value = native_load_value(&bytes, sign_extend, access.destination_width);
            if !native_snapshot_write_reg(snapshot, transfer_reg, value) {
                return Err(RuntimeError::Unsupported(format!(
                    "native linux4k guarded fault could not write {transfer_reg}"
                )));
            }
        }
        NativeScalarAccessKind::Store => {
            let value = native_snapshot_read_reg(snapshot, transfer_reg).ok_or_else(|| {
                RuntimeError::Unsupported(format!(
                    "native linux4k guarded fault could not read {transfer_reg}"
                ))
            })?;
            memory
                .write_bytes_raw(address, &value.to_le_bytes()[..access.width])
                .map_err(|error| {
                    RuntimeError::Unsupported(format!(
                        "native linux4k guarded store failed at 0x{address:x}: {error}"
                    ))
                })?;
        }
    }
    if let Some((base, value)) = writeback
        && !native_snapshot_write_reg(snapshot, base, value)
    {
        return Err(RuntimeError::Unsupported(format!(
            "native linux4k guarded fault could not update base register {base}"
        )));
    }
    snapshot.pc = snapshot.pc.checked_add(4).ok_or_else(|| {
        RuntimeError::Unsupported("native linux4k guarded PC overflow".to_string())
    })?;
    Ok(())
}

fn decode_native_trap(memory: &NativeMappedMemory, pc: u64) -> Result<NativeTrap, RuntimeError> {
    if let Some(trap) = decode_trap_instruction(memory.read_u32(pc)?, pc)? {
        return Ok(trap);
    }
    if pc >= 4
        && let Some(trap) = decode_trap_instruction(memory.read_u32(pc - 4)?, pc - 4)?
    {
        return Ok(trap);
    }
    Err(RuntimeError::Unsupported(format!(
        "native Darwin SIGTRAP at non-syscall PC 0x{pc:x}"
    )))
}

fn decode_trap_instruction(word: u32, pc: u64) -> Result<Option<NativeTrap>, RuntimeError> {
    if (word & 0xffe0_001f) != 0xd420_0000 {
        return Ok(None);
    }
    let imm = ((word >> 5) & 0xffff) as u16;
    let resume_pc = pc
        .checked_add(4)
        .ok_or_else(|| RuntimeError::Unsupported("native Darwin trap PC overflow".to_string()))?;
    if imm == BRK_NATIVE_SYSCALL_IMM {
        return Ok(Some(NativeTrap::Syscall { resume_pc }));
    }
    if (BRK_NATIVE_MRS_TPIDR_IMM_BASE..BRK_NATIVE_MRS_TPIDR_IMM_BASE + 32).contains(&imm) {
        return Ok(Some(NativeTrap::ReadTpidr {
            rt: u32::from(imm - BRK_NATIVE_MRS_TPIDR_IMM_BASE),
            resume_pc,
        }));
    }
    if (BRK_NATIVE_MSR_TPIDR_IMM_BASE..BRK_NATIVE_MSR_TPIDR_IMM_BASE + 32).contains(&imm) {
        return Ok(Some(NativeTrap::WriteTpidr {
            rt: u32::from(imm - BRK_NATIVE_MSR_TPIDR_IMM_BASE),
            resume_pc,
        }));
    }
    if (BRK_NATIVE_MRS_CTR_IMM_BASE..BRK_NATIVE_MRS_CTR_IMM_BASE + 32).contains(&imm) {
        return Ok(Some(NativeTrap::ReadConstant {
            rt: u32::from(imm - BRK_NATIVE_MRS_CTR_IMM_BASE),
            value: NATIVE_CTR_EL0,
            resume_pc,
        }));
    }
    if (BRK_NATIVE_MRS_DCZID_IMM_BASE..BRK_NATIVE_MRS_DCZID_IMM_BASE + 32).contains(&imm) {
        return Ok(Some(NativeTrap::ReadConstant {
            rt: u32::from(imm - BRK_NATIVE_MRS_DCZID_IMM_BASE),
            value: NATIVE_DCZID_EL0,
            resume_pc,
        }));
    }
    if (BRK_NATIVE_DC_ZVA_IMM_BASE..BRK_NATIVE_DC_ZVA_IMM_BASE + 32).contains(&imm) {
        return Ok(Some(NativeTrap::DcZva {
            rt: u32::from(imm - BRK_NATIVE_DC_ZVA_IMM_BASE),
            resume_pc,
        }));
    }
    Ok(None)
}

struct NativeMappedMemory {
    regions: Vec<NativeMappedRegion>,
    resume_pad_pages: Vec<u64>,
    protections: MemoryProtections,
    native_page_protections: BTreeMap<u64, u64>,
    linux4k_page_protections: BTreeMap<u64, [u64; 4]>,
    exclusive_reservation: Option<NativeExclusiveReservation>,
    host_page_size: u64,
    linux_page_size: u64,
}

#[derive(Clone, Copy)]
struct NativeExclusiveReservation {
    address: u64,
    width: usize,
    observed: u64,
}

struct NativeMappedRegion {
    start: u64,
    end: u64,
    host_protects: bool,
    shared_futex: bool,
    guest_writable: bool,
    default_prot: u64,
}

fn map_native_resume_pad_pages(
    image: &AddressSpace,
    host_page_size: u64,
) -> Result<Vec<u64>, RuntimeError> {
    if host_page_size == 0 || !host_page_size.is_power_of_two() {
        return Err(RuntimeError::Unsupported(format!(
            "native Darwin resume-pad page size is invalid: {host_page_size}"
        )));
    }

    let sigreturn_range = (
        NATIVE_DARWIN_SIGRETURN_TRAMPOLINE_BASE,
        NATIVE_DARWIN_SIGRETURN_TRAMPOLINE_BASE
            + carrick_mem::memory::LINUX_SIGRETURN_TRAMPOLINE_SIZE,
    );
    let mut occupied: Vec<(u64, u64)> = image
        .regions()
        .iter()
        .map(|region| (region.start, region.end))
        .collect();
    occupied.push(sigreturn_range);

    let mut buckets = BTreeSet::new();
    for (start, end) in image
        .regions()
        .iter()
        .filter(|region| region.perms.execute)
        .map(|region| (region.start, region.end))
        .chain(std::iter::once(sigreturn_range))
    {
        if start >= end {
            continue;
        }
        let mut bucket = start & !(NATIVE_DARWIN_RESUME_BUCKET_SIZE - 1);
        let last_bucket = (end - 1) & !(NATIVE_DARWIN_RESUME_BUCKET_SIZE - 1);
        loop {
            buckets.insert(bucket);
            if bucket == last_bucket {
                break;
            }
            bucket = bucket
                .checked_add(NATIVE_DARWIN_RESUME_BUCKET_SIZE)
                .ok_or_else(|| {
                    RuntimeError::Unsupported(
                        "native Darwin resume-pad bucket overflow".to_string(),
                    )
                })?;
        }
    }

    let mut pages = Vec::with_capacity(buckets.len());
    for bucket in buckets {
        let bucket_end = bucket
            .checked_add(NATIVE_DARWIN_RESUME_BUCKET_SIZE)
            .ok_or_else(|| {
                RuntimeError::Unsupported("native Darwin resume-pad range overflow".to_string())
            })?;
        let mut candidate = bucket_end.checked_sub(host_page_size).ok_or_else(|| {
            RuntimeError::Unsupported("native Darwin resume-pad address underflow".to_string())
        })?;
        let selected = loop {
            let candidate_end = candidate + host_page_size;
            let overlaps = occupied
                .iter()
                .any(|(start, end)| candidate < *end && *start < candidate_end);
            if !overlaps {
                break candidate;
            }
            if candidate < bucket + host_page_size {
                return Err(RuntimeError::Unsupported(format!(
                    "native Darwin executable bucket 0x{bucket:x} has no resume-pad page"
                )));
            }
            candidate -= host_page_size;
        };

        map_anonymous_region(selected, host_page_size, false)?;
        let page_size = usize::try_from(host_page_size).map_err(|_| {
            RuntimeError::Unsupported("native Darwin resume-pad page is too large".to_string())
        })?;
        let selected_usize = usize::try_from(selected).map_err(|_| {
            RuntimeError::Unsupported("native Darwin resume-pad address is too large".to_string())
        })?;
        let rc = unsafe {
            carrick_native_register_resume_page(
                bucket,
                selected_usize as *mut libc::c_void,
                page_size,
            )
        };
        if rc != 0 {
            unsafe {
                libc::munmap(selected_usize as *mut libc::c_void, page_size);
            }
            return Err(last_io_error("register native Darwin resume-pad page"));
        }
        pages.push(selected);
        occupied.push((selected, selected + host_page_size));
    }

    let pre_mmap = NATIVE_DARWIN_MMAP_BASE
        .checked_sub(host_page_size)
        .ok_or_else(|| {
            RuntimeError::Unsupported("native Darwin pre-mmap pad underflow".to_string())
        })?;
    let pre_mmap_end = pre_mmap + host_page_size;
    if occupied
        .iter()
        .any(|(start, end)| pre_mmap < *end && *start < pre_mmap_end)
    {
        return Err(RuntimeError::Unsupported(format!(
            "native Darwin pre-mmap resume pad overlaps 0x{pre_mmap:x}..0x{pre_mmap_end:x}"
        )));
    }
    map_anonymous_region(pre_mmap, host_page_size, false)?;
    let page_size = usize::try_from(host_page_size).map_err(|_| {
        RuntimeError::Unsupported("native Darwin resume-pad page is too large".to_string())
    })?;
    let pre_mmap_usize = usize::try_from(pre_mmap).map_err(|_| {
        RuntimeError::Unsupported("native Darwin pre-mmap pad address is too large".to_string())
    })?;
    let rc = unsafe {
        carrick_native_register_resume_page(
            pre_mmap & !(NATIVE_DARWIN_RESUME_BUCKET_SIZE - 1),
            pre_mmap_usize as *mut libc::c_void,
            page_size,
        )
    };
    if rc != 0 {
        unsafe {
            libc::munmap(pre_mmap_usize as *mut libc::c_void, page_size);
        }
        return Err(last_io_error(
            "register native Darwin pre-mmap resume-pad page",
        ));
    }
    pages.push(pre_mmap);
    Ok(pages)
}

fn native_region_linux_prot(read: bool, write: bool, exec: bool) -> u64 {
    let mut prot = 0;
    if read {
        prot |= crate::linux_abi::LINUX_PROT_READ;
    }
    if write {
        prot |= crate::linux_abi::LINUX_PROT_WRITE;
    }
    if exec {
        prot |= crate::linux_abi::LINUX_PROT_EXEC;
    }
    prot
}

impl NativeMappedMemory {
    fn map(
        image: &AddressSpace,
        layout: MemoryLayout,
        host_page_size: u64,
        linux_page_size: u64,
    ) -> Result<Self, RuntimeError> {
        if let Some(region) = image
            .regions()
            .iter()
            .find(|region| region.start < NATIVE_DARWIN_HARD_PAGEZERO_END)
        {
            return Err(RuntimeError::Unsupported(format!(
                "native Darwin cannot directly map guest region 0x{:x}..0x{:x} below 0x{NATIVE_DARWIN_HARD_PAGEZERO_END:x}: arm64 Mach-O enforces a hard 4 GiB __PAGEZERO; use a PIE/ET_DYN image or an address-virtualizing backend",
                region.start, region.end
            )));
        }
        unsafe { carrick_native_reset_resume_pads() };
        let mut regions = Vec::new();
        for region in image.regions() {
            map_region(region)?;
            regions.push(NativeMappedRegion {
                start: region.start,
                end: region.end,
                host_protects: true,
                shared_futex: false,
                guest_writable: region.perms.write,
                default_prot: native_region_linux_prot(
                    region.perms.read,
                    region.perms.write,
                    region.perms.execute,
                ),
            });
        }
        let resume_pad_pages = map_native_resume_pad_pages(image, host_page_size)?;
        map_bytes_region(
            NATIVE_DARWIN_SIGRETURN_TRAMPOLINE_BASE,
            carrick_mem::memory::LINUX_SIGRETURN_TRAMPOLINE_SIZE,
            &carrick_mem::memory::sigreturn_trampoline_bytes(),
            libc::PROT_READ | libc::PROT_EXEC,
            true,
        )?;
        regions.push(NativeMappedRegion {
            start: NATIVE_DARWIN_SIGRETURN_TRAMPOLINE_BASE,
            end: NATIVE_DARWIN_SIGRETURN_TRAMPOLINE_BASE
                + carrick_mem::memory::LINUX_SIGRETURN_TRAMPOLINE_SIZE,
            host_protects: true,
            shared_futex: false,
            guest_writable: false,
            default_prot: crate::linux_abi::LINUX_PROT_READ | crate::linux_abi::LINUX_PROT_EXEC,
        });
        map_anonymous_region(layout.heap_base, layout.heap_size, false)?;
        regions.push(NativeMappedRegion {
            start: layout.heap_base,
            end: checked_add_u64(layout.heap_base, layout.heap_size, "native heap end")?,
            host_protects: false,
            shared_futex: false,
            guest_writable: true,
            default_prot: crate::linux_abi::LINUX_PROT_READ | crate::linux_abi::LINUX_PROT_WRITE,
        });
        map_anonymous_region(layout.mmap_base, layout.mmap_size, false)?;
        regions.push(NativeMappedRegion {
            start: layout.mmap_base,
            end: checked_add_u64(layout.mmap_base, layout.mmap_size, "native mmap arena end")?,
            host_protects: true,
            shared_futex: false,
            guest_writable: true,
            default_prot: if linux_page_size == host_page_size {
                crate::linux_abi::LINUX_PROT_READ | crate::linux_abi::LINUX_PROT_WRITE
            } else {
                0
            },
        });
        map_anonymous_region(
            crate::memory::LINUX_SHARED_FILE_BASE,
            crate::memory::LINUX_SHARED_FILE_SIZE,
            true,
        )?;
        regions.push(NativeMappedRegion {
            start: crate::memory::LINUX_SHARED_FILE_BASE,
            end: checked_add_u64(
                crate::memory::LINUX_SHARED_FILE_BASE,
                crate::memory::LINUX_SHARED_FILE_SIZE,
                "native shared aperture end",
            )?,
            host_protects: false,
            shared_futex: true,
            guest_writable: true,
            default_prot: crate::linux_abi::LINUX_PROT_READ | crate::linux_abi::LINUX_PROT_WRITE,
        });
        map_anonymous_region(
            crate::memory::LINUX_PRIVATE_OVERLAY_BASE,
            crate::memory::LINUX_PRIVATE_OVERLAY_SIZE,
            false,
        )?;
        regions.push(NativeMappedRegion {
            start: crate::memory::LINUX_PRIVATE_OVERLAY_BASE,
            end: checked_add_u64(
                crate::memory::LINUX_PRIVATE_OVERLAY_BASE,
                crate::memory::LINUX_PRIVATE_OVERLAY_SIZE,
                "native private overlay aperture end",
            )?,
            host_protects: false,
            shared_futex: false,
            guest_writable: true,
            default_prot: crate::linux_abi::LINUX_PROT_READ | crate::linux_abi::LINUX_PROT_WRITE,
        });
        Ok(Self {
            regions,
            resume_pad_pages,
            protections: MemoryProtections::default(),
            native_page_protections: BTreeMap::new(),
            linux4k_page_protections: BTreeMap::new(),
            exclusive_reservation: None,
            host_page_size,
            linux_page_size,
        })
    }

    fn set_fork_inheritance(&self, share: bool) {
        let trace = std::env::var_os("CARRICK_NATIVE_TRACE_SYSCALLS").is_some();
        for region in &self.regions {
            if region.shared_futex || !region.guest_writable {
                continue;
            }
            let Ok(start) = usize::try_from(region.start) else {
                continue;
            };
            let Ok(len) = usize::try_from(region.end.saturating_sub(region.start)) else {
                continue;
            };
            let changed =
                set_native_region_fork_inheritance(start as *mut libc::c_void, len, share);
            if trace {
                child_write_stderr(
                    format!(
                        "native trace pid={} fork-inherit share={} start=0x{:x} end=0x{:x} changed={}\n",
                        unsafe { libc::getpid() },
                        share,
                        region.start,
                        region.end,
                        changed
                    )
                    .as_bytes(),
                );
            }
        }
    }

    fn replace_image(
        &mut self,
        image: &AddressSpace,
        relative_relocations: &[NativeRelativeRelocation],
        plan: &ExecutionPlan,
    ) -> Result<(), RuntimeError> {
        let mut ranges: Vec<(u64, u64)> = self
            .regions
            .iter()
            .map(|region| (region.start, region.end))
            .collect();
        ranges.sort_unstable_by_key(|range| range.0);
        let mut merged: Vec<(u64, u64)> = Vec::with_capacity(ranges.len());
        for (start, end) in ranges {
            if let Some(last) = merged.last_mut()
                && start <= last.1
            {
                last.1 = last.1.max(end);
                continue;
            }
            merged.push((start, end));
        }
        for (start, end) in merged {
            let len = usize::try_from(end.saturating_sub(start)).map_err(|_| {
                RuntimeError::Unsupported(format!(
                    "native Darwin execve unmap range too large: 0x{start:x}..0x{end:x}"
                ))
            })?;
            let address = usize::try_from(start).map_err(|_| {
                RuntimeError::Unsupported(format!(
                    "native Darwin execve unmap address too large: 0x{start:x}"
                ))
            })? as *mut libc::c_void;
            if len != 0 && unsafe { libc::munmap(address, len) } != 0 {
                return Err(last_io_error(&format!(
                    "munmap native Darwin execve range 0x{start:x}..0x{end:x}"
                )));
            }
        }
        for page in &self.resume_pad_pages {
            let address = usize::try_from(*page).map_err(|_| {
                RuntimeError::Unsupported(format!(
                    "native Darwin resume-pad address too large: 0x{page:x}"
                ))
            })? as *mut libc::c_void;
            let len = usize::try_from(self.host_page_size).map_err(|_| {
                RuntimeError::Unsupported(
                    "native Darwin resume-pad length is too large".to_string(),
                )
            })?;
            if unsafe { libc::munmap(address, len) } != 0 {
                return Err(last_io_error(&format!(
                    "munmap native Darwin resume-pad page 0x{page:x}"
                )));
            }
        }

        let mut replacement = Self::map(
            image,
            native_memory_layout(),
            plan.page_geometry.host_page_size,
            plan.page_geometry.linux_page_size,
        )?;
        apply_native_relative_relocations(&mut replacement, relative_relocations)?;
        *self = replacement;
        Ok(())
    }

    fn region_contains(&self, address: u64, length: usize) -> bool {
        let Ok(length) = u64::try_from(length) else {
            return false;
        };
        let Some(end) = address.checked_add(length) else {
            return false;
        };
        self.regions
            .iter()
            .any(|region| address >= region.start && end <= region.end)
    }

    fn host_protected_overlaps(
        &self,
        address: u64,
        length: usize,
    ) -> impl Iterator<Item = (u64, u64)> + '_ {
        let end = address.saturating_add(length as u64);
        let linux4k = self.uses_linux4k_subpages();
        self.regions
            .iter()
            .filter(move |region| {
                (linux4k || region.host_protects) && address < region.end && region.start < end
            })
            .map(move |region| (address.max(region.start), end.min(region.end)))
    }

    fn host_page_range(&self, start: u64, end: u64) -> Result<(u64, usize), MemoryError> {
        let page_size = self.host_page_size;
        let page_start = start & !(page_size - 1);
        let page_end = end
            .checked_add(page_size - 1)
            .map(|value| value & !(page_size - 1))
            .ok_or(MemoryError::OutOfBounds {
                address: start,
                length: usize::try_from(end.saturating_sub(start)).unwrap_or(usize::MAX),
            })?;
        let len = usize::try_from(page_end.saturating_sub(page_start)).map_err(|_| {
            MemoryError::OutOfBounds {
                address: start,
                length: usize::MAX,
            }
        })?;
        Ok((page_start, len))
    }

    fn uses_linux4k_subpages(&self) -> bool {
        self.host_page_size == 16 * 1024 && self.linux_page_size == 4 * 1024
    }

    fn default_linux_prot_at(&self, address: u64) -> u64 {
        self.regions
            .iter()
            .rev()
            .find(|region| address >= region.start && address < region.end)
            .map_or(0, |region| region.default_prot)
    }

    fn linux4k_host_page_protections(&self, page_start: u64) -> [u64; 4] {
        self.linux4k_page_protections
            .get(&page_start)
            .copied()
            .unwrap_or_else(|| {
                std::array::from_fn(|index| {
                    self.default_linux_prot_at(
                        page_start.saturating_add(index as u64 * self.linux_page_size),
                    )
                })
            })
    }

    fn classify_linux4k_host_page(&self, protections: [u64; 4]) -> HostPageState {
        let subpages = protections.map(|prot| {
            SubpageState::new(
                PageBacking::Anonymous,
                PagePerms {
                    read: prot & crate::linux_abi::LINUX_PROT_READ != 0,
                    write: prot & crate::linux_abi::LINUX_PROT_WRITE != 0,
                    exec: prot & crate::linux_abi::LINUX_PROT_EXEC != 0,
                },
            )
        });
        classify_host_page_state(
            crate::page_profile::PageGeometry {
                host_page_size: self.host_page_size,
                linux_page_size: self.linux_page_size,
                native_profile: Some(carrick_spec::NativePageProfile::Linux4kOn16k),
            },
            subpages,
        )
    }

    fn linux4k_range_allows(&self, address: u64, len: usize, write: bool) -> bool {
        if !self.uses_linux4k_subpages() || len == 0 {
            return false;
        }
        let Some(end) = address.checked_add(len as u64) else {
            return false;
        };
        let required = if write {
            crate::linux_abi::LINUX_PROT_WRITE
        } else {
            crate::linux_abi::LINUX_PROT_READ
        };
        let mut cursor = address;
        while cursor < end {
            let host_page = cursor & !(self.host_page_size - 1);
            let subpage = ((cursor - host_page) / self.linux_page_size) as usize;
            let protections = self.linux4k_host_page_protections(host_page);
            if protections
                .get(subpage)
                .is_none_or(|prot| prot & required == 0)
            {
                return false;
            }
            let next = (cursor & !(self.linux_page_size - 1)).saturating_add(self.linux_page_size);
            cursor = next.min(end);
        }
        true
    }

    fn invalidate_exclusive_range(&mut self, address: u64, len: usize) {
        let Some(reservation) = self.exclusive_reservation else {
            return;
        };
        let Some(end) = address.checked_add(len as u64) else {
            self.exclusive_reservation = None;
            return;
        };
        let Some(reservation_end) = reservation.address.checked_add(reservation.width as u64)
        else {
            self.exclusive_reservation = None;
            return;
        };
        if address < reservation_end && reservation.address < end {
            self.exclusive_reservation = None;
        }
    }

    fn exclusive_load(
        &mut self,
        address: u64,
        width: usize,
        acquire: bool,
    ) -> Result<u64, MemoryError> {
        if !address.is_multiple_of(width as u64) || !self.region_contains(address, width) {
            return Err(MemoryError::OutOfBounds {
                address,
                length: width,
            });
        }
        let changed = self.prepare_temporary_host_access(address, width, false)?;
        let ptr = usize::try_from(address).map_err(|_| MemoryError::OutOfBounds {
            address,
            length: width,
        })? as *mut u8;
        let ordering = if acquire {
            std::sync::atomic::Ordering::Acquire
        } else {
            std::sync::atomic::Ordering::Relaxed
        };
        let observed = unsafe {
            match width {
                1 => u64::from((&*ptr.cast::<std::sync::atomic::AtomicU8>()).load(ordering)),
                2 => u64::from((&*ptr.cast::<std::sync::atomic::AtomicU16>()).load(ordering)),
                4 => u64::from((&*ptr.cast::<std::sync::atomic::AtomicU32>()).load(ordering)),
                8 => (&*ptr.cast::<std::sync::atomic::AtomicU64>()).load(ordering),
                _ => return Err(MemoryError::Unsupported),
            }
        };
        self.restore_temporary_host_access(&changed, address, width)?;
        self.exclusive_reservation = Some(NativeExclusiveReservation {
            address,
            width,
            observed,
        });
        Ok(observed)
    }

    fn exclusive_store(
        &mut self,
        address: u64,
        width: usize,
        value: u64,
        release: bool,
    ) -> Result<bool, MemoryError> {
        let Some(reservation) = self.exclusive_reservation.take() else {
            return Ok(false);
        };
        if reservation.address != address || reservation.width != width {
            return Ok(false);
        }
        let changed = self.prepare_temporary_host_access(address, width, true)?;
        let ptr = usize::try_from(address).map_err(|_| MemoryError::OutOfBounds {
            address,
            length: width,
        })? as *mut u8;
        let success = if release {
            std::sync::atomic::Ordering::Release
        } else {
            std::sync::atomic::Ordering::Relaxed
        };
        let stored = unsafe {
            match width {
                1 => (&*ptr.cast::<std::sync::atomic::AtomicU8>())
                    .compare_exchange(
                        reservation.observed as u8,
                        value as u8,
                        success,
                        std::sync::atomic::Ordering::Relaxed,
                    )
                    .is_ok(),
                2 => (&*ptr.cast::<std::sync::atomic::AtomicU16>())
                    .compare_exchange(
                        reservation.observed as u16,
                        value as u16,
                        success,
                        std::sync::atomic::Ordering::Relaxed,
                    )
                    .is_ok(),
                4 => (&*ptr.cast::<std::sync::atomic::AtomicU32>())
                    .compare_exchange(
                        reservation.observed as u32,
                        value as u32,
                        success,
                        std::sync::atomic::Ordering::Relaxed,
                    )
                    .is_ok(),
                8 => (&*ptr.cast::<std::sync::atomic::AtomicU64>())
                    .compare_exchange(
                        reservation.observed,
                        value,
                        success,
                        std::sync::atomic::Ordering::Relaxed,
                    )
                    .is_ok(),
                _ => return Err(MemoryError::Unsupported),
            }
        };
        self.restore_temporary_host_access(&changed, address, width)?;
        Ok(stored)
    }

    fn linux4k_address_is_guarded(&self, address: u64) -> bool {
        if !self.uses_linux4k_subpages() {
            return false;
        }
        let host_page = address & !(self.host_page_size - 1);
        matches!(
            self.classify_linux4k_host_page(self.linux4k_host_page_protections(host_page)),
            HostPageState::MixedGuarded(_)
                | HostPageState::Composed16k
                | HostPageState::Unsupported(MixedPageReason::ExecutableMixedPage)
        )
    }

    fn native_host_prot_for_page(&self, page_start: u64) -> libc::c_int {
        if !self.uses_linux4k_subpages() {
            let prot = self
                .native_page_protections
                .get(&page_start)
                .copied()
                .unwrap_or_else(|| self.default_linux_prot_at(page_start));
            return linux_prot_to_native(prot);
        }
        let protections = self.linux4k_host_page_protections(page_start);
        match self.classify_linux4k_host_page(protections) {
            HostPageState::Uniform16k => linux_prot_to_native(protections[0]),
            HostPageState::MixedGuarded(_) | HostPageState::Composed16k => libc::PROT_NONE,
            HostPageState::Unsupported(_) => libc::PROT_NONE,
        }
    }

    fn mprotect_host_page(
        &self,
        page_start: u64,
        host_prot: libc::c_int,
        operation_address: u64,
        operation_len: usize,
    ) -> Result<(), MemoryError> {
        let ptr = usize::try_from(page_start).map_err(|_| MemoryError::OutOfBounds {
            address: operation_address,
            length: operation_len,
        })? as *mut libc::c_void;
        let host_page_len =
            usize::try_from(self.host_page_size).map_err(|_| MemoryError::OutOfBounds {
                address: operation_address,
                length: operation_len,
            })?;
        if unsafe { libc::mprotect(ptr, host_page_len, host_prot) } != 0 {
            return Err(MemoryError::HostMap(format!(
                "mprotect native Darwin host page 0x{page_start:x}: {}",
                std::io::Error::last_os_error()
            )));
        }
        Ok(())
    }

    fn prepare_temporary_host_access(
        &self,
        address: u64,
        len: usize,
        write: bool,
    ) -> Result<Vec<(u64, libc::c_int)>, MemoryError> {
        if len == 0 {
            return Ok(Vec::new());
        }
        let mut changed = Vec::new();
        let required = if write {
            libc::PROT_READ | libc::PROT_WRITE
        } else {
            libc::PROT_READ
        };
        for (start, end) in self.host_protected_overlaps(address, len) {
            let (page_start, page_len) = self.host_page_range(start, end)?;
            let page_end = page_start.saturating_add(page_len as u64);
            let mut page = page_start;
            while page < page_end {
                let restore = self.native_host_prot_for_page(page);
                if restore & required != required {
                    self.mprotect_host_page(page, required, address, len)?;
                    changed.push((page, restore));
                }
                page = page.saturating_add(self.host_page_size);
            }
        }
        Ok(changed)
    }

    fn restore_temporary_host_access(
        &self,
        changed: &[(u64, libc::c_int)],
        address: u64,
        len: usize,
    ) -> Result<(), MemoryError> {
        for (page_start, restore) in changed.iter().rev() {
            self.mprotect_host_page(*page_start, *restore, address, len)?;
        }
        Ok(())
    }

    fn protect_linux4k_range(
        &mut self,
        address: u64,
        len: usize,
        prot: u64,
    ) -> Result<(), MemoryError> {
        if !address.is_multiple_of(self.linux_page_size)
            || !(len as u64).is_multiple_of(self.linux_page_size)
        {
            return Err(MemoryError::Unsupported);
        }
        let end = address
            .checked_add(len as u64)
            .ok_or(MemoryError::OutOfBounds {
                address,
                length: len,
            })?;
        let first_host_page = address & !(self.host_page_size - 1);
        let last_host_page = end
            .checked_add(self.host_page_size - 1)
            .map(|value| value & !(self.host_page_size - 1))
            .ok_or(MemoryError::OutOfBounds {
                address,
                length: len,
            })?;
        let mut plan = Vec::new();
        let mut page_start = first_host_page;
        while page_start < last_host_page {
            let mut protections = self.linux4k_host_page_protections(page_start);
            for (index, subpage_prot) in protections.iter_mut().enumerate() {
                let subpage_start = page_start.saturating_add(index as u64 * self.linux_page_size);
                let subpage_end = subpage_start.saturating_add(self.linux_page_size);
                if address < subpage_end && subpage_start < end {
                    *subpage_prot = prot;
                }
            }
            let state = self.classify_linux4k_host_page(protections);
            let state = match state {
                HostPageState::Unsupported(MixedPageReason::ExecutableMixedPage) => {
                    HostPageState::MixedGuarded(MixedPageReason::ExecutableMixedPage)
                }
                HostPageState::Unsupported(_) => return Err(MemoryError::Unsupported),
                state => state,
            };
            plan.push((page_start, protections, state));
            page_start = page_start.saturating_add(self.host_page_size);
        }

        for (page_start, protections, state) in plan {
            let host_prot = match state {
                HostPageState::Uniform16k => linux_prot_to_native(protections[0]),
                HostPageState::MixedGuarded(_) | HostPageState::Composed16k => libc::PROT_NONE,
                HostPageState::Unsupported(_) => return Err(MemoryError::Unsupported),
            };
            if protections
                .iter()
                .any(|value| value & crate::linux_abi::LINUX_PROT_EXEC != 0)
            {
                self.mprotect_host_page(
                    page_start,
                    libc::PROT_READ | libc::PROT_WRITE,
                    address,
                    len,
                )?;
                let ptr = usize::try_from(page_start).map_err(|_| MemoryError::OutOfBounds {
                    address,
                    length: len,
                })? as *mut u8;
                let page_len =
                    usize::try_from(self.host_page_size).map_err(|_| MemoryError::OutOfBounds {
                        address,
                        length: len,
                    })?;
                patch_syscalls(ptr, page_len);
                unsafe { carrick_native_clear_icache(ptr.cast(), page_len) };
            }
            self.mprotect_host_page(page_start, host_prot, address, len)?;
            self.linux4k_page_protections
                .insert(page_start, protections);
        }
        Ok(())
    }

    fn read_u32(&self, address: u64) -> Result<u32, RuntimeError> {
        let bytes = self
            .read_bytes_raw(address, std::mem::size_of::<u32>())
            .map_err(|error| {
                RuntimeError::Unsupported(format!(
                    "native Darwin instruction read failed at 0x{address:x}: {error}"
                ))
            })?;
        let word: [u8; 4] = bytes.try_into().map_err(|_| {
            RuntimeError::Unsupported(format!(
                "native Darwin instruction read was short at 0x{address:x}"
            ))
        })?;
        Ok(u32::from_le_bytes(word))
    }

    fn write_u64(&mut self, address: u64, value: u64) -> Result<(), RuntimeError> {
        if !self.region_contains(address, std::mem::size_of::<u64>()) {
            return Err(RuntimeError::Unsupported(format!(
                "native Darwin relocation outside mapped guest memory at 0x{address:x}"
            )));
        }
        let ptr = usize::try_from(address).map_err(|_| {
            RuntimeError::Unsupported(format!("guest address too large: 0x{address:x}"))
        })? as *mut u64;
        unsafe { std::ptr::write_unaligned(ptr, value) };
        Ok(())
    }

    fn remap_private(
        &mut self,
        address: u64,
        len: usize,
        content: &[u8],
    ) -> Result<(), MemoryError> {
        if content.len() != len || !self.region_contains(address, len) {
            return Err(MemoryError::OutOfBounds {
                address,
                length: len,
            });
        }
        let end = address
            .checked_add(len as u64)
            .ok_or(MemoryError::OutOfBounds {
                address,
                length: len,
            })?;
        let (page_start, page_len) = self.host_page_range(address, end)?;
        let mut page = self.read_bytes_raw(page_start, page_len)?;
        let offset = usize::try_from(address.saturating_sub(page_start)).map_err(|_| {
            MemoryError::OutOfBounds {
                address,
                length: len,
            }
        })?;
        page[offset..offset + len].copy_from_slice(content);

        let ptr = usize::try_from(page_start).map_err(|_| MemoryError::OutOfBounds {
            address,
            length: len,
        })? as *mut libc::c_void;
        let mapped = unsafe {
            libc::mmap(
                ptr,
                page_len,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_ANON | libc::MAP_FIXED | libc::MAP_NORESERVE | libc::MAP_PRIVATE,
                -1,
                0,
            )
        };
        if mapped == libc::MAP_FAILED || mapped != ptr {
            return Err(MemoryError::OutOfBounds {
                address,
                length: len,
            });
        }
        unsafe {
            std::ptr::copy_nonoverlapping(page.as_ptr(), mapped.cast::<u8>(), page.len());
        }
        Ok(())
    }

    fn map_host_alias(
        &mut self,
        address: u64,
        len: u64,
        payload: &[u8],
        file: Option<(libc::c_int, libc::off_t, libc::c_int)>,
        prot_none: bool,
    ) -> Result<(), RuntimeError> {
        let map_len = align_up_u64(len, self.host_page_size, "native alias length")?;
        let map_len_usize = usize::try_from(map_len).map_err(|_| {
            RuntimeError::Unsupported(format!(
                "native Darwin alias too large: 0x{address:x}+0x{len:x}"
            ))
        })?;
        if map_len_usize == 0 {
            return Ok(());
        }
        let page_start = address & !(self.host_page_size - 1);
        let page_delta = address.saturating_sub(page_start);
        let host_map_len = align_up_u64(
            page_delta.checked_add(len).ok_or_else(|| {
                RuntimeError::Unsupported(format!(
                    "native Darwin alias host length overflow: 0x{address:x}+0x{len:x}"
                ))
            })?,
            self.host_page_size,
            "native alias host length",
        )?;
        let host_map_len_usize = usize::try_from(host_map_len).map_err(|_| {
            RuntimeError::Unsupported(format!(
                "native Darwin alias too large: 0x{address:x}+0x{len:x}"
            ))
        })?;
        let addr =
            usize::try_from(if page_delta == 0 { address } else { page_start }).map_err(|_| {
                RuntimeError::Unsupported(format!(
                    "native Darwin alias start too large: 0x{address:x}"
                ))
            })? as *mut libc::c_void;

        let (mmap_prot, final_prot, flags, fd, offset, direct_file) = match file {
            Some((fd, offset, prot)) if page_delta == 0 => (
                prot,
                prot,
                libc::MAP_SHARED | libc::MAP_FIXED,
                fd,
                offset,
                true,
            ),
            Some((fd, offset, prot)) => (
                libc::PROT_READ | libc::PROT_WRITE,
                prot,
                libc::MAP_ANON | libc::MAP_SHARED | libc::MAP_FIXED | libc::MAP_NORESERVE,
                fd,
                offset,
                false,
            ),
            None => (
                libc::PROT_READ | libc::PROT_WRITE,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_ANON | libc::MAP_PRIVATE | libc::MAP_FIXED | libc::MAP_NORESERVE,
                -1,
                0,
                false,
            ),
        };
        let mmap_fd = if direct_file { fd } else { -1 };
        let mmap_offset = if direct_file { offset } else { 0 };
        let mapped = unsafe {
            libc::mmap(
                addr,
                host_map_len_usize,
                mmap_prot,
                flags,
                mmap_fd,
                mmap_offset,
            )
        };
        if mapped != libc::MAP_FAILED && file.is_some() && !direct_file {
            let copy_len = usize::try_from(len).map_err(|_| {
                RuntimeError::Unsupported(format!(
                    "native Darwin alias guest length too large: 0x{address:x}+0x{len:x}"
                ))
            })?;
            let copy_offset = usize::try_from(page_delta).map_err(|_| {
                RuntimeError::Unsupported(format!(
                    "native Darwin alias page delta too large: 0x{page_delta:x}"
                ))
            })?;
            let dst = unsafe { mapped.cast::<u8>().add(copy_offset) };
            let mut copied = 0usize;
            while copied < copy_len {
                let rc = unsafe {
                    libc::pread(
                        fd,
                        dst.add(copied).cast::<libc::c_void>(),
                        copy_len - copied,
                        offset.saturating_add(copied as libc::off_t),
                    )
                };
                match rc.host_syscall_errno() {
                    Ok(0) => break,
                    Ok(n) => copied = copied.saturating_add(n as usize),
                    Err(errno) if errno == crate::linux_abi::LINUX_EINTR => {}
                    Err(errno) => {
                        unsafe { libc::close(fd) };
                        return Err(RuntimeError::Unsupported(format!(
                            "native Darwin alias pread failed with errno {}",
                            errno.get()
                        )));
                    }
                }
            }
            if final_prot != mmap_prot {
                let rc = unsafe { libc::mprotect(mapped, host_map_len_usize, final_prot) };
                if rc != 0 {
                    unsafe { libc::close(fd) };
                    return Err(last_io_error(&format!(
                        "mprotect native Darwin alias 0x{page_start:x}..0x{:x}",
                        page_start.saturating_add(host_map_len)
                    )));
                }
            }
        }
        if file.is_some() {
            unsafe { libc::close(fd) };
        }
        if mapped == libc::MAP_FAILED {
            return Err(last_io_error(&format!(
                "mmap native Darwin alias 0x{address:x}..0x{:x}",
                address.saturating_add(host_map_len)
            )));
        }
        if mapped != addr {
            return Err(RuntimeError::Unsupported(format!(
                "native Darwin mmap did not honor MAP_FIXED for alias 0x{address:x}"
            )));
        }

        if file.is_none() && !payload.is_empty() {
            let n = payload.len().min(map_len_usize);
            unsafe {
                std::ptr::copy_nonoverlapping(payload.as_ptr(), mapped.cast::<u8>(), n);
            }
        }

        let len_usize = usize::try_from(len).map_err(|_| {
            RuntimeError::Unsupported(format!(
                "native Darwin alias guest length too large: 0x{address:x}+0x{len:x}"
            ))
        })?;
        self.protections
            .set_no_access(address, len_usize, prot_none);
        self.protections.set_no_write(
            address,
            len_usize,
            !prot_none && final_prot & libc::PROT_WRITE == 0,
        );
        self.regions.push(NativeMappedRegion {
            start: address,
            end: checked_add_u64(address, len, "native alias end")?,
            host_protects: true,
            shared_futex: file.is_some(),
            guest_writable: final_prot & libc::PROT_WRITE != 0,
            default_prot: if prot_none { 0 } else { final_prot as u64 },
        });
        Ok(())
    }
}

impl GuestMemory for NativeMappedMemory {
    fn protections(&self) -> Option<&MemoryProtections> {
        Some(&self.protections)
    }

    fn write_bytes(&mut self, address: u64, bytes: &[u8]) -> Result<(), MemoryError> {
        if !bytes.is_empty()
            && (self.protections.range_no_access(address, bytes.len())
                || self.protections.range_no_write(address, bytes.len()))
        {
            return Err(MemoryError::OutOfBounds {
                address,
                length: bytes.len(),
            });
        }
        self.write_bytes_raw(address, bytes)
    }

    fn write_bytes_unchecked(&mut self, address: u64, bytes: &[u8]) -> Result<(), MemoryError> {
        if bytes.is_empty() {
            return Ok(());
        }
        if !self.region_contains(address, bytes.len()) {
            return Err(MemoryError::OutOfBounds {
                address,
                length: bytes.len(),
            });
        }
        self.write_bytes_raw(address, bytes)
    }

    fn zero_backing(&mut self, address: u64, len: usize) -> Result<(), MemoryError> {
        static ZERO_CHUNK: [u8; 64 * 1024] = [0; 64 * 1024];
        let mut offset = 0usize;
        while offset < len {
            let chunk = (len - offset).min(ZERO_CHUNK.len());
            let chunk_address =
                address
                    .checked_add(offset as u64)
                    .ok_or(MemoryError::OutOfBounds {
                        address,
                        length: len,
                    })?;
            self.write_bytes_unchecked(chunk_address, &ZERO_CHUNK[..chunk])?;
            offset += chunk;
        }
        Ok(())
    }

    fn read_bytes_raw(&self, address: u64, length: usize) -> Result<Vec<u8>, MemoryError> {
        if !self.region_contains(address, length) {
            return Err(MemoryError::OutOfBounds { address, length });
        }
        let ptr = usize::try_from(address)
            .map_err(|_| MemoryError::OutOfBounds { address, length })?
            as *const u8;
        let mut out = vec![0u8; length];
        let changed = self.prepare_temporary_host_access(address, length, false)?;
        unsafe {
            std::ptr::copy_nonoverlapping(ptr, out.as_mut_ptr(), length);
        }
        self.restore_temporary_host_access(&changed, address, length)?;
        Ok(out)
    }

    fn write_bytes_raw(&mut self, address: u64, bytes: &[u8]) -> Result<(), MemoryError> {
        let length = bytes.len();
        if !self.region_contains(address, length) {
            return Err(MemoryError::OutOfBounds { address, length });
        }
        self.invalidate_exclusive_range(address, length);
        let ptr = usize::try_from(address)
            .map_err(|_| MemoryError::OutOfBounds { address, length })?
            as *mut u8;
        let changed = self.prepare_temporary_host_access(address, length, true)?;
        unsafe {
            std::ptr::copy_nonoverlapping(bytes.as_ptr(), ptr, length);
        }
        self.restore_temporary_host_access(&changed, address, length)?;
        Ok(())
    }

    fn set_no_access(&mut self, address: u64, len: usize, no_access: bool) {
        self.protections.set_no_access(address, len, no_access);
    }

    fn set_no_write(&mut self, address: u64, len: usize, no_write: bool) {
        self.protections.set_no_write(address, len, no_write);
    }

    fn guest_range_is_writable(&self, address: u64, length: usize) -> bool {
        !(self.protections.range_no_access(address, length)
            || self.protections.range_no_write(address, length))
    }

    fn protect_range(&mut self, address: u64, len: usize, prot: u64) -> Result<(), MemoryError> {
        if len == 0 {
            return Ok(());
        }
        if !self.region_contains(address, len) {
            return Err(MemoryError::OutOfBounds {
                address,
                length: len,
            });
        }
        if self.uses_linux4k_subpages() {
            return self.protect_linux4k_range(address, len, prot);
        }
        let host_prot = linux_prot_to_native(prot);
        let overlaps: Vec<(u64, u64)> = self.host_protected_overlaps(address, len).collect();
        for (start, end) in overlaps {
            let (page_start, page_len) = self.host_page_range(start, end)?;
            let ptr = usize::try_from(page_start).map_err(|_| MemoryError::OutOfBounds {
                address,
                length: len,
            })? as *mut libc::c_void;
            if prot & crate::linux_abi::LINUX_PROT_EXEC != 0 {
                let writable =
                    unsafe { libc::mprotect(ptr, page_len, libc::PROT_READ | libc::PROT_WRITE) };
                if writable != 0 {
                    return Err(MemoryError::OutOfBounds {
                        address,
                        length: len,
                    });
                }
                patch_syscalls(ptr.cast::<u8>(), page_len);
                unsafe { carrick_native_clear_icache(ptr, page_len) };
            }
            let rc = unsafe { libc::mprotect(ptr, page_len, host_prot) };
            if rc != 0 {
                return Err(MemoryError::OutOfBounds {
                    address,
                    length: len,
                });
            }
            let mut page = page_start;
            let page_end = page_start.saturating_add(page_len as u64);
            while page < page_end {
                self.native_page_protections.insert(page, prot);
                page = page.saturating_add(self.host_page_size);
            }
        }
        Ok(())
    }

    fn unmap_range(&mut self, address: u64, len: usize) -> Result<(), MemoryError> {
        self.set_no_access(address, len, true);
        self.protect_range(address, len, 0)
    }

    fn shared_futex_location(
        &self,
        guest_addr: u64,
    ) -> Option<carrick_guest_mem::SharedFutexLocation> {
        if !guest_addr.is_multiple_of(std::mem::align_of::<u32>() as u64) {
            return None;
        }
        let end = guest_addr.checked_add(std::mem::size_of::<u32>() as u64)?;
        let shared = self
            .regions
            .iter()
            .any(|region| region.shared_futex && guest_addr >= region.start && end <= region.end);
        if !shared {
            return None;
        }
        let word = usize::try_from(guest_addr).ok()?;
        Some(carrick_guest_mem::SharedFutexLocation::Direct {
            word: carrick_guest_mem::HostVa(word),
            waiter_key: word,
        })
    }

    fn repoint_private(
        &mut self,
        va: u64,
        _overlay_ipa: u64,
        len: usize,
        content: &[u8],
    ) -> Result<(), MemoryError> {
        self.remap_private(va, len, content)
    }
}

fn linux_prot_to_native(prot: u64) -> libc::c_int {
    let mut host_prot = 0;
    if prot & crate::linux_abi::LINUX_PROT_READ != 0 {
        host_prot |= libc::PROT_READ;
    }
    if prot & crate::linux_abi::LINUX_PROT_WRITE != 0 {
        host_prot |= libc::PROT_WRITE;
    }
    if prot & crate::linux_abi::LINUX_PROT_EXEC != 0 {
        host_prot |= libc::PROT_EXEC;
    }
    host_prot
}

fn map_region(region: &MemoryRegion) -> Result<(), RuntimeError> {
    let length_u64 = region.end.checked_sub(region.start).ok_or_else(|| {
        RuntimeError::Unsupported("native Darwin empty inverted region".to_string())
    })?;
    let length = usize::try_from(length_u64).map_err(|_| {
        RuntimeError::Unsupported(format!(
            "native Darwin region too large: 0x{:x}..0x{:x}",
            region.start, region.end
        ))
    })?;
    if length == 0 {
        return Ok(());
    }
    let addr = usize::try_from(region.start).map_err(|_| {
        RuntimeError::Unsupported(format!(
            "native Darwin region start too large: 0x{:x}",
            region.start
        ))
    })? as *mut libc::c_void;
    let share = if region.shared {
        libc::MAP_SHARED
    } else {
        libc::MAP_PRIVATE
    };
    let mapped = unsafe {
        libc::mmap(
            addr,
            length,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_ANON | libc::MAP_FIXED | libc::MAP_NORESERVE | share,
            -1,
            0,
        )
    };
    if mapped == libc::MAP_FAILED {
        return Err(last_io_error(&format!(
            "mmap native Darwin region 0x{:x}..0x{:x}",
            region.start, region.end
        )));
    }
    if mapped != addr {
        return Err(RuntimeError::Unsupported(format!(
            "native Darwin mmap did not honor MAP_FIXED for 0x{:x}",
            region.start
        )));
    }

    let bytes = region.bytes();
    if !bytes.is_empty() {
        unsafe {
            std::ptr::copy_nonoverlapping(bytes.as_ptr(), mapped.cast::<u8>(), bytes.len());
        }
    }
    if region.perms.execute {
        patch_syscalls(mapped.cast::<u8>(), bytes.len());
        unsafe { carrick_native_clear_icache(mapped, bytes.len()) };
    }

    let prot = region_prot(region);
    let protect = unsafe { libc::mprotect(mapped, length, prot) };
    if protect != 0 {
        return Err(last_io_error(&format!(
            "mprotect native Darwin region 0x{:x}..0x{:x}",
            region.start, region.end
        )));
    }
    Ok(())
}

fn map_bytes_region(
    start: u64,
    length_u64: u64,
    bytes: &[u8],
    final_prot: libc::c_int,
    executable: bool,
) -> Result<(), RuntimeError> {
    let length = usize::try_from(length_u64).map_err(|_| {
        RuntimeError::Unsupported(format!(
            "native Darwin byte region too large: 0x{start:x}+0x{length_u64:x}"
        ))
    })?;
    if length == 0 {
        return Ok(());
    }
    if bytes.len() > length {
        return Err(RuntimeError::Unsupported(format!(
            "native Darwin byte region payload too large: {} > {length}",
            bytes.len()
        )));
    }
    let addr = usize::try_from(start).map_err(|_| {
        RuntimeError::Unsupported(format!(
            "native Darwin byte region start too large: 0x{start:x}"
        ))
    })? as *mut libc::c_void;
    let mapped = unsafe {
        libc::mmap(
            addr,
            length,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_ANON | libc::MAP_FIXED | libc::MAP_NORESERVE | libc::MAP_PRIVATE,
            -1,
            0,
        )
    };
    if mapped == libc::MAP_FAILED {
        return Err(last_io_error(&format!(
            "mmap native Darwin byte region 0x{start:x}+0x{length_u64:x}"
        )));
    }
    if mapped != addr {
        return Err(RuntimeError::Unsupported(format!(
            "native Darwin mmap did not honor MAP_FIXED for byte region 0x{start:x}"
        )));
    }
    if !bytes.is_empty() {
        unsafe {
            std::ptr::copy_nonoverlapping(bytes.as_ptr(), mapped.cast::<u8>(), bytes.len());
        }
    }
    if executable {
        patch_syscalls(mapped.cast::<u8>(), bytes.len());
        unsafe { carrick_native_clear_icache(mapped, bytes.len()) };
    }
    let protect = unsafe { libc::mprotect(mapped, length, final_prot) };
    if protect != 0 {
        return Err(last_io_error(&format!(
            "mprotect native Darwin byte region 0x{start:x}+0x{length_u64:x}"
        )));
    }
    Ok(())
}

fn map_anonymous_region(start: u64, length: u64, shared: bool) -> Result<(), RuntimeError> {
    let length = usize::try_from(length).map_err(|_| {
        RuntimeError::Unsupported(format!(
            "native Darwin anonymous region too large: 0x{start:x}+0x{length:x}"
        ))
    })?;
    if length == 0 {
        return Ok(());
    }
    let addr = usize::try_from(start).map_err(|_| {
        RuntimeError::Unsupported(format!(
            "native Darwin anonymous region start too large: 0x{start:x}"
        ))
    })? as *mut libc::c_void;
    let share = if shared {
        libc::MAP_SHARED
    } else {
        libc::MAP_PRIVATE
    };
    let mapped = unsafe {
        libc::mmap(
            addr,
            length,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_ANON | libc::MAP_FIXED | libc::MAP_NORESERVE | share,
            -1,
            0,
        )
    };
    if mapped == libc::MAP_FAILED {
        return Err(last_io_error(&format!(
            "mmap native Darwin anonymous region 0x{start:x}..0x{:x}",
            start.saturating_add(length as u64)
        )));
    }
    if mapped != addr {
        return Err(RuntimeError::Unsupported(format!(
            "native Darwin mmap did not honor MAP_FIXED for anonymous region 0x{start:x}"
        )));
    }
    Ok(())
}

fn set_native_region_fork_inheritance(address: *mut libc::c_void, len: usize, share: bool) -> bool {
    unsafe extern "C" {
        fn minherit(
            addr: *mut libc::c_void,
            len: libc::size_t,
            inherit: libc::c_int,
        ) -> libc::c_int;
    }
    let inherit = if share {
        VM_INHERIT_SHARE
    } else {
        VM_INHERIT_COPY
    };
    unsafe { minherit(address, len, inherit) == 0 }
}

fn region_prot(region: &MemoryRegion) -> libc::c_int {
    let mut prot = 0;
    if region.perms.read {
        prot |= libc::PROT_READ;
    }
    if region.perms.write {
        prot |= libc::PROT_WRITE;
    }
    // The large mmap arena is executable in the HVF stage-1 model so later
    // guest mmap/mprotect can grant execute permission without remapping host
    // memory. Native starts narrower: executable permissions are applied to
    // initialized executable regions, not to lazy zero data arenas.
    if region.perms.execute && !region.bytes().is_empty() {
        prot |= libc::PROT_EXEC;
    }
    prot
}

fn patch_syscalls(base: *mut u8, length: usize) {
    let words = length / std::mem::size_of::<u32>();
    for index in 0..words {
        let ptr = unsafe { base.add(index * std::mem::size_of::<u32>()).cast::<u32>() };
        let word = unsafe { std::ptr::read_unaligned(ptr) };
        let patched = if word == SVC_0 {
            Some(BRK_NATIVE_SYSCALL)
        } else if (word & !SYSTEM_REGISTER_RT_MASK) == MRS_TPIDR_EL0 {
            Some(brk_instruction(
                BRK_NATIVE_MRS_TPIDR_IMM_BASE | ((word & SYSTEM_REGISTER_RT_MASK) as u16),
            ))
        } else if (word & !SYSTEM_REGISTER_RT_MASK) == MSR_TPIDR_EL0 {
            Some(brk_instruction(
                BRK_NATIVE_MSR_TPIDR_IMM_BASE | ((word & SYSTEM_REGISTER_RT_MASK) as u16),
            ))
        } else if (word & !SYSTEM_REGISTER_RT_MASK) == MRS_CTR_EL0 {
            Some(brk_instruction(
                BRK_NATIVE_MRS_CTR_IMM_BASE | ((word & SYSTEM_REGISTER_RT_MASK) as u16),
            ))
        } else if (word & !SYSTEM_REGISTER_RT_MASK) == MRS_DCZID_EL0 {
            Some(brk_instruction(
                BRK_NATIVE_MRS_DCZID_IMM_BASE | ((word & SYSTEM_REGISTER_RT_MASK) as u16),
            ))
        } else if (word & !SYSTEM_REGISTER_RT_MASK) == DC_ZVA {
            Some(brk_instruction(
                BRK_NATIVE_DC_ZVA_IMM_BASE | ((word & SYSTEM_REGISTER_RT_MASK) as u16),
            ))
        } else if (word & !SYSTEM_REGISTER_RT_MASK) == DC_CVAU
            || (word & !SYSTEM_REGISTER_RT_MASK) == IC_IVAU
        {
            Some(AARCH64_NOP)
        } else {
            None
        };
        if let Some(word) = patched {
            unsafe { std::ptr::write_unaligned(ptr, word) };
        }
    }
}

fn pipe_pair() -> Result<(RawFd, RawFd), RuntimeError> {
    let mut fds = [0; 2];
    let rc = unsafe { libc::pipe(fds.as_mut_ptr()) };
    if rc == 0 {
        Ok((fds[0], fds[1]))
    } else {
        Err(last_io_error("pipe"))
    }
}

fn close_fd(fd: RawFd) {
    unsafe {
        libc::close(fd);
    }
}

fn child_dup2_or_exit(from: RawFd, to: RawFd) {
    let rc = unsafe { libc::dup2(from, to) };
    if rc < 0 {
        child_write_stderr(b"native Darwin child error: dup2 failed\n");
        unsafe { libc::_exit(125) };
    }
}

fn child_write_stderr(bytes: &[u8]) {
    let mut written = 0usize;
    while written < bytes.len() {
        let ptr = unsafe { bytes.as_ptr().add(written) };
        let rc = unsafe {
            libc::write(
                libc::STDERR_FILENO,
                ptr.cast::<libc::c_void>(),
                bytes.len() - written,
            )
        };
        if rc <= 0 {
            break;
        }
        let Ok(n) = usize::try_from(rc) else {
            break;
        };
        written = written.saturating_add(n);
    }
}

fn read_pipe_to_end(fd: RawFd) -> Result<Vec<u8>, std::io::Error> {
    let mut file = unsafe { std::fs::File::from_raw_fd(fd) };
    let mut out = Vec::new();
    file.read_to_end(&mut out)?;
    Ok(out)
}

fn join_reader(
    handle: thread::JoinHandle<Result<Vec<u8>, std::io::Error>>,
    stream: &str,
) -> Result<Vec<u8>, RuntimeError> {
    match handle.join() {
        Ok(Ok(bytes)) => Ok(bytes),
        Ok(Err(err)) => Err(RuntimeError::FsBackend(anyhow::anyhow!(
            "native Darwin failed to read {stream}: {err}"
        ))),
        Err(_) => Err(RuntimeError::Unsupported(format!(
            "native Darwin {stream} reader thread panicked"
        ))),
    }
}

fn waitpid_blocking(pid: libc::pid_t) -> Result<libc::c_int, RuntimeError> {
    let mut status = 0;
    loop {
        let rc = unsafe { libc::waitpid(pid, &mut status, 0) };
        if rc == pid {
            return Ok(status);
        }
        if rc < 0 {
            let err = std::io::Error::last_os_error();
            if err.raw_os_error() == Some(libc::EINTR) {
                continue;
            }
            return Err(RuntimeError::FsBackend(anyhow::anyhow!(
                "native Darwin waitpid failed: {err}"
            )));
        }
    }
}

fn last_io_error(context: &str) -> RuntimeError {
    RuntimeError::FsBackend(anyhow::anyhow!(
        "{context}: {}",
        std::io::Error::last_os_error()
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn synthetic_dynamic_elf(interpreter: Option<&[u8]>) -> Vec<u8> {
        const ELF_HEADER_SIZE: usize = 64;
        const PROGRAM_HEADER_SIZE: usize = 56;
        const PT_INTERP: u32 = 3;

        let program_header_count = u16::from(interpreter.is_some());
        let interpreter_offset = ELF_HEADER_SIZE + PROGRAM_HEADER_SIZE;
        let mut file = vec![0_u8; interpreter_offset + interpreter.map_or(0, <[u8]>::len)];
        file[0..4].copy_from_slice(b"\x7fELF");
        file[4] = 2;
        file[5] = 1;
        file[6] = 1;
        file[16..18].copy_from_slice(&ET_DYN.to_le_bytes());
        file[18..20].copy_from_slice(&183_u16.to_le_bytes());
        file[20..24].copy_from_slice(&1_u32.to_le_bytes());
        file[32..40].copy_from_slice(&(ELF_HEADER_SIZE as u64).to_le_bytes());
        file[52..54].copy_from_slice(&(ELF_HEADER_SIZE as u16).to_le_bytes());
        file[54..56].copy_from_slice(&(PROGRAM_HEADER_SIZE as u16).to_le_bytes());
        file[56..58].copy_from_slice(&program_header_count.to_le_bytes());
        if let Some(interpreter) = interpreter {
            let ph = ELF_HEADER_SIZE;
            file[ph..ph + 4].copy_from_slice(&PT_INTERP.to_le_bytes());
            file[ph + 8..ph + 16].copy_from_slice(&(interpreter_offset as u64).to_le_bytes());
            file[ph + 32..ph + 40].copy_from_slice(&(interpreter.len() as u64).to_le_bytes());
            file[interpreter_offset..].copy_from_slice(interpreter);
        }
        file
    }

    #[test]
    fn native_bridge_context_is_thread_local() {
        let mut main_context = NativeUcontextSnapshot::default();
        main_context.x[0] = 0x1111;
        assert_eq!(unsafe { carrick_native_seed_ucontext(&main_context) }, 0);

        let child_context = std::thread::spawn(|| {
            let mut context = NativeUcontextSnapshot::default();
            context.x[0] = 0x2222;
            assert_eq!(unsafe { carrick_native_seed_ucontext(&context) }, 0);
            snapshot_ucontext().expect("snapshot child native context")
        })
        .join()
        .expect("join native context child");

        let main_after = snapshot_ucontext().expect("snapshot main native context");
        assert_eq!(child_context.x[0], 0x2222);
        assert_eq!(main_after.x[0], 0x1111);
    }

    #[test]
    #[allow(deprecated)] // libc exposes mach_task_self_ as the stable self-task port.
    fn native_pagezero_min_offset_rejects_reallocation() {
        const GUEST_ADDRESS: usize = 0x20_0000;
        const HOST_PAGE_SIZE: usize = 16 * 1024;

        let pid = unsafe { libc::fork() };
        assert!(pid >= 0, "fork failed: {}", std::io::Error::last_os_error());
        if pid == 0 {
            let deallocate = unsafe {
                libc::vm_deallocate(
                    libc::mach_task_self_,
                    GUEST_ADDRESS as libc::vm_address_t,
                    HOST_PAGE_SIZE as libc::vm_size_t,
                )
            };
            if deallocate != 0 {
                unsafe { libc::_exit(1) };
            }
            let mapped = unsafe {
                libc::mmap(
                    GUEST_ADDRESS as *mut libc::c_void,
                    HOST_PAGE_SIZE,
                    libc::PROT_READ | libc::PROT_WRITE,
                    libc::MAP_ANON | libc::MAP_PRIVATE | libc::MAP_FIXED,
                    -1,
                    0,
                )
            };
            unsafe {
                libc::_exit(i32::from(mapped as usize == GUEST_ADDRESS) * 2);
            }
        }

        let mut status = 0;
        assert_eq!(unsafe { libc::waitpid(pid, &mut status, 0) }, pid);
        assert!(libc::WIFEXITED(status), "child status was 0x{status:x}");
        assert_eq!(libc::WEXITSTATUS(status), 0);
    }

    #[test]
    fn native_mmap_arena_does_not_overlap_fixed_windows() {
        let layout = native_memory_layout();
        let arena = (layout.mmap_base, layout.mmap_base + layout.mmap_size);
        let fixed = [
            (
                crate::memory::LINUX_INTERPRETER_BASE,
                crate::memory::LINUX_SHARED_FILE_BASE,
            ),
            (
                crate::memory::LINUX_SHARED_FILE_BASE,
                crate::memory::LINUX_SHARED_FILE_BASE + crate::memory::LINUX_SHARED_FILE_SIZE,
            ),
            (
                crate::memory::LINUX_PRIVATE_OVERLAY_BASE,
                crate::memory::LINUX_PRIVATE_OVERLAY_BASE
                    + crate::memory::LINUX_PRIVATE_OVERLAY_SIZE,
            ),
        ];
        for window in fixed {
            assert!(
                arena.1 <= window.0 || window.1 <= arena.0,
                "native mmap arena overlaps fixed window 0x{:x}..0x{:x}",
                window.0,
                window.1
            );
        }
    }

    #[test]
    fn native_mmap_arena_is_reservable_on_darwin() {
        let layout = native_memory_layout();
        let pid = unsafe { libc::fork() };
        assert!(pid >= 0, "fork failed: {}", std::io::Error::last_os_error());
        if pid == 0 {
            let code = if map_anonymous_region(layout.mmap_base, layout.mmap_size, false).is_ok() {
                0
            } else {
                1
            };
            unsafe { libc::_exit(code) };
        }

        let mut status = 0;
        assert_eq!(unsafe { libc::waitpid(pid, &mut status, 0) }, pid);
        assert!(libc::WIFEXITED(status));
        assert_eq!(libc::WEXITSTATUS(status), 0);
    }

    #[test]
    fn native16k_mmap_arena_can_become_executable() {
        let pid = unsafe { libc::fork() };
        assert!(pid >= 0, "fork failed: {}", std::io::Error::last_os_error());
        if pid == 0 {
            let page_size = 16 * 1024_u64;
            let layout = MemoryLayout {
                heap_base: NATIVE_DARWIN_HEAP_BASE,
                heap_size: page_size,
                mmap_base: NATIVE_DARWIN_MMAP_BASE,
                mmap_size: page_size,
            };
            let image = AddressSpace::from_regions(0, Vec::new())
                .expect("empty native test image should be valid");
            let result = NativeMappedMemory::map(&image, layout, page_size, page_size).and_then(
                |mut memory| {
                    let ret = 0xd65f_03c0_u32.to_le_bytes();
                    memory
                        .write_bytes_raw(layout.mmap_base, &ret)
                        .map_err(|err| RuntimeError::Unsupported(format!("test write: {err}")))?;
                    let start = usize::try_from(layout.mmap_base)
                        .map_err(|_| RuntimeError::Unsupported("test address overflow".into()))?
                        as *mut libc::c_void;
                    unsafe { carrick_native_clear_icache(start, ret.len()) };
                    memory
                        .protect_range(
                            layout.mmap_base,
                            page_size as usize,
                            crate::linux_abi::LINUX_PROT_READ | crate::linux_abi::LINUX_PROT_EXEC,
                        )
                        .map_err(|err| RuntimeError::Unsupported(format!("test protect: {err}")))?;
                    let entry: unsafe extern "C" fn() = unsafe { std::mem::transmute(start) };
                    unsafe { entry() };
                    Ok(())
                },
            );
            unsafe { libc::_exit(i32::from(result.is_err())) };
        }

        let mut status = 0;
        assert_eq!(unsafe { libc::waitpid(pid, &mut status, 0) }, pid);
        assert!(libc::WIFEXITED(status), "child status was 0x{status:x}");
        assert_eq!(libc::WEXITSTATUS(status), 0);
    }

    #[test]
    fn native16k_exec_protection_patches_linux_syscalls() {
        let pid = unsafe { libc::fork() };
        assert!(pid >= 0, "fork failed: {}", std::io::Error::last_os_error());
        if pid == 0 {
            let page_size = 16 * 1024_u64;
            let layout = MemoryLayout {
                heap_base: NATIVE_DARWIN_HEAP_BASE,
                heap_size: page_size,
                mmap_base: NATIVE_DARWIN_MMAP_BASE,
                mmap_size: page_size,
            };
            let image = AddressSpace::from_regions(0, Vec::new())
                .expect("empty native test image should be valid");
            let patched = NativeMappedMemory::map(&image, layout, page_size, page_size)
                .and_then(|mut memory| {
                    memory
                        .protect_range(layout.mmap_base, page_size as usize, 0)
                        .map_err(|err| RuntimeError::Unsupported(format!("test reserve: {err}")))?;
                    memory
                        .write_bytes_unchecked(layout.mmap_base, &SVC_0.to_le_bytes())
                        .map_err(|err| RuntimeError::Unsupported(format!("test write: {err}")))?;
                    memory
                        .protect_range(
                            layout.mmap_base,
                            page_size as usize,
                            crate::linux_abi::LINUX_PROT_READ | crate::linux_abi::LINUX_PROT_EXEC,
                        )
                        .map_err(|err| RuntimeError::Unsupported(format!("test protect: {err}")))?;
                    memory.read_u32(layout.mmap_base)
                })
                .is_ok_and(|word| word == BRK_NATIVE_SYSCALL);
            unsafe { libc::_exit(i32::from(!patched)) };
        }

        let mut status = 0;
        assert_eq!(unsafe { libc::waitpid(pid, &mut status, 0) }, pid);
        assert!(libc::WIFEXITED(status), "child status was 0x{status:x}");
        assert_eq!(libc::WEXITSTATUS(status), 0);
    }

    #[test]
    fn native_linux4k_uniform_host_page_can_become_executable() {
        let pid = unsafe { libc::fork() };
        assert!(pid >= 0, "fork failed: {}", std::io::Error::last_os_error());
        if pid == 0 {
            let host_page_size = 16 * 1024_u64;
            let linux_page_size = 4 * 1024_u64;
            let layout = MemoryLayout {
                heap_base: NATIVE_DARWIN_HEAP_BASE,
                heap_size: host_page_size,
                mmap_base: NATIVE_DARWIN_MMAP_BASE,
                mmap_size: host_page_size,
            };
            let image = AddressSpace::from_regions(0, Vec::new())
                .expect("empty native test image should be valid");
            let executable = NativeMappedMemory::map(
                &image,
                layout,
                host_page_size,
                linux_page_size,
            )
            .and_then(|mut memory| {
                let ret = 0xd65f_03c0_u32.to_le_bytes();
                memory
                    .write_bytes_unchecked(layout.mmap_base, &ret)
                    .map_err(|err| RuntimeError::Unsupported(format!("test write: {err}")))?;
                memory
                    .protect_range(
                        layout.mmap_base,
                        host_page_size as usize,
                        crate::linux_abi::LINUX_PROT_READ | crate::linux_abi::LINUX_PROT_EXEC,
                    )
                    .map_err(|err| RuntimeError::Unsupported(format!("test protect: {err}")))?;
                let entry: unsafe extern "C" fn() =
                    unsafe {
                        std::mem::transmute(usize::try_from(layout.mmap_base).map_err(|_| {
                            RuntimeError::Unsupported("test address overflow".into())
                        })? as *mut libc::c_void)
                    };
                unsafe { entry() };
                Ok(())
            });
            unsafe { libc::_exit(i32::from(executable.is_err())) };
        }

        let mut status = 0;
        assert_eq!(unsafe { libc::waitpid(pid, &mut status, 0) }, pid);
        assert!(libc::WIFEXITED(status), "child status was 0x{status:x}");
        assert_eq!(libc::WEXITSTATUS(status), 0);
    }

    #[test]
    fn native_linux4k_mixed_subpage_protection_is_guarded() {
        let pid = unsafe { libc::fork() };
        assert!(pid >= 0, "fork failed: {}", std::io::Error::last_os_error());
        if pid == 0 {
            let host_page_size = 16 * 1024_u64;
            let linux_page_size = 4 * 1024_u64;
            let layout = MemoryLayout {
                heap_base: NATIVE_DARWIN_HEAP_BASE,
                heap_size: host_page_size,
                mmap_base: NATIVE_DARWIN_MMAP_BASE,
                mmap_size: host_page_size,
            };
            let image = AddressSpace::from_regions(0, Vec::new())
                .expect("empty native test image should be valid");
            let guarded = NativeMappedMemory::map(&image, layout, host_page_size, linux_page_size)
                .is_ok_and(|mut memory| {
                    let protected = memory
                        .protect_range(
                            layout.mmap_base + linux_page_size,
                            linux_page_size as usize,
                            crate::linux_abi::LINUX_PROT_READ,
                        )
                        .is_ok();
                    protected
                        && matches!(
                            memory.classify_linux4k_host_page(
                                memory.linux4k_host_page_protections(layout.mmap_base)
                            ),
                            HostPageState::MixedGuarded(_)
                        )
                });
            unsafe { libc::_exit(i32::from(!guarded)) };
        }

        let mut status = 0;
        assert_eq!(unsafe { libc::waitpid(pid, &mut status, 0) }, pid);
        assert!(libc::WIFEXITED(status), "child status was 0x{status:x}");
        assert_eq!(libc::WEXITSTATUS(status), 0);
    }

    #[test]
    fn native_linux4k_guarded_heap_allows_adjacent_subpage_backing_write() {
        let pid = unsafe { libc::fork() };
        assert!(pid >= 0, "fork failed: {}", std::io::Error::last_os_error());
        if pid == 0 {
            let host_page_size = 16 * 1024_u64;
            let linux_page_size = 4 * 1024_u64;
            let layout = MemoryLayout {
                heap_base: NATIVE_DARWIN_HEAP_BASE,
                heap_size: host_page_size,
                mmap_base: NATIVE_DARWIN_MMAP_BASE,
                mmap_size: host_page_size,
            };
            let image = AddressSpace::from_regions(0, Vec::new())
                .expect("empty native test image should be valid");
            let wrote = NativeMappedMemory::map(&image, layout, host_page_size, linux_page_size)
                .is_ok_and(|mut memory| {
                    memory
                        .protect_range(layout.heap_base, linux_page_size as usize, 0)
                        .is_ok()
                        && memory
                            .write_bytes_unchecked(layout.heap_base + linux_page_size, &[0x5a])
                            .is_ok()
                });
            unsafe { libc::_exit(i32::from(!wrote)) };
        }

        let mut status = 0;
        assert_eq!(unsafe { libc::waitpid(pid, &mut status, 0) }, pid);
        assert!(libc::WIFEXITED(status), "child status was 0x{status:x}");
        assert_eq!(libc::WEXITSTATUS(status), 0);
    }

    #[test]
    fn native_linux4k_executable_tail_is_guarded_until_instruction_fetch() {
        let pid = unsafe { libc::fork() };
        assert!(pid >= 0, "fork failed: {}", std::io::Error::last_os_error());
        if pid == 0 {
            let host_page_size = 16 * 1024_u64;
            let linux_page_size = 4 * 1024_u64;
            let layout = MemoryLayout {
                heap_base: NATIVE_DARWIN_HEAP_BASE,
                heap_size: host_page_size,
                mmap_base: NATIVE_DARWIN_MMAP_BASE,
                mmap_size: host_page_size,
            };
            let image = AddressSpace::from_regions(0, Vec::new())
                .expect("empty native test image should be valid");
            let guarded = NativeMappedMemory::map(&image, layout, host_page_size, linux_page_size)
                .is_ok_and(|mut memory| {
                    let wrote = memory
                        .write_bytes_unchecked(layout.mmap_base, &AARCH64_NOP.to_le_bytes())
                        .is_ok();
                    let protected = memory
                        .protect_range(
                            layout.mmap_base,
                            (3 * linux_page_size) as usize,
                            crate::linux_abi::LINUX_PROT_READ | crate::linux_abi::LINUX_PROT_EXEC,
                        )
                        .is_ok();
                    let mut snapshot = NativeUcontextSnapshot {
                        pc: layout.mmap_base,
                        signal: libc::SIGBUS,
                        fault_address: layout.mmap_base,
                        ..NativeUcontextSnapshot::default()
                    };
                    wrote
                        && protected
                        && memory.linux4k_address_is_guarded(layout.mmap_base)
                        && memory.read_bytes_raw(layout.mmap_base, 4).is_ok()
                        && emulate_linux4k_guarded_fault(&mut memory, &mut snapshot).is_err()
                });
            unsafe { libc::_exit(i32::from(!guarded)) };
        }

        let mut status = 0;
        assert_eq!(unsafe { libc::waitpid(pid, &mut status, 0) }, pid);
        assert!(libc::WIFEXITED(status), "child status was 0x{status:x}");
        assert_eq!(libc::WEXITSTATUS(status), 0);
    }

    #[test]
    fn native_mixed_page_decoder_exposes_scalar_load_store_operands() {
        let load = bad64::decode(0xf940_0020, 0x1000).expect("decode ldr x0, [x1]");
        let store = bad64::decode(0xf900_0020, 0x1004).expect("decode str x0, [x1]");
        let vector_load = bad64::decode(0x4c40_7020, 0x1008).expect("decode ld1 {v0.16b}, [x1]");
        let pair_load = bad64::decode(0xad40_0420, 0x100c).expect("decode ldp q0, q1, [x1]");
        let q_load = bad64::decode(0x3dc0_0420, 0x100c).expect("decode ldr q0, [x1, #16]");
        let register_store =
            bad64::decode(0xf83a_5861, 0x1010).expect("decode str x1, [x3, w26, uxtw #3]");

        assert_eq!(load.op(), bad64::Op::LDR);
        assert_eq!(store.op(), bad64::Op::STR);
        assert_eq!(load.operands().len(), 2);
        assert_eq!(store.operands().len(), 2);
        assert_ne!(load.operands()[0], load.operands()[1]);
        assert_ne!(store.operands()[0], store.operands()[1]);
        assert_eq!(vector_load.op(), bad64::Op::LD1);
        assert!(matches!(
            vector_load.operands(),
            [
                bad64::Operand::MultiReg {
                    arrspec: Some(bad64::ArrSpec::SixteenBytes(None)),
                    ..
                },
                bad64::Operand::MemReg(bad64::Reg::X1)
            ]
        ));
        assert_eq!(pair_load.op(), bad64::Op::LDP);
        assert!(matches!(
            pair_load.operands(),
            [
                bad64::Operand::Reg {
                    reg: bad64::Reg::Q0,
                    arrspec: None,
                },
                bad64::Operand::Reg {
                    reg: bad64::Reg::Q1,
                    arrspec: None,
                },
                bad64::Operand::MemOffset {
                    reg: bad64::Reg::X1,
                    offset: bad64::Imm::Signed(0),
                    ..
                }
            ]
        ));
        assert!(matches!(
            q_load.operands(),
            [
                bad64::Operand::Reg {
                    reg: bad64::Reg::Q0,
                    arrspec: None,
                },
                bad64::Operand::MemOffset {
                    reg: bad64::Reg::X1,
                    offset: bad64::Imm::Signed(16),
                    ..
                }
            ]
        ));
        assert!(matches!(
            register_store.operands(),
            [
                bad64::Operand::Reg {
                    reg: bad64::Reg::X1,
                    arrspec: None,
                },
                bad64::Operand::MemExt {
                    regs: [bad64::Reg::X3, bad64::Reg::W26],
                    shift: Some(bad64::Shift::UXTW(3)),
                    arrspec: None,
                }
            ]
        ));
    }

    #[test]
    fn native_linux4k_guard_blocks_direct_access_but_allows_backing_copy() {
        let pid = unsafe { libc::fork() };
        assert!(pid >= 0, "fork failed: {}", std::io::Error::last_os_error());
        if pid == 0 {
            let host_page_size = 16 * 1024_u64;
            let linux_page_size = 4 * 1024_u64;
            let layout = MemoryLayout {
                heap_base: NATIVE_DARWIN_HEAP_BASE,
                heap_size: host_page_size,
                mmap_base: NATIVE_DARWIN_MMAP_BASE,
                mmap_size: host_page_size,
            };
            let image = AddressSpace::from_regions(0, Vec::new())
                .expect("empty native test image should be valid");
            let guarded = NativeMappedMemory::map(&image, layout, host_page_size, linux_page_size)
                .and_then(|mut memory| {
                    let address = layout.mmap_base + linux_page_size;
                    memory
                        .protect_range(
                            address,
                            linux_page_size as usize,
                            crate::linux_abi::LINUX_PROT_READ | crate::linux_abi::LINUX_PROT_WRITE,
                        )
                        .map_err(|error| RuntimeError::Unsupported(error.to_string()))?;
                    memory
                        .write_bytes_unchecked(address, &[0x5a])
                        .map_err(|error| RuntimeError::Unsupported(error.to_string()))?;

                    let direct = unsafe { libc::fork() };
                    if direct == 0 {
                        unsafe {
                            libc::signal(libc::SIGBUS, libc::SIG_DFL);
                            libc::signal(libc::SIGSEGV, libc::SIG_DFL);
                            let ptr = usize::try_from(address).unwrap_or(0) as *const u8;
                            std::ptr::read_volatile(ptr);
                            libc::_exit(0);
                        }
                    }
                    if direct < 0 {
                        return Err(RuntimeError::Unsupported(
                            std::io::Error::last_os_error().to_string(),
                        ));
                    }
                    let mut status = 0;
                    if unsafe { libc::waitpid(direct, &mut status, 0) } != direct
                        || !libc::WIFSIGNALED(status)
                        || !matches!(libc::WTERMSIG(status), libc::SIGBUS | libc::SIGSEGV)
                    {
                        return Err(RuntimeError::Unsupported(format!(
                            "direct guarded read unexpectedly completed with status 0x{status:x}"
                        )));
                    }
                    let bytes = memory
                        .read_bytes_raw(address, 1)
                        .map_err(|error| RuntimeError::Unsupported(error.to_string()))?;
                    (bytes == [0x5a]).then_some(()).ok_or_else(|| {
                        RuntimeError::Unsupported(
                            "guarded backing copy returned wrong byte".to_string(),
                        )
                    })
                });
            unsafe { libc::_exit(i32::from(guarded.is_err())) };
        }

        let mut status = 0;
        assert_eq!(unsafe { libc::waitpid(pid, &mut status, 0) }, pid);
        assert!(libc::WIFEXITED(status), "child status was 0x{status:x}");
        assert_eq!(libc::WEXITSTATUS(status), 0);
    }

    #[test]
    fn native_linux4k_guard_emulates_scalar_load() {
        let pid = unsafe { libc::fork() };
        assert!(pid >= 0, "fork failed: {}", std::io::Error::last_os_error());
        if pid == 0 {
            let host_page_size = 16 * 1024_u64;
            let linux_page_size = 4 * 1024_u64;
            let layout = MemoryLayout {
                heap_base: NATIVE_DARWIN_HEAP_BASE,
                heap_size: host_page_size,
                mmap_base: NATIVE_DARWIN_MMAP_BASE,
                mmap_size: 2 * host_page_size,
            };
            let image = AddressSpace::from_regions(0, Vec::new())
                .expect("empty native test image should be valid");
            let emulated = NativeMappedMemory::map(&image, layout, host_page_size, linux_page_size)
                .and_then(|mut memory| {
                    let pc = layout.mmap_base;
                    let address = layout.mmap_base + host_page_size + linux_page_size;
                    memory
                        .write_bytes_unchecked(pc, &0xf940_0020_u32.to_le_bytes())
                        .map_err(|error| RuntimeError::Unsupported(error.to_string()))?;
                    memory
                        .protect_range(
                            pc,
                            host_page_size as usize,
                            crate::linux_abi::LINUX_PROT_READ | crate::linux_abi::LINUX_PROT_EXEC,
                        )
                        .map_err(|error| RuntimeError::Unsupported(error.to_string()))?;
                    memory
                        .protect_range(
                            address,
                            linux_page_size as usize,
                            crate::linux_abi::LINUX_PROT_READ | crate::linux_abi::LINUX_PROT_WRITE,
                        )
                        .map_err(|error| RuntimeError::Unsupported(error.to_string()))?;
                    memory
                        .write_bytes_unchecked(address, &0x1122_3344_5566_7788_u64.to_le_bytes())
                        .map_err(|error| RuntimeError::Unsupported(error.to_string()))?;
                    let mut snapshot = NativeUcontextSnapshot {
                        pc,
                        signal: libc::SIGBUS,
                        fault_address: address,
                        ..NativeUcontextSnapshot::default()
                    };
                    snapshot.x[1] = address;
                    emulate_linux4k_guarded_fault(&mut memory, &mut snapshot)?;
                    if snapshot.x[0] != 0x1122_3344_5566_7788 || snapshot.pc != pc + 4 {
                        return Err(RuntimeError::Unsupported(format!(
                            "emulated load produced x0=0x{:x} pc=0x{:x}",
                            snapshot.x[0], snapshot.pc
                        )));
                    }
                    memory
                        .write_bytes_unchecked(pc, &0x4c40_7020_u32.to_le_bytes())
                        .map_err(|error| RuntimeError::Unsupported(error.to_string()))?;
                    snapshot.pc = pc;
                    snapshot.fault_address = address;
                    snapshot.v[0] = [0; 16];
                    emulate_linux4k_guarded_fault(&mut memory, &mut snapshot)?;
                    let mut expected = [0_u8; 16];
                    expected[..8].copy_from_slice(&0x1122_3344_5566_7788_u64.to_le_bytes());
                    if snapshot.v[0] != expected || snapshot.pc != pc + 4 {
                        return Err(RuntimeError::Unsupported(format!(
                            "emulated vector load produced v0={:02x?} pc=0x{:x}",
                            snapshot.v[0], snapshot.pc
                        )));
                    }
                    memory
                        .write_bytes_unchecked(pc, &0x3dc0_0420_u32.to_le_bytes())
                        .map_err(|error| RuntimeError::Unsupported(error.to_string()))?;
                    memory
                        .write_bytes_unchecked(address + 16, &[0xa5; 16])
                        .map_err(|error| RuntimeError::Unsupported(error.to_string()))?;
                    snapshot.pc = pc;
                    snapshot.fault_address = address + 16;
                    snapshot.v[0] = [0; 16];
                    emulate_linux4k_guarded_fault(&mut memory, &mut snapshot)?;
                    if snapshot.v[0] != [0xa5; 16] || snapshot.pc != pc + 4 {
                        return Err(RuntimeError::Unsupported(format!(
                            "emulated q load produced v0={:02x?} pc=0x{:x}",
                            snapshot.v[0], snapshot.pc
                        )));
                    }
                    memory
                        .write_bytes_unchecked(pc, &0xad40_0420_u32.to_le_bytes())
                        .map_err(|error| RuntimeError::Unsupported(error.to_string()))?;
                    memory
                        .write_bytes_unchecked(address + 16, &[0xa5; 16])
                        .map_err(|error| RuntimeError::Unsupported(error.to_string()))?;
                    snapshot.pc = pc;
                    snapshot.fault_address = address;
                    snapshot.v[0] = [0; 16];
                    snapshot.v[1] = [0; 16];
                    emulate_linux4k_guarded_fault(&mut memory, &mut snapshot)?;
                    if snapshot.v[0] != expected
                        || snapshot.v[1] != [0xa5; 16]
                        || snapshot.pc != pc + 4
                    {
                        return Err(RuntimeError::Unsupported(format!(
                            "emulated pair load produced v0={:02x?} v1={:02x?} pc=0x{:x}",
                            snapshot.v[0], snapshot.v[1], snapshot.pc
                        )));
                    }
                    Ok(())
                });
            unsafe { libc::_exit(i32::from(emulated.is_err())) };
        }

        let mut status = 0;
        assert_eq!(unsafe { libc::waitpid(pid, &mut status, 0) }, pid);
        assert!(libc::WIFEXITED(status), "child status was 0x{status:x}");
        assert_eq!(libc::WEXITSTATUS(status), 0);
    }

    #[test]
    fn native_linux4k_guard_emulates_exclusive_compare_exchange() {
        let pid = unsafe { libc::fork() };
        assert!(pid >= 0, "fork failed: {}", std::io::Error::last_os_error());
        if pid == 0 {
            let host_page_size = 16 * 1024_u64;
            let linux_page_size = 4 * 1024_u64;
            let layout = MemoryLayout {
                heap_base: NATIVE_DARWIN_HEAP_BASE,
                heap_size: host_page_size,
                mmap_base: NATIVE_DARWIN_MMAP_BASE,
                mmap_size: 2 * host_page_size,
            };
            let image = AddressSpace::from_regions(0, Vec::new())
                .expect("empty native test image should be valid");
            let emulated = NativeMappedMemory::map(&image, layout, host_page_size, linux_page_size)
                .and_then(|mut memory| {
                    let pc = layout.mmap_base;
                    let address = layout.mmap_base + host_page_size + linux_page_size;
                    memory
                        .write_bytes_unchecked(pc, &0x885f_fc40_u32.to_le_bytes())
                        .map_err(|error| RuntimeError::Unsupported(error.to_string()))?;
                    memory
                        .protect_range(
                            pc,
                            host_page_size as usize,
                            crate::linux_abi::LINUX_PROT_READ | crate::linux_abi::LINUX_PROT_EXEC,
                        )
                        .map_err(|error| RuntimeError::Unsupported(error.to_string()))?;
                    memory
                        .protect_range(
                            address,
                            linux_page_size as usize,
                            crate::linux_abi::LINUX_PROT_READ | crate::linux_abi::LINUX_PROT_WRITE,
                        )
                        .map_err(|error| RuntimeError::Unsupported(error.to_string()))?;
                    memory
                        .write_bytes_unchecked(address, &7_u32.to_le_bytes())
                        .map_err(|error| RuntimeError::Unsupported(error.to_string()))?;

                    let mut snapshot = NativeUcontextSnapshot {
                        pc,
                        signal: libc::SIGBUS,
                        fault_address: address,
                        ..NativeUcontextSnapshot::default()
                    };
                    snapshot.x[2] = address;
                    emulate_linux4k_guarded_fault(&mut memory, &mut snapshot)?;
                    if snapshot.x[0] != 7 || snapshot.pc != pc + 4 {
                        return Err(RuntimeError::Unsupported(format!(
                            "emulated ldaxr produced x0={} pc=0x{:x}",
                            snapshot.x[0], snapshot.pc
                        )));
                    }

                    memory
                        .write_bytes_unchecked(pc, &0x8803_fc44_u32.to_le_bytes())
                        .map_err(|error| RuntimeError::Unsupported(error.to_string()))?;
                    snapshot.pc = pc;
                    snapshot.x[4] = 9;
                    emulate_linux4k_guarded_fault(&mut memory, &mut snapshot)?;
                    let stored = memory
                        .read_bytes_raw(address, std::mem::size_of::<u32>())
                        .map_err(|error| RuntimeError::Unsupported(error.to_string()))?;
                    if snapshot.x[3] != 0 || stored != 9_u32.to_le_bytes() || snapshot.pc != pc + 4
                    {
                        return Err(RuntimeError::Unsupported(format!(
                            "emulated stlxr produced status={} bytes={stored:02x?} pc=0x{:x}",
                            snapshot.x[3], snapshot.pc
                        )));
                    }

                    memory
                        .write_bytes_unchecked(pc, &0x885f_fc40_u32.to_le_bytes())
                        .map_err(|error| RuntimeError::Unsupported(error.to_string()))?;
                    snapshot.pc = pc;
                    emulate_linux4k_guarded_fault(&mut memory, &mut snapshot)?;
                    memory
                        .write_bytes_unchecked(address, &11_u32.to_le_bytes())
                        .map_err(|error| RuntimeError::Unsupported(error.to_string()))?;
                    memory
                        .write_bytes_unchecked(pc, &0x8803_fc44_u32.to_le_bytes())
                        .map_err(|error| RuntimeError::Unsupported(error.to_string()))?;
                    snapshot.pc = pc;
                    snapshot.x[4] = 13;
                    emulate_linux4k_guarded_fault(&mut memory, &mut snapshot)?;
                    let stored = memory
                        .read_bytes_raw(address, std::mem::size_of::<u32>())
                        .map_err(|error| RuntimeError::Unsupported(error.to_string()))?;
                    if snapshot.x[3] != 1 || stored != 11_u32.to_le_bytes() || snapshot.pc != pc + 4
                    {
                        return Err(RuntimeError::Unsupported(format!(
                            "invalidated stlxr produced status={} bytes={stored:02x?} pc=0x{:x}",
                            snapshot.x[3], snapshot.pc
                        )));
                    }
                    Ok(())
                });
            if let Err(error) = &emulated {
                child_write_stderr(format!("exclusive emulation test: {error}\n").as_bytes());
            }
            unsafe { libc::_exit(i32::from(emulated.is_err())) };
        }

        let mut status = 0;
        assert_eq!(unsafe { libc::waitpid(pid, &mut status, 0) }, pid);
        assert!(libc::WIFEXITED(status), "child status was 0x{status:x}");
        assert_eq!(libc::WEXITSTATUS(status), 0);
    }

    #[test]
    fn native16k_zero_backing_replaces_readonly_page() {
        let pid = unsafe { libc::fork() };
        assert!(pid >= 0, "fork failed: {}", std::io::Error::last_os_error());
        if pid == 0 {
            let page_size = 16 * 1024_u64;
            let layout = MemoryLayout {
                heap_base: NATIVE_DARWIN_HEAP_BASE,
                heap_size: page_size,
                mmap_base: NATIVE_DARWIN_MMAP_BASE,
                mmap_size: page_size,
            };
            let image = AddressSpace::from_regions(0, Vec::new())
                .expect("empty native test image should be valid");
            let zeroed = NativeMappedMemory::map(&image, layout, page_size, page_size)
                .and_then(|mut memory| {
                    memory
                        .write_bytes_unchecked(layout.mmap_base, &[0xff; 16])
                        .map_err(|err| RuntimeError::Unsupported(format!("test write: {err}")))?;
                    memory
                        .protect_range(
                            layout.mmap_base,
                            page_size as usize,
                            crate::linux_abi::LINUX_PROT_READ,
                        )
                        .map_err(|err| RuntimeError::Unsupported(format!("test protect: {err}")))?;
                    memory
                        .zero_backing(layout.mmap_base, page_size as usize)
                        .map_err(|err| RuntimeError::Unsupported(format!("test zero: {err}")))?;
                    memory
                        .read_bytes_raw(layout.mmap_base, 16)
                        .map_err(|err| RuntimeError::Unsupported(format!("test read: {err}")))
                })
                .is_ok_and(|bytes| bytes == [0; 16]);
            unsafe { libc::_exit(i32::from(!zeroed)) };
        }

        let mut status = 0;
        assert_eq!(unsafe { libc::waitpid(pid, &mut status, 0) }, pid);
        assert!(libc::WIFEXITED(status), "child status was 0x{status:x}");
        assert_eq!(libc::WEXITSTATUS(status), 0);
    }

    #[test]
    fn native_vfork_inheritance_shares_private_pages() {
        let page_size = 16 * 1024;
        let mapped = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                page_size,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_ANON | libc::MAP_PRIVATE,
                -1,
                0,
            )
        };
        assert_ne!(mapped, libc::MAP_FAILED);
        let word = mapped.cast::<u32>();
        unsafe { word.write(0) };
        assert!(set_native_region_fork_inheritance(mapped, page_size, true));

        let pid = unsafe { libc::fork() };
        assert!(pid >= 0, "fork failed: {}", std::io::Error::last_os_error());
        if pid == 0 {
            unsafe {
                word.write(42);
                libc::_exit(0);
            }
        }

        assert!(set_native_region_fork_inheritance(mapped, page_size, false));
        let mut status = 0;
        assert_eq!(unsafe { libc::waitpid(pid, &mut status, 0) }, pid);
        assert!(libc::WIFEXITED(status));
        assert_eq!(libc::WEXITSTATUS(status), 0);
        assert_eq!(unsafe { word.read() }, 42);
        unsafe { libc::munmap(mapped, page_size) };
    }

    fn native_mapping_subset_survives_shared_inheritance_fork(
        selected: impl Fn(&NativeMappedRegion) -> bool,
    ) -> bool {
        let outer = unsafe { libc::fork() };
        assert!(
            outer >= 0,
            "fork failed: {}",
            std::io::Error::last_os_error()
        );
        if outer == 0 {
            let page_size = 16 * 1024_u64;
            let layout = native_memory_layout();
            let image = AddressSpace::from_regions(0, Vec::new())
                .expect("empty native test image should be valid");
            let memory = NativeMappedMemory::map(&image, layout, page_size, page_size)
                .expect("native mapping set should map");
            for region in memory.regions.iter().filter(|region| selected(region)) {
                let start = usize::try_from(region.start).expect("native region start fits usize");
                let len = usize::try_from(region.end - region.start)
                    .expect("native region length fits usize");
                assert!(set_native_region_fork_inheritance(
                    start as *mut libc::c_void,
                    len,
                    true,
                ));
            }
            let child = unsafe { libc::fork() };
            if child == 0 {
                unsafe { libc::_exit(0) };
            }
            let mut status = 0;
            let waited = unsafe { libc::waitpid(child, &mut status, 0) };
            for region in memory.regions.iter().filter(|region| selected(region)) {
                let start = usize::try_from(region.start).expect("native region start fits usize");
                let len = usize::try_from(region.end - region.start)
                    .expect("native region length fits usize");
                let _ = set_native_region_fork_inheritance(start as *mut libc::c_void, len, false);
            }
            let ok = waited == child && libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0;
            unsafe { libc::_exit(i32::from(!ok)) };
        }

        let mut status = 0;
        assert_eq!(unsafe { libc::waitpid(outer, &mut status, 0) }, outer);
        libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0
    }

    fn native_nested_fork_survives_without_mappings() -> bool {
        let outer = unsafe { libc::fork() };
        assert!(
            outer >= 0,
            "fork failed: {}",
            std::io::Error::last_os_error()
        );
        if outer == 0 {
            let child = unsafe { libc::fork() };
            if child == 0 {
                unsafe { libc::_exit(0) };
            }
            let mut status = 0;
            let waited = unsafe { libc::waitpid(child, &mut status, 0) };
            let ok = waited == child && libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0;
            unsafe { libc::_exit(i32::from(!ok)) };
        }

        let mut status = 0;
        assert_eq!(unsafe { libc::waitpid(outer, &mut status, 0) }, outer);
        libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0
    }

    fn native_fixed_mapping_survives_nested_fork(start: u64, len: u64, shared: bool) -> bool {
        let outer = unsafe { libc::fork() };
        assert!(
            outer >= 0,
            "fork failed: {}",
            std::io::Error::last_os_error()
        );
        if outer == 0 {
            let mapped = map_anonymous_region(start, len, shared).is_ok();
            if !mapped {
                unsafe { libc::_exit(2) };
            }
            let child = unsafe { libc::fork() };
            if child == 0 {
                unsafe { libc::_exit(0) };
            }
            let mut status = 0;
            let waited = unsafe { libc::waitpid(child, &mut status, 0) };
            let ok = waited == child && libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0;
            unsafe { libc::_exit(i32::from(!ok)) };
        }

        let mut status = 0;
        assert_eq!(unsafe { libc::waitpid(outer, &mut status, 0) }, outer);
        libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0
    }

    #[test]
    fn native_mapping_classes_survive_shared_inheritance_fork() {
        let layout = native_memory_layout();
        assert!(
            native_nested_fork_survives_without_mappings(),
            "native nested-fork control failed without native mappings"
        );
        let fixed_cases = [
            (
                "sigreturn",
                NATIVE_DARWIN_SIGRETURN_TRAMPOLINE_BASE,
                carrick_mem::memory::LINUX_SIGRETURN_TRAMPOLINE_SIZE,
                false,
            ),
            ("heap", layout.heap_base, layout.heap_size, false),
            ("mmap", layout.mmap_base, layout.mmap_size, false),
            (
                "shared aperture",
                crate::memory::LINUX_SHARED_FILE_BASE,
                crate::memory::LINUX_SHARED_FILE_SIZE,
                true,
            ),
            (
                "private overlay",
                crate::memory::LINUX_PRIVATE_OVERLAY_BASE,
                crate::memory::LINUX_PRIVATE_OVERLAY_SIZE,
                false,
            ),
        ];
        let fixed_failures: Vec<_> = fixed_cases
            .into_iter()
            .filter_map(|(name, start, len, shared)| {
                (!native_fixed_mapping_survives_nested_fork(start, len, shared)).then_some(name)
            })
            .collect();
        assert!(
            fixed_failures.is_empty(),
            "native fixed mappings broke the fork child: {fixed_failures:?}"
        );
        assert!(
            native_mapping_subset_survives_shared_inheritance_fork(|_| false),
            "native nested-fork baseline failed without changing inheritance"
        );
        let cases = [
            ("sigreturn", NATIVE_DARWIN_SIGRETURN_TRAMPOLINE_BASE),
            ("heap", layout.heap_base),
            ("mmap", layout.mmap_base),
            ("shared aperture", crate::memory::LINUX_SHARED_FILE_BASE),
            ("private overlay", crate::memory::LINUX_PRIVATE_OVERLAY_BASE),
        ];
        let mut failures = Vec::new();
        for (name, start) in cases {
            if !native_mapping_subset_survives_shared_inheritance_fork(|region| {
                region.start == start
            }) {
                failures.push(name);
            }
        }

        if !native_mapping_subset_survives_shared_inheritance_fork(|region| {
            region.start == layout.heap_base
                || region.start == layout.mmap_base
                || region.start == crate::memory::LINUX_PRIVATE_OVERLAY_BASE
        }) {
            failures.push("HVF-equivalent writable set");
        }

        assert!(
            failures.is_empty(),
            "sharing native mapping classes broke the fork child: {failures:?}"
        );
    }

    #[test]
    fn native_vfork_inheritance_matches_hvf_writability() {
        let child = unsafe { libc::fork() };
        assert!(
            child >= 0,
            "fork failed: {}",
            std::io::Error::last_os_error()
        );
        if child == 0 {
            let layout = native_memory_layout();
            let image = AddressSpace::from_regions(0, Vec::new())
                .expect("empty native test image should be valid");
            let memory = NativeMappedMemory::map(&image, layout, 16 * 1024, 16 * 1024)
                .expect("native mapping set should map");
            let writable = |start| {
                memory
                    .regions
                    .iter()
                    .find(|region| region.start == start)
                    .map(|region| region.guest_writable && !region.shared_futex)
            };
            let matches_hvf = writable(NATIVE_DARWIN_SIGRETURN_TRAMPOLINE_BASE) == Some(false)
                && writable(layout.heap_base) == Some(true)
                && writable(layout.mmap_base) == Some(true)
                && writable(crate::memory::LINUX_SHARED_FILE_BASE) == Some(false)
                && writable(crate::memory::LINUX_PRIVATE_OVERLAY_BASE) == Some(true);
            unsafe { libc::_exit(i32::from(!matches_hvf)) };
        }

        let mut status = 0;
        assert_eq!(unsafe { libc::waitpid(child, &mut status, 0) }, child);
        assert!(libc::WIFEXITED(status), "child status was 0x{status:x}");
        assert_eq!(libc::WEXITSTATUS(status), 0);
    }

    #[test]
    fn native_dynamic_loader_owns_main_relocations() {
        let dynamic = synthetic_dynamic_elf(Some(b"/lib/ld-linux-aarch64.so.1\0"));
        let elf = Elf::parse(&dynamic).expect("synthetic dynamic ELF should parse");

        assert!(!native_image_needs_eager_relocations(&elf));
    }

    #[test]
    fn native_static_pie_needs_eager_relative_relocations() {
        let static_pie = synthetic_dynamic_elf(None);
        let elf = Elf::parse(&static_pie).expect("synthetic static PIE should parse");

        assert!(native_image_needs_eager_relocations(&elf));
    }
}
