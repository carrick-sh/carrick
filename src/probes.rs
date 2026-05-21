use crate::compat::{CompatEvent, SyscallArgs};

/// USDT probes for the carrick provider. The `usdt` crate's hard cap is
/// 6 args per probe, so syscall args ride as a `&SyscallArgs` reference
/// — usdt JSON-encodes it through serde and passes the resulting
/// C-string pointer to DTrace. Consumers use `copyinstr(argN)` to read
/// the JSON (looks like `[v0,v1,v2,v3,v4,v5]`).
#[usdt::provider(provider = "carrick")]
mod carrick_usdt {
    use crate::compat::SyscallArgs;

    // arg2 is the ADDRESS of a `SyscallArgs` ([u64; 6], contiguous); DTrace
    // does `copyin(arg2, 48)` and reads the six args by offset. This probe
    // fires on EVERY guest syscall, so we must NOT JSON-encode here — that
    // string-builds on every fire even for a script that only wants one
    // syscall, which is what made `carrick trace` slow (DTrace itself is
    // production-safe; the cost was ours). Same raw-pointer trick as
    // `vcpu__trap`.
    fn syscall__entry(_: u64, _: &str, _: u64) {}
    fn syscall__return(_: u64, _: &str, _: i64, _: i32) {}
    // arg2 is the ADDRESS of a `SyscallArgs` ([u64; 6]); DTrace copyin's 48
    // bytes — same raw-pointer convention as `syscall__entry`, no JSON.
    fn unhandled__syscall(_: u64, _: &str, _: u64) {}
    fn partial__syscall(_: u64, _: &str, _: u64, _: &str) {}
    fn unhandled__ioctl(_: i32, _: u64, _: u64) {}
    fn proc__read__unimplemented(_: &str) {}
    fn sys__read__unimplemented(_: &str) {}
    fn signal__unsupported(_: i32, _: &str) {}
    /// Fires on every guest syscall that passes flag bits we don't
    /// recognise. Catches Linux ABI drift loudly instead of letting
    /// the dispatcher silently drop behaviour the guest expected.
    fn unknown__syscall__flags(_: u64, _: &str, _: u32, _: u64) {}
    /// Fires before `libc::fork` from the trap engine's clone path.
    /// Args are the captured pre-fork vCPU PC, ELR_EL1, and CPSR.
    fn fork__pre(_: u64, _: u64, _: u64) {}
    /// Fires after the parent/child have rebuilt their HVF context and
    /// restored the snapshot. `pid` is the libc::fork return value
    /// (0 in the child, child pid in the parent).
    fn fork__post(_: i32, _: u64, _: u64) {}
    /// Fires every syscall trap. `arg0` is the ADDRESS of a
    /// `compat::GuestRegs` (`#[repr(C)]`); DTrace does
    /// `copyin(arg0, sizeof(gregs_t))` and reads fields by offset. A
    /// raw pointer (not JSON) keeps this hot probe cheap and lets D
    /// read full u64 register values exactly.
    fn vcpu__trap(_: u64) {}
    /// Fires when `execve_into` has finished swapping the engine to
    /// the new image. `path`, `entry`, `initial_sp`, `mapping_count`
    /// let dtrace operators verify the new process layout.
    fn execve__loaded(_: &str, _: u64, _: u64, _: u64) {}
    /// Fires at the tail of `execve_into` with the actual SCTLR/TTBR0/
    /// MAIR values read back from HVF. Use this to verify the new
    /// process's stage-1 MMU state matches what the fresh-from-cli
    /// case sets up.
    fn execve__sysregs(_: u64, _: u64, _: u64) {}
    /// Fires every time the dispatcher's `open_at_path` resolves a
    /// guest path. `pid` is the carrick-host pid (so the parent vs
    /// forked-children streams are demultiplexable). `result_size`
    /// is the bytes returned (for File) or `0` (for Directory /
    /// errno). `errno` is `0` on success.
    fn path__open(_: u32, _: &str, _: u64, _: i32) {}
    /// Fires when a guest process exits via exit_group. `pid` is the
    /// carrick-host pid; correlate with `execve__loaded` (same pid) to
    /// see which binary exited with which code.
    fn guest__exit(_: u32, _: i32) {}
    /// Fires on execve with the joined argv (space-separated), so
    /// dtrace operators can see exactly how the guest invokes a
    /// child (e.g. apt's sqv method calling /usr/bin/sqv).
    fn execve__argv(_: u32, _: &str, _: &str) {}
    /// Host-pipe I/O: `dir` is 0 for read, 1 for write; `n` is the
    /// byte count (negative on error). Used to trace whether a forked
    /// child's stdout actually reaches the parent's pipe read.
    fn host__pipe__io(_: u32, _: i32, _: i32, _: i64) {}
    /// Fires on a filesystem-backend decision/outcome. `op` names the
    /// operation + result (e.g. "set_times:ok", "set_times:open_none",
    /// "set_times:futimens_err", "unlink", "rename"), `path` is the
    /// resolved guest path, `errno` is the Linux errno carrick returns
    /// (0 on success). Lets `carrick trace` see WHY a host-backed fs
    /// syscall returned an errno — the internal reason invisible to the guest.
    fn fs__op(_: u32, _: &str, _: &str, _: i32) {}
    /// Fires when a guest signal handler frame is injected. `signum` is the
    /// Linux signal, `saved_pc` the pre-signal PC stored in the sigframe (the
    /// PC the eventual rt_sigreturn must restore), `new_sp` the SP_EL0 the
    /// frame was written at, `handler` the guest handler entry. Lets a trace
    /// see exactly what state is captured for later restore.
    fn signal__inject(_: i32, _: u64, _: u64, _: u64) {}
    /// Fires inside rt_sigreturn/restore. `saved_pc` is the PC about to be
    /// restored into ELR_EL1, `sp` the SP_EL0 the frame was read from,
    /// `magic` the frame magic read back. A corrupted `saved_pc` or `magic`
    /// here pinpoints sigframe corruption (the "PROT_REA" wild-PC crash).
    fn signal__restore(_: u64, _: u64, _: u64) {}
    /// Reusable guest-memory watchpoint. When `CARRICK_WATCH_ADDR=<hex>` is
    /// set, fires before EVERY syscall with (`syscall_nr`, `addr`, the current
    /// little-endian u64 at `addr`). Lets a trace bracket exactly which
    /// syscall a guest address changes across — e.g. which operation corrupts
    /// a GOT slot. Zero-cost (and not even read) when the env var is unset.
    fn mem__watch(_: u64, _: u64, _: u64) {}
}

pub fn fork_pre(pc: u64, elr: u64, cpsr: u64) {
    carrick_usdt::fork__pre!(|| (pc, elr, cpsr));
}

// For these helpers the PID read happens INSIDE the closure. usdt's
// `probe!` macro only invokes the closure when the probe is enabled
// (it gates on `is_enabled()` in asm before calling), so `getpid()`
// is genuinely zero-cost when no DTrace consumer is attached.
pub fn path_open(path: &str, result_size: u64, errno: i32) {
    carrick_usdt::path__open!(|| (
        libc::getpid() as u32,
        path,
        result_size,
        errno
    ));
}

pub fn guest_exit(code: i32) {
    carrick_usdt::guest__exit!(|| (libc::getpid() as u32, code));
}

pub fn execve_argv(path: &str, argv: &[String]) {
    // `argv.join` allocates, so it can't move inside the closure (the
    // returned `&str` would dangle once the closure's local String
    // drops, before usdt serialises it). execve is rare, so the
    // unconditional join is acceptable; the hot paths above are the
    // ones that matter for zero-cost-when-disabled.
    let joined = argv.join(" ");
    carrick_usdt::execve__argv!(|| (
        libc::getpid() as u32,
        path,
        joined.as_str()
    ));
}

pub fn fs_op(op: &str, path: &str, errno: i32) {
    carrick_usdt::fs__op!(|| (libc::getpid() as u32, op, path, errno));
}

pub fn host_pipe_io(host_fd: i32, dir: i32, n: i64) {
    carrick_usdt::host__pipe__io!(|| (
        libc::getpid() as u32,
        host_fd,
        dir,
        n
    ));
}



pub fn fork_post(pid: i32, pc: u64, elr: u64) {
    carrick_usdt::fork__post!(|| (pid, pc, elr));
}

pub fn signal_inject(signum: i32, saved_pc: u64, new_sp: u64, handler: u64) {
    carrick_usdt::signal__inject!(|| (signum, saved_pc, new_sp, handler));
}

pub fn signal_restore(saved_pc: u64, sp: u64, magic: u64) {
    carrick_usdt::signal__restore!(|| (saved_pc, sp, magic));
}

pub fn mem_watch(syscall_nr: u64, addr: u64, value: u64) {
    carrick_usdt::mem__watch!(|| (syscall_nr, addr, value));
}

// `#[inline(never)]`: usdt embeds the probe site (an asm! anchor) in
// the function body. If this gets inlined into multiple callers, each
// copy becomes a SEPARATE DTrace probe site that fires independently
// — so a single logical trap would fire `vcpu-trap` twice. Pinning the
// function to one body keeps it a single, stable probe site.
#[inline(never)]
pub fn vcpu_trap(regs: &crate::compat::GuestRegs) {
    // Pass the struct's address; DTrace copyin's it. The reference is
    // live for the duration of this (inline(never)) function, which is
    // where usdt's synchronous probe fire happens, so the pointer is
    // valid when DTrace reads it.
    let ptr = regs as *const crate::compat::GuestRegs as u64;
    carrick_usdt::vcpu__trap!(|| ptr);
}


pub fn execve_loaded(path: &str, entry: u64, initial_sp: u64, mapping_count: u64) {
    carrick_usdt::execve__loaded!(|| (path, entry, initial_sp, mapping_count));
}

pub fn execve_sysregs(sctlr: u64, ttbr0: u64, mair: u64) {
    carrick_usdt::execve__sysregs!(|| (sctlr, ttbr0, mair));
}

pub fn register_dtrace_probes() -> Result<(), usdt::Error> {
    usdt::register_probes()
}

pub fn fire(event: &CompatEvent) {
    fire_usdt(event);
}

fn fire_usdt(event: &CompatEvent) {
    match event {
        CompatEvent::SyscallEntry { number, name, args } => {
            // `args` lives in `event` for the duration of this synchronous
            // probe fire, so its address is valid when DTrace copyin's it.
            let args_ptr = args as *const SyscallArgs as u64;
            carrick_usdt::syscall__entry!(|| (*number, name.as_str(), args_ptr));
        }
        CompatEvent::SyscallReturn {
            number,
            name,
            retval,
            errno,
        } => {
            carrick_usdt::syscall__return!(|| {
                (*number, name.as_str(), *retval, errno.unwrap_or(0))
            });
        }
        CompatEvent::UnhandledSyscall { number, name, args } => {
            let args_ptr = args as *const SyscallArgs as u64;
            carrick_usdt::unhandled__syscall!(|| (*number, name.as_str(), args_ptr));
        }
        CompatEvent::PartialSyscall {
            number,
            name,
            args,
            reason,
        } => {
            let args_ptr = args as *const SyscallArgs as u64;
            carrick_usdt::partial__syscall!(|| (*number, name.as_str(), args_ptr, reason.as_str()));
        }
        CompatEvent::UnhandledIoctl { fd, request, arg } => {
            carrick_usdt::unhandled__ioctl!(|| (*fd, *request, *arg));
        }
        CompatEvent::ProcReadUnimplemented { path } => {
            carrick_usdt::proc__read__unimplemented!(|| path.as_str());
        }
        CompatEvent::SysReadUnimplemented { path } => {
            carrick_usdt::sys__read__unimplemented!(|| path.as_str());
        }
        CompatEvent::SignalUnsupported { signum, reason } => {
            carrick_usdt::signal__unsupported!(|| (*signum, reason.as_str()));
        }
        CompatEvent::UnknownSyscallFlags {
            number,
            name,
            argument,
            unknown_bits,
        } => {
            carrick_usdt::unknown__syscall__flags!(|| (
                *number,
                name.as_str(),
                *argument,
                *unknown_bits
            ));
        }
    }
}

#[allow(dead_code)]
fn _assert_args_are_serializable(args: &SyscallArgs) -> &SyscallArgs {
    args
}
