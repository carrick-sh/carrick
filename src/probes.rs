use crate::compat::{CompatEvent, SyscallArgs};

/// USDT probes for the carrick provider. The `usdt` crate's hard cap is
/// 6 args per probe, so syscall args ride as a `&SyscallArgs` reference
/// — usdt JSON-encodes it through serde and passes the resulting
/// C-string pointer to DTrace. Consumers use `copyinstr(argN)` to read
/// the JSON (looks like `[v0,v1,v2,v3,v4,v5]`).
#[usdt::provider(provider = "carrick")]
mod carrick_usdt {
    use crate::compat::SyscallArgs;

    fn syscall__entry(_: u64, _: &str, _: &SyscallArgs) {}
    fn syscall__return(_: u64, _: &str, _: i64, _: i32) {}
    fn unhandled__syscall(_: u64, _: &str, _: &SyscallArgs) {}
    fn partial__syscall(_: u64, _: &str, _: &SyscallArgs, _: &str) {}
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
    /// Fires every time the trap engine returns from `vcpu.run` with
    /// a syscall exit. Args are the guest's EL0 PC at the trap (taken
    /// from ELR_EL1, which HVF sets to instruction-after-svc), the
    /// syscall number from x8, and x0 (first arg / clone retval).
    /// Lower overhead than `syscall-entry` for cases where you only
    /// want to spot loops.
    fn vcpu__trap(_: u64, _: u64, _: u64, _: u64) {}
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
}

pub fn fork_pre(pc: u64, elr: u64, cpsr: u64) {
    carrick_usdt::fork__pre!(|| (pc, elr, cpsr));
}

pub fn path_open(path: &str, result_size: u64, errno: i32) {
    let pid = unsafe { libc::getpid() as u32 };
    carrick_usdt::path__open!(|| (pid, path, result_size, errno));
}


pub fn fork_post(pid: i32, pc: u64, elr: u64) {
    carrick_usdt::fork__post!(|| (pid, pc, elr));
}

pub fn vcpu_trap(guest_pc: u64, x8: u64, x0: u64, x30: u64) {
    carrick_usdt::vcpu__trap!(|| (guest_pc, x8, x0, x30));
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
            carrick_usdt::syscall__entry!(|| (*number, name.as_str(), args));
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
            carrick_usdt::unhandled__syscall!(|| (*number, name.as_str(), args));
        }
        CompatEvent::PartialSyscall {
            number,
            name,
            args,
            reason,
        } => {
            carrick_usdt::partial__syscall!(|| (*number, name.as_str(), args, reason.as_str()));
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
