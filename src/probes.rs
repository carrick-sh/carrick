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
    /// Fires before `libc::fork` from the trap engine's clone path.
    /// Args are the captured pre-fork vCPU PC, ELR_EL1, and CPSR.
    fn fork__pre(_: u64, _: u64, _: u64) {}
    /// Fires after the parent/child have rebuilt their HVF context and
    /// restored the snapshot. `pid` is the libc::fork return value
    /// (0 in the child, child pid in the parent).
    fn fork__post(_: i32, _: u64, _: u64) {}
}

pub fn fork_pre(pc: u64, elr: u64, cpsr: u64) {
    carrick_usdt::fork__pre!(|| (pc, elr, cpsr));
}

pub fn fork_post(pid: i32, pc: u64, elr: u64) {
    carrick_usdt::fork__post!(|| (pid, pc, elr));
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
    }
}

#[allow(dead_code)]
fn _assert_args_are_serializable(args: &SyscallArgs) -> &SyscallArgs {
    args
}
