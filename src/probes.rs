use crate::compat::{CompatEvent, SyscallArgs};

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
            carrick_usdt::partial__syscall!(|| { (*number, name.as_str(), args, reason.as_str()) });
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
