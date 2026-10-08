//! Linux rt_sigaction wire policy over the execution lane's exact sighand.
use crate::abi::entry::SyscallResult;
use crate::lifecycle::{LifecycleNative, LifecycleOutcome};
use carrick_guest_arch::UserVa;
use carrick_signal_core::{SignalSet, policy::*};
use carrick_syscall_abi::signal::*;

/// Validated caller-thread target. Signal zero is an identity probe.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ThreadSignalRequest {
    group: Option<core::num::NonZeroU32>,
    thread: core::num::NonZeroU32,
    signal: Option<Signal>,
}
impl ThreadSignalRequest {
    pub fn decode(group: Option<u64>, thread: u64, signal: u64) -> Result<Self, SyscallResult> {
        let positive = |raw: u64| {
            let value = raw as i32;
            if value <= 0 {
                None
            } else {
                core::num::NonZeroU32::new(value as u32)
            }
        };
        let thread = positive(thread).ok_or(SyscallResult::new(-22))?;
        let group = match group {
            Some(raw) => Some(positive(raw).ok_or(SyscallResult::new(-22))?),
            None => None,
        };
        let raw_signal = signal as i32;
        let signal = if raw_signal == 0 {
            None
        } else {
            Some(Signal::from_number(raw_signal).ok_or(SyscallResult::new(-22))?)
        };
        Ok(Self {
            group,
            thread,
            signal,
        })
    }
    pub fn matches(self, group: u32, thread: u32) -> bool {
        self.thread.get() == thread && self.group.is_none_or(|target| target.get() == group)
    }
    pub const fn signal(self) -> Option<Signal> {
        self.signal
    }
}

fn word(bytes: &[u8; 32], offset: usize) -> u64 {
    let mut value = [0; 8];
    value.copy_from_slice(&bytes[offset..offset + 8]);
    u64::from_le_bytes(value)
}
pub fn decode_action(bytes: &[u8; 32]) -> Action {
    let handler = word(bytes, 0);
    let flags = word(bytes, 8);
    Action {
        disposition: match handler {
            LINUX_SIG_DFL => Disposition::Default,
            LINUX_SIG_IGN => Disposition::Ignore,
            address => Disposition::Handler(HandlerAddress(address)),
        },
        flags: ActionFlags {
            on_stack: flags & LINUX_SA_ONSTACK != 0,
            reset_hand: flags & LINUX_SA_RESETHAND != 0,
            nodefer: flags & LINUX_SA_NODEFER != 0,
            restart: flags & LINUX_SA_RESTART != 0,
            siginfo: flags & LINUX_SA_SIGINFO != 0,
            no_child_wait: flags & LINUX_SA_NOCLDWAIT != 0,
            no_child_stop: flags & LINUX_SA_NOCLDSTOP != 0,
        },
        mask: SignalSet::from_bits(word(bytes, 24) & !((1 << 8) | (1 << 18))),
        restorer: (flags & LINUX_SA_RESTORER != 0).then(|| RestorerAddress(word(bytes, 16))),
    }
}
pub fn encode_action(action: Action) -> [u8; 32] {
    let handler = match action.disposition {
        Disposition::Default => LINUX_SIG_DFL,
        Disposition::Ignore => LINUX_SIG_IGN,
        Disposition::Handler(address) => address.0,
    };
    let mut flags = 0;
    for (enabled, flag) in [
        (action.flags.on_stack, LINUX_SA_ONSTACK),
        (action.flags.reset_hand, LINUX_SA_RESETHAND),
        (action.flags.nodefer, LINUX_SA_NODEFER),
        (action.flags.restart, LINUX_SA_RESTART),
        (action.flags.siginfo, LINUX_SA_SIGINFO),
        (action.flags.no_child_wait, LINUX_SA_NOCLDWAIT),
        (action.flags.no_child_stop, LINUX_SA_NOCLDSTOP),
        (action.restorer.is_some(), LINUX_SA_RESTORER),
    ] {
        if enabled {
            flags |= flag;
        }
    }
    let mut bytes = [0; 32];
    for (chunk, value) in bytes.chunks_exact_mut(8).zip([
        handler,
        flags,
        action.restorer.map_or(0, |address| address.0),
        action.mask.bits(),
    ]) {
        chunk.copy_from_slice(&value.to_le_bytes());
    }
    bytes
}
pub fn sigaction<'a>(native: &mut dyn LifecycleNative<'a>) -> Option<LifecycleOutcome> {
    let args = native.arguments();
    let returned = |value| LifecycleOutcome::Returned {
        result: SyscallResult::new(value),
        work: false,
    };
    if args[3] != 8 {
        return Some(returned(-22));
    }
    let raw = args[0] as u32;
    let Some(signal) = i32::try_from(raw).ok().and_then(Signal::from_number) else {
        return Some(returned(-22));
    };
    let replacement = if args[1] != 0 {
        if signal.uncatchable() {
            return Some(returned(-22));
        }
        let mut bytes = [0; 32];
        if !native.copy_in(&mut bytes, UserVa::new(args[1])) {
            return Some(returned(-14));
        }
        Some(decode_action(&bytes))
    } else {
        None
    };
    let old = match native.signal_action(signal, replacement)? {
        Ok(old) => old,
        Err(result) => {
            return Some(LifecycleOutcome::Returned {
                result,
                work: false,
            });
        }
    };
    if args[2] != 0 && !native.copy_out(UserVa::new(args[2]), &encode_action(old)) {
        return Some(returned(-14));
    }
    Some(returned(0))
}

/// Command completion uses an exit code; guest waiters retain the original
/// Linux wait encoding. A signal is reported as 128 + signal, never raised
/// against the carrier. Stopped/continued/nonterminal records are invalid here.
pub fn command_exit_code(status: carrick_sched_core::process::LinuxWaitStatus) -> Option<u8> {
    let raw = status.raw();
    if raw < 0 {
        return None;
    }
    if raw & !0xff00 == 0 {
        return Some((raw >> 8) as u8);
    }
    if raw & !0xff == 0 {
        let signal = raw & 0x7f;
        if (1..=64).contains(&signal) {
            return Some(128 + signal as u8);
        }
    }
    None
}
