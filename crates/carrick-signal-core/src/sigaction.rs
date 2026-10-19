//! The one rt_sigaction(2) argument decoder, validator and wire codec.
//!
//! Semantic authority: sigaction(2), signal(7) and execve(2) (clean-room,
//! man-pages only). Every Carrick lane that serves `rt_sigaction` — the EL1
//! ring and the host dispatcher — calls [`rt_sigaction`] through its own
//! [`SigactionPort`]. No consumer decodes `struct sigaction`, orders its
//! errors, or translates `SA_*` bits itself; `just lint-domains` rejects a
//! second decoder (`scripts/migrate/check-signal-core-boundary.py`).
//!
//! Error order (one place, fixed): a wrong `sigsetsize` is `EINVAL`; an
//! unreadable `act` is `EFAULT`; then an out-of-range signal, or an attempt
//! to change SIGKILL/SIGSTOP, is `EINVAL`; the exchange is committed before
//! `oldact` is written, so an unwritable `oldact` is `EFAULT` after the new
//! action is already installed.

use carrick_syscall_abi::{
    LINUX_EFAULT, LINUX_EINVAL, LINUX_RT_SIGSET_SIZE, LINUX_SA_NOCLDSTOP, LINUX_SA_NOCLDWAIT,
    LINUX_SA_NODEFER, LINUX_SA_ONSTACK, LINUX_SA_RESETHAND, LINUX_SA_RESTART, LINUX_SA_RESTORER,
    LINUX_SA_SIGINFO, LINUX_SIG_DFL, LINUX_SIG_IGN, LinuxErrno, LinuxSigaction,
};

use crate::SignalSet;
use crate::policy::{Action, ActionFlags, Disposition, HandlerAddress, RestorerAddress, Signal};

/// Translate one guest `struct sigaction` into the typed policy action.
///
/// `SA_RESTORER` alone makes `sa_restorer` meaningful (sigaction(2)); a
/// restorer address without the flag is not retained. SIGKILL and SIGSTOP
/// cannot be blocked, so they are removed from `sa_mask` (signal(7)). Flag
/// bits this core does not name are not retained.
pub fn decode_action(wire: LinuxSigaction) -> Action {
    let handler = wire.sa_handler;
    let bits = wire.sa_flags;
    let restorer = wire.sa_restorer;
    let mask = wire.sa_mask;
    let disposition = match handler {
        LINUX_SIG_DFL => Disposition::Default,
        LINUX_SIG_IGN => Disposition::Ignore,
        address => Disposition::Handler(HandlerAddress(address)),
    };
    let flags = ActionFlags {
        reset_hand: bits & LINUX_SA_RESETHAND != 0,
        on_stack: bits & LINUX_SA_ONSTACK != 0,
        nodefer: bits & LINUX_SA_NODEFER != 0,
        restart: bits & LINUX_SA_RESTART != 0,
        siginfo: bits & LINUX_SA_SIGINFO != 0,
        no_child_wait: bits & LINUX_SA_NOCLDWAIT != 0,
        no_child_stop: bits & LINUX_SA_NOCLDSTOP != 0,
    };
    Action {
        disposition,
        flags,
        mask: SignalSet::from_bits(mask[0])
            .without(Signal::KILL)
            .without(Signal::STOP),
        restorer: (bits & LINUX_SA_RESTORER != 0).then_some(RestorerAddress(restorer)),
    }
}

/// The exact inverse of [`decode_action`] for every action it produces.
pub fn encode_action(action: Action) -> LinuxSigaction {
    let mut wire = LinuxSigaction::empty();
    wire.sa_handler = match action.disposition {
        Disposition::Default => LINUX_SIG_DFL,
        Disposition::Ignore => LINUX_SIG_IGN,
        Disposition::Handler(address) => address.0,
    };
    let named = [
        (action.flags.no_child_stop, LINUX_SA_NOCLDSTOP),
        (action.flags.no_child_wait, LINUX_SA_NOCLDWAIT),
        (action.flags.siginfo, LINUX_SA_SIGINFO),
        (action.flags.on_stack, LINUX_SA_ONSTACK),
        (action.flags.restart, LINUX_SA_RESTART),
        (action.flags.nodefer, LINUX_SA_NODEFER),
        (action.flags.reset_hand, LINUX_SA_RESETHAND),
    ];
    let mut bits = named
        .iter()
        .filter(|(set, _)| *set)
        .fold(0, |bits, (_, bit)| bits | bit);
    if let Some(restorer) = action.restorer {
        bits |= LINUX_SA_RESTORER;
        wire.sa_restorer = restorer.0;
    }
    wire.sa_flags = bits;
    wire.sa_mask = [action.mask.bits()];
    wire
}

/// Raw rt_sigaction(signum, act, oldact, sigsetsize) register arguments.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SigactionArgs {
    pub signum: u64,
    pub act: u64,
    pub oldact: u64,
    pub sigsetsize: u64,
}

impl SigactionArgs {
    pub const fn from_registers([signum, act, oldact, sigsetsize]: [u64; 4]) -> Self {
        Self {
            signum,
            act,
            oldact,
            sigsetsize,
        }
    }
}

/// One lane's guest memory and sighand owner, as rt_sigaction needs them.
pub trait SigactionPort {
    /// Copy the caller's `act`; `None` is a fault.
    fn read_action(&mut self, act: u64) -> Option<LinuxSigaction>;

    /// Return the current action and, when `new` is present, install it under
    /// one sighand admission. The owner applies the [`crate::policy::Installation`]
    /// discard to its pending sets in that same admission.
    fn exchange(&mut self, signal: Signal, new: Option<Action>) -> Result<Action, LinuxErrno>;

    /// Copy `old` to the caller's `oldact`; `false` is a fault.
    fn write_action(&mut self, oldact: u64, old: LinuxSigaction) -> bool;
}

/// rt_sigaction(2) for every lane. `signum` is the C `int` argument: only its
/// low 32 bits are significant.
pub fn rt_sigaction(args: SigactionArgs, port: &mut dyn SigactionPort) -> Result<(), LinuxErrno> {
    if args.sigsetsize != LINUX_RT_SIGSET_SIZE {
        return Err(LINUX_EINVAL);
    }
    let new = if args.act != 0 {
        Some(decode_action(
            port.read_action(args.act).ok_or(LINUX_EFAULT)?,
        ))
    } else {
        None
    };
    let signal = Signal::from_number(args.signum as u32 as i32).ok_or(LINUX_EINVAL)?;
    if new.is_some() && signal.uncatchable() {
        return Err(LINUX_EINVAL);
    }
    let old = port.exchange(signal, new)?;
    if args.oldact != 0 && !port.write_action(args.oldact, encode_action(old)) {
        return Err(LINUX_EFAULT);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::ActionTable;
    use alloc::vec::Vec;

    const ACT: u64 = 0x1000;
    const OLD: u64 = 0x2000;
    const BAD: u64 = 0xdead_0000;

    #[derive(Default)]
    struct Port {
        table: ActionTable,
        act: Option<LinuxSigaction>,
        written: Option<LinuxSigaction>,
        calls: Vec<&'static str>,
    }

    impl SigactionPort for Port {
        fn read_action(&mut self, act: u64) -> Option<LinuxSigaction> {
            self.calls.push("read");
            (act == ACT).then_some(self.act?)
        }
        fn exchange(&mut self, signal: Signal, new: Option<Action>) -> Result<Action, LinuxErrno> {
            self.calls.push("exchange");
            match new {
                Some(action) => self
                    .table
                    .install(signal, action)
                    .map(|installed| installed.previous)
                    .map_err(|_| LINUX_EINVAL),
                None => Ok(self.table.action(signal)),
            }
        }
        fn write_action(&mut self, oldact: u64, old: LinuxSigaction) -> bool {
            self.calls.push("write");
            if oldact != OLD {
                return false;
            }
            self.written = Some(old);
            true
        }
    }

    fn args(signum: u64, act: u64, oldact: u64) -> SigactionArgs {
        SigactionArgs::from_registers([signum, act, oldact, LINUX_RT_SIGSET_SIZE])
    }

    fn handler(address: u64) -> LinuxSigaction {
        let mut wire = LinuxSigaction::empty();
        wire.sa_handler = address;
        wire
    }

    #[test]
    fn codec_round_trips_named_flags_and_strips_unblockable_mask() {
        let mut wire = handler(0x4000);
        wire.sa_flags = LINUX_SA_SIGINFO | LINUX_SA_RESTART | LINUX_SA_RESTORER | LINUX_SA_ONSTACK;
        wire.sa_restorer = 0x5000;
        wire.sa_mask = [u64::MAX];
        let action = decode_action(wire);
        assert_eq!(action.restorer, Some(RestorerAddress(0x5000)));
        let encoded = encode_action(action);
        let mask = encoded.sa_mask;
        assert_eq!(mask[0], !((1 << 8) | (1 << 18)));
        let (flags, expected) = (encoded.sa_flags, wire.sa_flags);
        assert_eq!(flags, expected);
        assert_eq!(decode_action(encoded), action);

        let mut no_flag = handler(0x4000);
        no_flag.sa_restorer = 0x5000;
        let encoded = encode_action(decode_action(no_flag));
        let restorer = encoded.sa_restorer;
        assert_eq!(
            restorer, 0,
            "a restorer without SA_RESTORER is not retained"
        );
    }

    #[test]
    fn errors_follow_the_one_fixed_order() {
        let mut port = Port {
            act: Some(handler(0x4000)),
            ..Port::default()
        };
        let bad_size = SigactionArgs::from_registers([10, BAD, BAD, 4]);
        assert_eq!(rt_sigaction(bad_size, &mut port), Err(LINUX_EINVAL));
        assert!(port.calls.is_empty(), "sigsetsize precedes every access");

        for signum in [0, 9, 19, 65] {
            assert_eq!(
                rt_sigaction(args(signum, BAD, 0), &mut port),
                Err(LINUX_EFAULT),
                "an unreadable act faults before signal validation ({signum})"
            );
        }
        for signum in [0, 65, 9, 19] {
            assert_eq!(
                rt_sigaction(args(signum, ACT, 0), &mut port),
                Err(LINUX_EINVAL),
                "{signum}"
            );
        }
        assert_eq!(rt_sigaction(args(0, 0, OLD), &mut port), Err(LINUX_EINVAL));
        assert_eq!(rt_sigaction(args(9, 0, OLD), &mut port), Ok(()));
        assert_eq!(port.written, Some(LinuxSigaction::empty()));
    }

    #[test]
    fn unwritable_oldact_faults_after_the_install_commits() {
        let mut port = Port {
            act: Some(handler(0x4000)),
            ..Port::default()
        };
        assert_eq!(
            rt_sigaction(args(10, ACT, BAD), &mut port),
            Err(LINUX_EFAULT)
        );
        assert_eq!(
            port.table
                .action(Signal::from_number(10).unwrap())
                .disposition,
            Disposition::Handler(HandlerAddress(0x4000))
        );
        assert_eq!(port.calls, ["read", "exchange", "write"]);
    }

    #[test]
    fn signum_is_the_low_c_int() {
        let mut port = Port::default();
        assert_eq!(
            rt_sigaction(args((1 << 32) | 10, 0, OLD), &mut port),
            Ok(())
        );
        assert_eq!(
            rt_sigaction(args(u64::MAX, 0, OLD), &mut port),
            Err(LINUX_EINVAL)
        );
    }
}
