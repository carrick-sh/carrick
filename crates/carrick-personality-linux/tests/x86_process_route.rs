use carrick_personality_linux::{
    dispatch::{Family, route_aarch64},
    entry::decode_x86_64,
    lifecycle::LifecycleCall,
};

#[test]
fn arm_ppoll_stays_forwarded_until_guest_wait_is_complete() {
    assert_eq!(route_aarch64(73, u64::MAX), Family::Unported);
}
use carrick_syscall_abi::syscall_x86_64::{SyscallRemap, lookup_x86_64};

#[test]
fn x86_process_calls_route_to_neutral_lifecycle_hooks() {
    for (native, expected) in [
        (61, LifecycleCall::Wait4),
        (247, LifecycleCall::WaitId),
        (231, LifecycleCall::ExitGroup),
    ] {
        let entry = lookup_x86_64(native).expect("process syscall has a table entry");
        let canonical = match entry.remap {
            SyscallRemap::Direct(canonical) => canonical.raw(),
            SyscallRemap::Private(canonical) => canonical.raw(),
            _ => panic!("process syscall must have a canonical route"),
        };
        let call = decode_x86_64(native, [0; 6], 0x7000);
        assert_eq!(call.canonical.raw(), canonical);
        assert_eq!(
            route_aarch64(call.canonical.raw(), u64::MAX),
            Family::Lifecycle(expected)
        );
    }
    // Native fork has no separate canonical ordinal: its ABI adapter uses
    // the same minimal SIGCHLD clone shape as the shared process owner.
    assert!(lookup_x86_64(57).is_none());
    let fork = decode_x86_64(57, [99; 6], 0x7000);
    assert_eq!(fork.canonical.raw(), 220);
    assert_eq!(fork.args, [17, 0, 0, 0, 0, 0]);
    assert_eq!(fork.native.raw(), 57);
    assert_eq!(
        route_aarch64(fork.canonical.raw(), u64::MAX),
        Family::Lifecycle(LifecycleCall::Clone)
    );
    // ARM's real syscall 220 retains its thread-clone interpretation.
    assert_eq!(
        route_aarch64(220, u64::MAX),
        Family::Lifecycle(LifecycleCall::Clone)
    );
    assert_eq!(
        route_aarch64(260, u64::MAX),
        Family::Lifecycle(LifecycleCall::Wait4)
    );
    assert_eq!(
        route_aarch64(94, u64::MAX),
        Family::Lifecycle(LifecycleCall::ExitGroup)
    );
}

#[test]
fn x86_sched_calls_route_to_neutral_sched_family() {
    for (native, expected) in [
        (
            146,
            carrick_personality_linux::sched::SchedCall::GetPriorityMax,
        ),
        (
            147,
            carrick_personality_linux::sched::SchedCall::GetPriorityMin,
        ),
        (
            148,
            carrick_personality_linux::sched::SchedCall::RrGetInterval,
        ),
    ] {
        let entry = lookup_x86_64(native).expect("sched syscall has a table entry");
        let canonical = match entry.remap {
            SyscallRemap::Direct(canonical) => canonical.raw(),
            SyscallRemap::Private(canonical) => canonical.raw(),
            _ => panic!("sched syscall must have a canonical route"),
        };
        let call = decode_x86_64(native, [0; 6], 0x7000);
        assert_eq!(call.canonical.raw(), canonical);
        assert_eq!(
            route_aarch64(call.canonical.raw(), u64::MAX),
            Family::Sched(expected)
        );
    }
}

#[test]
fn arm_sigreturn_uses_the_native_signal_owner() {
    // #323 pre-approved the ARM return through the retained signal owner.
    assert_eq!(
        route_aarch64(139, u64::MAX),
        Family::Signal(carrick_personality_linux::signal::SignalCall::RtSigreturn)
    );
    assert_eq!(
        carrick_personality_linux::dispatch::route_x86(139, u64::MAX),
        Family::Signal(carrick_personality_linux::signal::SignalCall::RtSigreturn)
    );
}

#[test]
fn pidfds_remain_unported_until_the_native_owner_exists() {
    assert_eq!(route_aarch64(424, u64::MAX), Family::Unported);
    assert_eq!(
        carrick_personality_linux::dispatch::route_x86(424, u64::MAX),
        Family::Unported
    );
}

#[test]
fn arm_signal_routes_match_preapproved_native_owner() {
    for ordinal in (129..=139).chain(core::iter::once(240)) {
        let expected = match ordinal {
            129 => Family::Signal(carrick_personality_linux::signal::SignalCall::Kill),
            130 => Family::Signal(carrick_personality_linux::signal::SignalCall::Tkill),
            131 => Family::Signal(carrick_personality_linux::signal::SignalCall::Tgkill),
            132 => Family::Lifecycle(LifecycleCall::SigAltStack),
            133 => Family::Signal(carrick_personality_linux::signal::SignalCall::RtSigsuspend),
            // #323 pre-approved ARM rt_sigaction for the native signal owner.
            134 => Family::Signal(carrick_personality_linux::signal::SignalCall::RtSigaction),
            135 => Family::Lifecycle(LifecycleCall::SigProcMask),
            136 => Family::Signal(carrick_personality_linux::signal::SignalCall::RtSigpending),
            137 => Family::Signal(carrick_personality_linux::signal::SignalCall::RtSigtimedwait),
            138 => Family::Signal(carrick_personality_linux::signal::SignalCall::RtSigqueueinfo),
            139 => Family::Signal(carrick_personality_linux::signal::SignalCall::RtSigreturn),
            240 => Family::Signal(carrick_personality_linux::signal::SignalCall::RtTgsigqueueinfo),
            _ => unreachable!(),
        };
        assert_eq!(
            route_aarch64(ordinal, u64::MAX),
            expected,
            "ARM ordinal {ordinal}"
        );
    }
}

#[test]
fn x86_sysv_ipc_routes_to_ring_and_zeroes_abi_padding_bytes() {
    use carrick_core::personality::UserCopy;
    use carrick_guest_arch::{GuestIsa, UserVa};
    use carrick_personality_linux::dispatch::route_x86;
    use carrick_personality_linux::identity::TaskCredentials;
    use carrick_personality_linux::ipc::namespace::IpcNamespace;
    use carrick_personality_linux::ipc::{
        IPC_CREAT, IPC_INFO, IPC_PRIVATE, IPC_STAT, IpcCall, IpcNative, IpcOutcome, LinuxMsginfo,
        LinuxMsqidDs, LinuxSembuf, LinuxSemidDs, LinuxSemidDsX86_64, LinuxSeminfo, MsgrcvResult,
        ProcessIpcVenue, invoke,
    };

    struct RouteVenue {
        ns: IpcNamespace,
        creds: TaskCredentials,
    }
    impl RouteVenue {
        fn new() -> Self {
            Self {
                ns: IpcNamespace::new(),
                creds: TaskCredentials::ROOT,
            }
        }
    }
    impl ProcessIpcVenue for RouteVenue {
        fn msgget(&mut self, key: i32, msgflg: i32) -> Result<i32, i64> {
            self.ns
                .msgget(&self.creds, key, msgflg)
                .map_err(|e| e.guest_retval())
        }
        fn msgctl(
            &mut self,
            msqid: i32,
            cmd: i32,
            buf: Option<&mut LinuxMsqidDs>,
        ) -> Result<i64, i64> {
            let out = buf.expect("IPC_STAT passes out record");
            self.ns
                .msgctl_stat(&self.creds, msqid, cmd, out)
                .map_err(|e| e.guest_retval())
        }
        fn msgctl_info(&mut self, _cmd: i32, buf: &mut LinuxMsginfo) -> Result<i64, i64> {
            self.ns.msgctl_info(buf).map_err(|e| e.guest_retval())
        }
        fn msgsnd(&mut self, _: i32, _: i64, _: &[u8], _: i32) -> Result<IpcOutcome, i64> {
            unreachable!()
        }
        fn msgrcv(&mut self, _: i32, _: UserVa, _: i64, _: i32, _: usize) -> MsgrcvResult {
            unreachable!()
        }
        fn msgrcv_restore(&mut self, _: i32, _: usize, _: i64, _: Vec<u8>) -> Result<(), i64> {
            unreachable!()
        }
        fn semget(&mut self, key: i32, nsems: i32, semflg: i32) -> Result<i32, i64> {
            self.ns
                .semget(&self.creds, key, nsems, semflg)
                .map_err(|e| e.guest_retval())
        }
        fn sem_nsems(&mut self, semid: i32) -> Result<usize, i64> {
            self.ns
                .sem_set(semid)
                .map(|s| s.sems.len())
                .map_err(|e| e.guest_retval())
        }
        fn semctl_rmid(&mut self, _: i32) -> Result<i64, i64> {
            unreachable!()
        }
        fn semctl_stat(
            &mut self,
            semid: i32,
            _semnum: i32,
            cmd: i32,
            ds: &mut LinuxSemidDs,
        ) -> Result<i64, i64> {
            self.ns
                .semctl_stat(&self.creds, semid, cmd, ds)
                .map_err(|e| e.guest_retval())
        }
        fn semctl_set(&mut self, _: i32, _: &LinuxSemidDs) -> Result<i64, i64> {
            unreachable!()
        }
        fn semctl_info(&mut self, _: i32, _: &mut LinuxSeminfo) -> Result<i64, i64> {
            unreachable!()
        }
        fn semctl_getval(&mut self, _: i32, _: i32) -> Result<i64, i64> {
            unreachable!()
        }
        fn semctl_setval(&mut self, _: i32, _: i32, _: u64) -> Result<i64, i64> {
            unreachable!()
        }
        fn semctl_getpid(&mut self, _: i32, _: i32) -> Result<i64, i64> {
            unreachable!()
        }
        fn semctl_getncnt(&mut self, _: i32, _: i32) -> Result<i64, i64> {
            unreachable!()
        }
        fn semctl_getzcnt(&mut self, _: i32, _: i32) -> Result<i64, i64> {
            unreachable!()
        }
        fn semctl_getall(&mut self, _: i32, _: &mut [u16]) -> Result<i64, i64> {
            unreachable!()
        }
        fn semctl_setall(&mut self, _: i32, _: &[u16]) -> Result<i64, i64> {
            unreachable!()
        }
        fn semop(
            &mut self,
            _: i32,
            _: &[LinuxSembuf],
            _: Option<core::time::Duration>,
        ) -> Result<IpcOutcome, i64> {
            unreachable!()
        }
    }

    struct X86IpcEnv<'v> {
        args: [u64; 6],
        buf: Vec<u8>,
        base: u64,
        venue: &'v mut RouteVenue,
    }
    impl UserCopy for X86IpcEnv<'_> {
        fn copy_in(&mut self, dst: &mut [u8], src: UserVa) -> bool {
            let off = (src.raw() - self.base) as usize;
            dst.copy_from_slice(&self.buf[off..off + dst.len()]);
            true
        }
        fn copy_out(&mut self, dst: UserVa, src: &[u8]) -> bool {
            let off = (dst.raw() - self.base) as usize;
            self.buf[off..off + src.len()].copy_from_slice(src);
            true
        }
    }
    impl<'a> IpcNative<'a> for X86IpcEnv<'_> {
        fn arguments(&self) -> [u64; 6] {
            self.args
        }
        fn process_ipc(&mut self) -> Option<&mut dyn ProcessIpcVenue> {
            Some(self.venue)
        }
        fn guest_isa(&self) -> GuestIsa {
            GuestIsa::X86_64
        }
    }

    let msgctl_dec = decode_x86_64(71, [0; 6], 0x7000);
    let semctl_dec = decode_x86_64(66, [0; 6], 0x7000);
    assert_eq!(
        route_x86(msgctl_dec.canonical.raw(), u64::MAX),
        Family::Ipc(IpcCall::MsgCtl)
    );
    assert_eq!(
        route_x86(semctl_dec.canonical.raw(), u64::MAX),
        Family::Ipc(IpcCall::SemCtl)
    );

    let mut venue = RouteVenue::new();
    let msqid = venue.msgget(IPC_PRIVATE, IPC_CREAT | 0o600).unwrap();
    let semid = venue.semget(IPC_PRIVATE, 2, IPC_CREAT | 0o600).unwrap();
    let base = 0x9000u64;

    let mut env = X86IpcEnv {
        args: [msqid as u64, IPC_STAT as u64, base, 0, 0, 0],
        buf: vec![0xFE; core::mem::size_of::<LinuxMsqidDs>()],
        base,
        venue: &mut venue,
    };
    assert!(matches!(
        invoke(IpcCall::MsgCtl, &mut env),
        IpcOutcome::Returned(r) if r.raw() == 0
    ));
    assert_eq!(&env.buf[28..32], &[0, 0, 0, 0]);

    let mut info_env = X86IpcEnv {
        args: [0, IPC_INFO as u64, base, 0, 0, 0],
        buf: vec![0xFE; core::mem::size_of::<LinuxMsginfo>()],
        base,
        venue: &mut venue,
    };
    assert!(matches!(
        invoke(IpcCall::MsgCtl, &mut info_env),
        IpcOutcome::Returned(r) if r.raw() >= 0
    ));
    assert_eq!(&info_env.buf[30..32], &[0, 0]);

    let mut sem_env = X86IpcEnv {
        args: [semid as u64, 0, IPC_STAT as u64, base, 0, 0],
        buf: vec![0xFE; core::mem::size_of::<LinuxSemidDsX86_64>()],
        base,
        venue: &mut venue,
    };
    assert!(matches!(
        invoke(IpcCall::SemCtl, &mut sem_env),
        IpcOutcome::Returned(r) if r.raw() == 0
    ));
    assert_eq!(&sem_env.buf[28..32], &[0, 0, 0, 0]);
}
