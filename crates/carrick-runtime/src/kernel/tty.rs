//! Carrier-local relay-to-kernel terminal signal routing.

use std::collections::BTreeMap;
use std::os::unix::io::RawFd;
use std::sync::{Arc, OnceLock, Weak};

use carrick_abi::LinuxErrno;
use parking_lot::Mutex;

use super::{ContainerId, Kernel, LinuxSignal, ProcessGroupId, SessionId, TaskLifecycle};

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum TtyKey {
    Launch,
    Pty(u32),
}

impl From<u32> for TtyKey {
    fn from(index: u32) -> Self {
        TtyKey::Pty(index)
    }
}

#[derive(Default)]
struct TtyState {
    kernel: Option<Weak<Kernel>>,
    container: Option<ContainerId>,
    session: Option<SessionId>,
    foreground: Option<ProcessGroupId>,
    acknowledged: bool,
    pending: u64,
    literal_next: bool,
}

#[derive(Default)]
struct TtyRegistry {
    launch: TtyState,
    ptys: BTreeMap<u32, TtyState>,
}

impl TtyRegistry {
    fn get_state_mut(&mut self, key: TtyKey) -> &mut TtyState {
        match key {
            TtyKey::Launch => &mut self.launch,
            TtyKey::Pty(index) => self.ptys.entry(index).or_default(),
        }
    }
}

fn slot() -> &'static Mutex<TtyRegistry> {
    static SLOT: OnceLock<Mutex<TtyRegistry>> = OnceLock::new();
    SLOT.get_or_init(|| Mutex::new(TtyRegistry::default()))
}

/// Begin a new interactive carrier session before the relay thread can observe
/// input. This removes any route or pending signals left by a prior run.
pub(crate) fn prepare() {
    let mut reg = slot().lock();
    reg.launch = TtyState::default();
}

pub(crate) fn install(kernel: &Arc<Kernel>) {
    let mut reg = slot().lock();
    reg.launch.kernel = Some(Arc::downgrade(kernel));
    reg.launch.container = None;
    reg.launch.acknowledged = false;
}

pub(super) fn acknowledge_ready(expected_kernel: &Kernel, container: ContainerId) {
    let (kernel, pending) = {
        let mut reg = slot().lock();
        let Some(kernel) = reg.launch.kernel.as_ref().and_then(Weak::upgrade) else {
            return;
        };
        if !std::ptr::eq(kernel.as_ref(), expected_kernel) {
            return;
        }
        reg.launch.container = Some(container);
        reg.launch.acknowledged = true;
        let pending = std::mem::take(&mut reg.launch.pending);
        (kernel, pending)
    };
    for signum in 1..=64 {
        if pending & (1_u64 << (signum - 1)) == 0 {
            continue;
        }
        if let Ok(signal) = LinuxSignal::for_signal_number(signum) {
            kernel.post_signal_to_tty_foreground(container, signal);
        }
    }
}

pub(crate) fn attach_pty(
    index: u32,
    kernel: &Arc<Kernel>,
    container: ContainerId,
    session: SessionId,
    foreground: ProcessGroupId,
    force: bool,
) -> Result<(), LinuxErrno> {
    let mut reg = slot().lock();
    let state = reg.ptys.entry(index).or_default();
    if let Some(existing) = state.session {
        if existing != session && !force {
            return Err(carrick_abi::LINUX_EPERM);
        }
    }
    state.kernel = Some(Arc::downgrade(kernel));
    state.container = Some(container);
    state.session = Some(session);
    state.foreground = Some(foreground);
    state.acknowledged = true;
    Ok(())
}

pub(crate) fn set_foreground_process_group(
    tty: TtyKey,
    session: SessionId,
    foreground: ProcessGroupId,
) -> Result<(), LinuxErrno> {
    let mut reg = slot().lock();
    match tty {
        TtyKey::Launch => {
            reg.launch.foreground = Some(foreground);
            Ok(())
        }
        TtyKey::Pty(index) => {
            let state = reg.ptys.get_mut(&index).ok_or(carrick_abi::LINUX_ENOTTY)?;
            if state.session != Some(session) {
                return Err(carrick_abi::LINUX_ENOTTY);
            }
            state.foreground = Some(foreground);
            Ok(())
        }
    }
}

pub(crate) fn foreground_process_group(
    tty: TtyKey,
    session: SessionId,
) -> Result<ProcessGroupId, LinuxErrno> {
    let reg = slot().lock();
    match tty {
        TtyKey::Launch => reg.launch.foreground.ok_or(carrick_abi::LINUX_ENOTTY),
        TtyKey::Pty(index) => {
            let state = reg.ptys.get(&index).ok_or(carrick_abi::LINUX_ENOTTY)?;
            if state.session != Some(session) {
                return Err(carrick_abi::LINUX_ENOTTY);
            }
            state.foreground.ok_or(carrick_abi::LINUX_ENOTTY)
        }
    }
}

/// Whether `session` already has a controlling terminal (the launch tty or
/// any guest pty). Linux refuses `TIOCSCTTY` with EPERM for a session leader
/// that already has one.
pub(crate) fn session_owns_tty(session: SessionId) -> bool {
    let reg = slot().lock();
    reg.launch.session == Some(session) || reg.ptys.values().any(|s| s.session == Some(session))
}

pub(crate) fn session(tty: TtyKey) -> Option<SessionId> {
    let reg = slot().lock();
    match tty {
        TtyKey::Launch => reg.launch.session,
        TtyKey::Pty(index) => reg.ptys.get(&index).and_then(|s| s.session),
    }
}

pub(crate) fn detach(tty: TtyKey) {
    let mut reg = slot().lock();
    match tty {
        TtyKey::Launch => {
            reg.launch.session = None;
            reg.launch.foreground = None;
        }
        TtyKey::Pty(index) => {
            reg.ptys.remove(&index);
        }
    }
}

pub(crate) fn detach_if_session(tty: TtyKey, session: SessionId) {
    let mut reg = slot().lock();
    match tty {
        TtyKey::Launch => {
            if reg.launch.session == Some(session) {
                reg.launch.session = None;
                reg.launch.foreground = None;
            }
        }
        TtyKey::Pty(index) => {
            if let Some(state) = reg.ptys.get_mut(&index) {
                if state.session == Some(session) {
                    state.session = None;
                    state.foreground = None;
                }
            }
        }
    }
}

pub(crate) fn route_foreground_signal(signum: i32) {
    route_foreground_signal_to_tty(TtyKey::Launch, signum);
}

pub(crate) fn route_foreground_signal_to_tty(tty: TtyKey, signum: i32) -> usize {
    let Ok(signal) = LinuxSignal::for_signal_number(signum) else {
        return 0;
    };
    let route = {
        let mut reg = slot().lock();
        match tty {
            TtyKey::Launch => {
                if !reg.launch.acknowledged {
                    reg.launch.pending |= 1_u64 << (signum - 1);
                    return 0;
                }
                reg.launch
                    .kernel
                    .as_ref()
                    .and_then(Weak::upgrade)
                    .zip(reg.launch.container)
                    .map(|(k, c)| (k, c, None))
            }
            TtyKey::Pty(index) => {
                let Some(state) = reg.ptys.get_mut(&index) else {
                    return 0;
                };
                let Some(kernel) = state.kernel.as_ref().and_then(Weak::upgrade) else {
                    return 0;
                };
                let Some(container) = state.container else {
                    return 0;
                };
                let Some(foreground) = state.foreground else {
                    return 0;
                };
                Some((kernel, container, Some(foreground)))
            }
        }
    };
    let Some((kernel, container, foreground)) = route else {
        return 0;
    };
    match foreground {
        Some(group) => deliver_signal_to_group(&kernel, container, group, signal),
        None => kernel.post_signal_to_tty_foreground(container, signal),
    }
}

fn deliver_signal_to_group(
    kernel: &Kernel,
    container: ContainerId,
    group_id: ProcessGroupId,
    signal: LinuxSignal,
) -> usize {
    let state = kernel.registry().state.read();
    let mut tasks = state
        .process_groups
        .get(&group_id)
        .filter(|record| record.container == container)
        .into_iter()
        .flat_map(|record| record.members.iter())
        .filter_map(|task| {
            state.tasks.get(&task.id).and_then(|record| {
                (record.task.key() == *task
                    && record.task.lifecycle() == TaskLifecycle::Live
                    && record.task.container().id() == container)
                    .then_some(*task)
            })
        })
        .collect::<Vec<_>>();
    drop(state);
    tasks.sort_unstable();
    tasks.dedup();
    let mut delivered = 0;
    for task in tasks {
        if kernel.post_signal_to_task_key(task, signal, None) {
            delivered += 1;
        }
    }
    delivered
}

#[derive(Default, Clone, Debug)]
pub(crate) struct LineDiscipline {
    pub(crate) literal_next: bool,
}

impl LineDiscipline {
    pub(crate) fn route_control_input(
        &mut self,
        bytes: &[u8],
        tty_fd: RawFd,
        tty: TtyKey,
        mut on_signal: impl FnMut(i32, u8, &libc::termios),
    ) -> Vec<u8> {
        let mut termios: libc::termios = unsafe { std::mem::zeroed() };
        if unsafe { libc::tcgetattr(tty_fd, &mut termios) } != 0
            || termios.c_lflag & libc::ISIG == 0
        {
            return bytes.to_vec();
        }
        let controls = [
            (termios.c_cc[libc::VINTR], carrick_abi::LINUX_SIGINT),
            (termios.c_cc[libc::VQUIT], carrick_abi::LINUX_SIGQUIT),
            (termios.c_cc[libc::VSUSP], carrick_abi::LINUX_SIGTSTP),
        ];
        let mut forwarded = Vec::with_capacity(bytes.len());
        for byte in bytes {
            if self.literal_next {
                forwarded.push(*byte);
                self.literal_next = false;
                continue;
            }
            if termios.c_lflag & (libc::ICANON | libc::IEXTEN) == (libc::ICANON | libc::IEXTEN)
                && termios.c_cc[libc::VLNEXT] != 0xff
                && *byte == termios.c_cc[libc::VLNEXT]
            {
                // Preserve VLNEXT itself so the line discipline quotes
                // the following byte; suppress signal recognition for that byte.
                forwarded.push(*byte);
                self.literal_next = true;
                continue;
            }
            if let Some((_, signal)) = controls
                .iter()
                .find(|(control, _)| *control != 0xff && byte == control)
            {
                if termios.c_lflag & libc::NOFLSH == 0 {
                    forwarded.clear();
                    unsafe {
                        libc::tcflush(tty_fd, libc::TCIOFLUSH);
                    }
                }
                on_signal(*signal, *byte, &termios);
                route_foreground_signal_to_tty(tty, *signal);
            } else {
                forwarded.push(*byte);
            }
        }
        forwarded
    }
}

pub(crate) fn process_master_write(tty: TtyKey, host_fd: RawFd, bytes: &[u8]) -> Vec<u8> {
    let mut ld = {
        let mut reg = slot().lock();
        let state = reg.get_state_mut(tty);
        LineDiscipline {
            literal_next: state.literal_next,
        }
    };
    let forwarded = ld.route_control_input(bytes, host_fd, tty, |_signum, _byte, _termios| {});
    {
        let mut reg = slot().lock();
        let state = reg.get_state_mut(tty);
        state.literal_next = ld.literal_next;
    }
    forwarded
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kernel::{ClonePlan, RootBootstrap};
    use crate::thread::ThreadId;
    use carrick_abi::LinuxCloneFlags;

    fn bootstrap(pid: i32) -> (Arc<Kernel>, crate::kernel::KernelContext) {
        let input = RootBootstrap::for_reference_model(
            pid,
            ThreadId::synthetic_for_tests(pid),
            "root".to_string(),
        )
        .expect("bootstrap input");
        Kernel::bootstrap_root(input).expect("kernel")
    }

    #[test]
    fn pty_master_vintr_delivers_sigint_to_foreground_pgrp_and_not_others() {
        let (kernel, root) = bootstrap(500);
        let fork_plan = ClonePlan::from_flags(LinuxCloneFlags::empty()).expect("fork plan");
        let child = kernel
            .fork_task(
                &root,
                fork_plan,
                ThreadId::synthetic_for_tests(501),
                "child".to_string(),
                None,
            )
            .expect("child task");
        let child_id = child.task.key().id;
        let child_group = kernel
            .create_process_group(child_id, None)
            .expect("child process group");

        let pty_pair = crate::pty_relay::PtyPair::allocate().expect("pty pair");
        detach(TtyKey::Pty(5001));
        attach_pty(
            5001,
            &kernel,
            root.container().id(),
            child.task.session(),
            child_group,
            false,
        )
        .expect("attach pty");

        let forwarded = process_master_write(TtyKey::Pty(5001), pty_pair.master_fd, b"\x03");
        assert!(
            forwarded.is_empty(),
            "VINTR must be consumed by line discipline"
        );

        assert!(
            child
                .shared()
                .pending_signals()
                .present()
                .contains(carrick_abi::LINUX_SIGINT),
            "foreground process group must receive SIGINT"
        );
        assert!(
            !root
                .shared()
                .pending_signals()
                .present()
                .contains(carrick_abi::LINUX_SIGINT),
            "other process group must not receive SIGINT"
        );

        detach(TtyKey::Pty(5001));
        unsafe {
            libc::close(pty_pair.master_fd);
            libc::close(pty_pair.slave_fd);
        }
    }

    #[test]
    fn pty_master_write_without_isig_passes_through() {
        let (kernel, root) = bootstrap(510);
        let pty_pair = crate::pty_relay::PtyPair::allocate().expect("pty pair");
        detach(TtyKey::Pty(5002));
        attach_pty(
            5002,
            &kernel,
            root.container().id(),
            root.task().session(),
            root.task().process_group(),
            false,
        )
        .expect("attach pty");

        let mut termios: libc::termios = unsafe { std::mem::zeroed() };
        assert_eq!(
            unsafe { libc::tcgetattr(pty_pair.slave_fd, &mut termios) },
            0
        );
        termios.c_lflag &= !libc::ISIG;
        assert_eq!(
            unsafe { libc::tcsetattr(pty_pair.slave_fd, libc::TCSANOW, &termios) },
            0
        );

        let forwarded = process_master_write(TtyKey::Pty(5002), pty_pair.master_fd, b"\x03");
        assert_eq!(forwarded, b"\x03", "without ISIG byte must pass through");
        assert!(
            !root
                .shared()
                .pending_signals()
                .present()
                .contains(carrick_abi::LINUX_SIGINT),
            "no signal should be generated when ISIG is disabled"
        );

        detach(TtyKey::Pty(5002));
        unsafe {
            libc::close(pty_pair.master_fd);
            libc::close(pty_pair.slave_fd);
        }
    }

    #[test]
    fn pty_master_write_without_foreground_pgrp_drops_byte_and_no_signal() {
        let (_kernel, root) = bootstrap(520);
        let pty_pair = crate::pty_relay::PtyPair::allocate().expect("pty pair");
        detach(TtyKey::Pty(5003));
        let forwarded = process_master_write(TtyKey::Pty(5003), pty_pair.master_fd, b"\x03");
        assert!(
            forwarded.is_empty(),
            "without foreground group byte must be dropped"
        );
        assert!(
            !root
                .shared()
                .pending_signals()
                .present()
                .contains(carrick_abi::LINUX_SIGINT),
            "no signal should be delivered without foreground group"
        );

        detach(TtyKey::Pty(5003));
        unsafe {
            libc::close(pty_pair.master_fd);
            libc::close(pty_pair.slave_fd);
        }
    }

    #[test]
    fn pty_master_write_vlnext_quotes_signal_byte() {
        let (kernel, root) = bootstrap(530);
        let pty_pair = crate::pty_relay::PtyPair::allocate().expect("pty pair");
        detach(TtyKey::Pty(5004));
        attach_pty(
            5004,
            &kernel,
            root.container().id(),
            root.task().session(),
            root.task().process_group(),
            false,
        )
        .expect("attach pty");

        let forwarded = process_master_write(TtyKey::Pty(5004), pty_pair.master_fd, &[0x16, 0x03]);
        assert_eq!(forwarded, vec![0x16, 0x03], "VLNEXT must quote VINTR");
        assert!(
            !root
                .shared()
                .pending_signals()
                .present()
                .contains(carrick_abi::LINUX_SIGINT),
            "quoted VINTR must not generate signal"
        );

        detach(TtyKey::Pty(5004));
        unsafe {
            libc::close(pty_pair.master_fd);
            libc::close(pty_pair.slave_fd);
        }
    }

    #[test]
    fn pty_master_write_noflsh_preserves_preceding_input() {
        let (kernel, root) = bootstrap(540);
        let pty_pair = crate::pty_relay::PtyPair::allocate().expect("pty pair");
        detach(TtyKey::Pty(5005));
        attach_pty(
            5005,
            &kernel,
            root.container().id(),
            root.task().session(),
            root.task().process_group(),
            false,
        )
        .expect("attach pty");

        let forwarded_flush =
            process_master_write(TtyKey::Pty(5005), pty_pair.master_fd, b"abc\x03");
        assert!(
            forwarded_flush.is_empty(),
            "without NOFLSH preceding data is flushed"
        );

        let mut termios: libc::termios = unsafe { std::mem::zeroed() };
        assert_eq!(
            unsafe { libc::tcgetattr(pty_pair.slave_fd, &mut termios) },
            0
        );
        termios.c_lflag |= libc::NOFLSH;
        assert_eq!(
            unsafe { libc::tcsetattr(pty_pair.slave_fd, libc::TCSANOW, &termios) },
            0
        );

        let forwarded_noflsh =
            process_master_write(TtyKey::Pty(5005), pty_pair.master_fd, b"abc\x03");
        assert_eq!(
            forwarded_noflsh, b"abc",
            "with NOFLSH preceding data is preserved"
        );

        detach(TtyKey::Pty(5005));
        unsafe {
            libc::close(pty_pair.master_fd);
            libc::close(pty_pair.slave_fd);
        }
    }
}
