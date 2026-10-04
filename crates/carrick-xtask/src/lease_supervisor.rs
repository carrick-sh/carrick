//! Lease ownership and workload lifetime share one supervisor process.
//! The caller is a proxy: its death requests cancellation, never unlocks flock.
//! Catchable termination cancels work before release. SIGKILL of this sole
//! flock owner releases exclusion immediately; it is not crash containment.

use crate::host_lease::{HostLease, HostLeaseError, HostLeaseMode, extract_exit_code};
use std::ffi::OsString;
use std::io::{self, Read};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::process::CommandExt;
use std::process::{Child, Command};

#[derive(clap::Args, Debug)]
pub struct SupervisorArgs {
    #[arg(long)]
    owner: libc::pid_t,
    #[arg(long, value_enum)]
    mode: HostLeaseMode,
    #[arg(long)]
    check_load: bool,
    #[arg(trailing_var_arg = true, required = true, allow_hyphen_values = true)]
    command: Vec<OsString>,
}

pub fn launch(
    mode: HostLeaseMode,
    check_load: bool,
    args: &[OsString],
) -> Result<i32, HostLeaseError> {
    let executable = std::env::current_exe().map_err(HostLeaseError::ChildWait)?;
    let mut command = Command::new(executable);
    command
        .args(["lease-supervisor", "--owner"])
        .process_group(0)
        .arg(std::process::id().to_string())
        .args(["--mode", &mode.to_string()])
        .env_remove("CARRICK_HOST_LEASE_SOCKET")
        .env_remove("CARRICK_HOST_LEASE_FD")
        .env_remove("CARRICK_HOST_LEASE_MODE");
    command.env_remove(crate::host_lease::SCOPE_FD);
    if check_load {
        command.arg("--check-load");
    }
    let mut supervisor =
        command
            .arg("--")
            .args(args)
            .spawn()
            .map_err(|source| HostLeaseError::Spawn {
                cmd: "lease supervisor".into(),
                source,
            })?;
    Ok(extract_exit_code(
        &supervisor.wait().map_err(HostLeaseError::ChildWait)?,
    ))
}

pub fn run(args: SupervisorArgs) -> Result<i32, HostLeaseError> {
    // Register parent death before acquiring the lease or spawning any work.
    let mut events = ExitEvents::new(args.owner).map_err(HostLeaseError::ChildWait)?;
    // SAFETY: getppid has no preconditions. A dead/reparented owner cannot admit.
    if unsafe { libc::getppid() } != args.owner {
        return Ok(1);
    }
    #[cfg(target_os = "linux")]
    // SAFETY: this dedicated process must adopt and reap orphaned descendants.
    if unsafe { libc::prctl(libc::PR_SET_CHILD_SUBREAPER, 1) } != 0 {
        return Err(HostLeaseError::ChildWait(io::Error::last_os_error()));
    }
    let (mut lifetime, writer) = scope_pipe().map_err(HostLeaseError::ChildWait)?;
    let identity =
        crate::host_lease::ScopeIdentity::writer(&writer).map_err(HostLeaseError::ChildWait)?;
    let lease =
        HostLease::acquire_supervised(args.mode, identity, |delay| events.wait_owner(delay))?;
    if args.check_load {
        crate::host_load::check()?;
    }
    if events.owner_dead().map_err(HostLeaseError::ChildWait)? {
        return Ok(1);
    }

    // EOF grants release only after every inherited writer has closed. This
    // includes arbitrary Cargo/test forks and execs, without sharing flock.
    #[cfg(target_os = "macos")]
    let scope = macos_scope::PipeWriter::from_reader(lifetime.as_raw_fd())
        .map_err(HostLeaseError::ChildWait)?;
    let mut command = Command::new(&args.command[0]);
    command.args(&args.command[1..]);
    command.env("CARRICK_LEASE_SUPERVISOR", std::process::id().to_string());
    command.env(crate::host_lease::SCOPE_FD, writer.as_raw_fd().to_string());
    lease
        .configure_command(&mut command)
        .map_err(HostLeaseError::ChildWait)?;
    // SAFETY: only async-signal-safe setsid/fcntl, before arbitrary code runs.
    unsafe {
        command.pre_exec(move || {
            if libc::setsid() < 0 {
                return Err(io::Error::last_os_error());
            }
            if libc::fcntl(writer.as_raw_fd(), libc::F_SETFD, 0) < 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let child = command.spawn().map_err(|source| HostLeaseError::Spawn {
        cmd: args.command[0].to_string_lossy().into_owned(),
        source,
    })?;
    drop(command); // No supervisor-side writer may postpone lifetime EOF.
    let mut workload = Workload {
        child,
        reaped: false,
        #[cfg(target_os = "macos")]
        scope,
        #[cfg(target_os = "macos")]
        cancelled: std::collections::BTreeMap::new(),
    };
    let supervision = events
        .watch_worker(workload.child.id() as libc::pid_t)
        .and_then(|()| events.wait());

    // On owner death AND normal command exit, terminate remaining run-scoped
    // descendants. Retain exclusion across this whole operation and EOF.
    complete_cleanup("cancel workload", || workload.cancel());
    let status = complete_cleanup("reap worker", || workload.child.wait());
    workload.reaped = true;
    #[cfg(target_os = "linux")]
    complete_cleanup("reap descendants", reap_descendants);
    let mut bytes = [0; 256];
    loop {
        match lifetime.read(&mut bytes) {
            Ok(0) => break,
            Ok(_) => continue,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(_) => {
                complete_cleanup("workload lifetime EOF", || lifetime.read(&mut bytes));
            }
        }
    }
    #[cfg(not(target_os = "linux"))]
    complete_cleanup("descendant reaping", || workload.wait_for_reaping());
    supervision.map_err(HostLeaseError::ChildWait)?;
    drop(lease);
    Ok(extract_exit_code(&status))
}

fn complete_cleanup<T>(operation: &str, mut attempt: impl FnMut() -> io::Result<T>) -> T {
    let mut reported = None;
    loop {
        match attempt() {
            Ok(result) => return result,
            Err(error) => {
                let message = error.to_string();
                if reported.as_ref() != Some(&message) {
                    eprintln!(
                        "host-lease: {operation} failed: {error}; retaining exclusion and continuing cleanup"
                    );
                    reported = Some(message);
                }
                std::thread::sleep(std::time::Duration::from_millis(10));
            }
        }
    }
}

#[cfg(test)]
mod cleanup_tests {
    #[test]
    fn permission_error_keeps_observing_workload_exit() {
        let (send, receive) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let mut attempts = 0;
            super::complete_cleanup("permission fixture", || {
                attempts += 1;
                if attempts == 1 {
                    Err(std::io::Error::from_raw_os_error(libc::EPERM))
                } else {
                    // Privileged work finishes naturally after cancellation was
                    // refused. The next observation must permit cleanup/release.
                    Ok(())
                }
            });
            send.send(attempts).unwrap();
        });
        assert_eq!(
            receive
                .recv_timeout(std::time::Duration::from_millis(500))
                .ok(),
            Some(2),
            "permission error prevented the next exit observation"
        );
    }
}

fn scope_pipe() -> io::Result<(std::fs::File, OwnedFd)> {
    let mut fds = [-1; 2];
    // SAFETY: valid two-fd output; uniquely owned on successful pipe.
    if unsafe { libc::pipe(fds.as_mut_ptr()) } < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: the two descriptors were just created and uniquely owned.
    let read = unsafe { OwnedFd::from_raw_fd(fds[0]) };
    let write = unsafe { OwnedFd::from_raw_fd(fds[1]) };
    for fd in [&read, &write] {
        // SAFETY: owned descriptor; only workload's explicit handoff clears it.
        if unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_SETFD, libc::FD_CLOEXEC) } < 0 {
            return Err(io::Error::last_os_error());
        }
    }
    Ok((std::fs::File::from(read), write))
}

struct Workload {
    child: Child,
    reaped: bool,
    #[cfg(target_os = "macos")]
    scope: macos_scope::PipeWriter,
    #[cfg(target_os = "macos")]
    cancelled: std::collections::BTreeMap<ProcessIncarnation, macos_scope::ProcessWatch>,
}

impl Workload {
    fn cancel(&mut self) -> io::Result<()> {
        let group = self.child.id() as libc::pid_t;
        #[cfg(target_os = "macos")]
        {
            self.scope.cancel(group, &mut self.cancelled)?;
        }
        // SAFETY: child created its own session/group before exec. The zombie
        // leader remains unreaped here, pinning its identity during cancellation.
        #[cfg(not(target_os = "macos"))]
        if unsafe { libc::kill(-group, libc::SIGKILL) } < 0
            && io::Error::last_os_error().raw_os_error() != Some(libc::ESRCH)
        {
            let error = io::Error::last_os_error();
            if error.raw_os_error() != Some(libc::EPERM) {
                return Err(error);
            }
            eprintln!(
                "host-lease: privileged workload refused cancellation; retaining exclusion until exit"
            );
        }
        Ok(())
    }

    #[cfg(not(target_os = "linux"))]
    fn wait_for_reaping(&self) -> io::Result<()> {
        #[cfg(target_os = "macos")]
        for process in self.cancelled.values() {
            loop {
                if process.reaped()? {
                    break;
                }
                std::thread::sleep(std::time::Duration::from_millis(1));
            }
        }
        #[cfg(target_os = "macos")]
        return Ok(());
        #[cfg(not(target_os = "macos"))]
        {
            let group = self.child.id() as libc::pid_t;
            loop {
                // SAFETY: existence probe for the isolated workload group.
                if unsafe { libc::kill(-group, 0) } < 0 {
                    let error = io::Error::last_os_error();
                    if error.raw_os_error() == Some(libc::ESRCH) {
                        return Ok(());
                    }
                    return Err(error);
                }
                // Darwin reparents indirect descendants to launchd, which reaps
                // them. Keep exclusion until that reaping has removed the group.
                std::thread::sleep(std::time::Duration::from_millis(1));
            }
        }
    }
}

#[cfg(any(target_os = "macos", test))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct ProcessIncarnation {
    pid: libc::pid_t,
    unique_id: u64,
    start: Option<(u64, u64)>,
}

#[cfg(any(target_os = "macos", test))]
impl ProcessIncarnation {
    fn signal(
        self,
        signal: libc::c_int,
        observe: impl FnOnce(libc::pid_t) -> io::Result<Option<Self>>,
        send: impl FnOnce(libc::pid_t, libc::c_int) -> io::Result<()>,
    ) -> io::Result<()> {
        if self.present(observe(self.pid)?) {
            send(self.pid, signal)?;
        }
        Ok(())
    }

    fn present(self, observed: Option<Self>) -> bool {
        observed.is_some_and(|current| {
            self.pid == current.pid
                && self.unique_id == current.unique_id
                && match (self.start, current.start) {
                    (Some(expected), Some(actual)) => expected == actual,
                    _ => true, // Kernel unique ID remains available across UID changes.
                }
        })
    }
}

#[cfg(test)]
mod incarnation_tests {
    use super::ProcessIncarnation;

    #[test]
    fn exit_reap_and_reuse_before_each_signal_does_not_target_replacement() {
        let selected = ProcessIncarnation {
            pid: 24,
            unique_id: 1,
            start: Some((1, 10)),
        };
        let replacement = ProcessIncarnation {
            unique_id: 2,
            start: Some((2, 10)),
            ..selected
        };
        for signal in [libc::SIGSTOP, libc::SIGKILL] {
            for observed in [None, Some(replacement)] {
                let mut signalled = false;
                selected
                    .signal(
                        signal,
                        |_| Ok(observed),
                        |_, _| {
                            signalled = true;
                            Ok(())
                        },
                    )
                    .unwrap();
                assert!(
                    !signalled,
                    "signal {signal} targeted an exited/reused process incarnation"
                );
            }
        }
    }

    #[test]
    fn reaping_does_not_wait_on_a_replacement_incarnation() {
        let selected = ProcessIncarnation {
            pid: 24,
            unique_id: 1,
            start: Some((1, 10)),
        };
        let replacement = ProcessIncarnation {
            unique_id: 2,
            start: Some((2, 10)),
            ..selected
        };
        assert!(
            !selected.present(Some(replacement)),
            "reaping waited on a reused PID"
        );
    }

    #[test]
    fn privilege_change_preserves_live_identity_without_matching_replacement() {
        let selected = ProcessIncarnation {
            pid: 24,
            unique_id: 1,
            start: Some((1, 10)),
        };
        let privileged = ProcessIncarnation {
            start: None,
            ..selected
        };
        assert!(
            selected.present(Some(privileged)),
            "UID change falsely certified exit"
        );
        assert!(
            !selected.present(Some(ProcessIncarnation {
                unique_id: 2,
                ..privileged
            })),
            "privileged replacement reused cancellation authority"
        );
    }
}

impl Drop for Workload {
    fn drop(&mut self) {
        if !self.reaped {
            let _ = self.cancel();
            let _ = self.child.wait();
        }
    }
}

#[cfg(target_os = "linux")]
fn reap_descendants() -> io::Result<()> {
    loop {
        // The direct worker is dead: every remaining descendant is either an
        // adopted child here, or below one. Kill roots, reap, repeat to ECHILD;
        // this also catches children that created another group/session.
        let children =
            std::fs::read_to_string(format!("/proc/self/task/{}/children", std::process::id()))?;
        for pid in children.split_whitespace() {
            let pid: libc::pid_t = pid
                .parse()
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
            // Exit/reaping authority is independent of signal permission. A
            // privileged adopted child that exited must not be stuck at EPERM.
            let reaped = unsafe { libc::waitpid(pid, std::ptr::null_mut(), libc::WNOHANG) };
            if reaped == pid {
                continue;
            }
            if reaped < 0 {
                let error = io::Error::last_os_error();
                if error.raw_os_error() == Some(libc::ECHILD) {
                    continue;
                }
                return Err(error);
            }
            // SAFETY: exact unreaped adopted child, cannot be a reused PID.
            if unsafe { libc::kill(pid, libc::SIGKILL) } < 0
                && io::Error::last_os_error().raw_os_error() != Some(libc::ESRCH)
            {
                let error = io::Error::last_os_error();
                if error.raw_os_error() != Some(libc::EPERM) {
                    return Err(error);
                }
                eprintln!(
                    "host-lease: privileged descendant {pid} refused cancellation; awaiting its exit with exclusion held"
                );
            }
        }
        // SAFETY: this process runs no unrelated work; all children are scoped.
        if unsafe { libc::waitpid(-1, std::ptr::null_mut(), 0) } >= 0 {
            continue;
        }
        let error = io::Error::last_os_error();
        match error.raw_os_error() {
            Some(libc::ECHILD) => return Ok(()),
            Some(libc::EINTR) => continue,
            _ => return Err(error),
        }
    }
}

#[cfg(target_os = "macos")]
mod macos_scope;

#[cfg(target_os = "linux")]
struct ExitEvents {
    owner: OwnedFd,
    worker: Option<OwnedFd>,
    cancellation: CancellationSignals,
}

#[cfg(target_os = "linux")]
impl ExitEvents {
    fn pidfd(pid: libc::pid_t) -> io::Result<OwnedFd> {
        carrick_portable::process_exit_fd(carrick_portable::HostProcessId::from_native(pid)?)
    }
    fn new(owner: libc::pid_t) -> io::Result<Self> {
        Ok(Self {
            owner: Self::pidfd(owner)?,
            worker: None,
            cancellation: CancellationSignals::new()?,
        })
    }
    fn watch_worker(&mut self, worker: libc::pid_t) -> io::Result<()> {
        self.worker = Some(Self::pidfd(worker)?);
        Ok(())
    }
    fn owner_dead(&mut self) -> io::Result<bool> {
        self.poll(0)
    }
    fn wait_owner(&mut self, delay: std::time::Duration) -> io::Result<bool> {
        self.poll(delay.as_millis().min(i32::MAX as u128) as i32)
    }
    fn wait(&mut self) -> io::Result<()> {
        self.poll(-1).map(|_| ())
    }
    fn poll(&self, timeout: i32) -> io::Result<bool> {
        let mut events = vec![libc::pollfd {
            fd: self.owner.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        }];
        events.push(libc::pollfd {
            fd: self.cancellation.reader.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        });
        if let Some(worker) = &self.worker {
            events.push(libc::pollfd {
                fd: worker.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            });
        }
        loop {
            // SAFETY: initialized array of live process descriptors.
            let result = unsafe { libc::poll(events.as_mut_ptr(), events.len() as _, timeout) };
            if result >= 0 {
                return Ok(events[0].revents != 0 || events[1].revents != 0);
            }
            let error = io::Error::last_os_error();
            if error.kind() != io::ErrorKind::Interrupted {
                return Err(error);
            }
        }
    }
}

#[cfg(not(target_os = "linux"))]
struct ExitEvents {
    queue: OwnedFd,
    _cancellation: CancellationSignals,
}

#[cfg(not(target_os = "linux"))]
impl ExitEvents {
    fn new(owner: libc::pid_t) -> io::Result<Self> {
        // SAFETY: kqueue creates a uniquely owned descriptor.
        let fd = unsafe { libc::kqueue() };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        let cancellation = CancellationSignals::new()?;
        let result = Self {
            queue: unsafe { OwnedFd::from_raw_fd(fd) },
            _cancellation: cancellation,
        };
        if unsafe { libc::fcntl(fd, libc::F_SETFD, libc::FD_CLOEXEC) } < 0 {
            return Err(io::Error::last_os_error());
        }
        result.watch(owner)?;
        // Register the self-pipe, so signal arrival before kevent waits cannot
        // be lost. The handler only writes; cleanup runs in ordinary code.
        let mut event = unsafe { std::mem::zeroed::<libc::kevent>() };
        event.ident = result._cancellation.reader.as_raw_fd() as _;
        event.filter = libc::EVFILT_READ;
        event.flags = libc::EV_ADD | libc::EV_ENABLE;
        if unsafe { libc::kevent(fd, &event, 1, std::ptr::null_mut(), 0, std::ptr::null()) } < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(result)
    }
    fn watch(&self, pid: libc::pid_t) -> io::Result<()> {
        // SAFETY: initialize one EVFILT_PROC exit watch on the owned queue.
        let mut event = unsafe { std::mem::zeroed::<libc::kevent>() };
        event.ident = pid as _;
        event.filter = libc::EVFILT_PROC;
        event.flags = libc::EV_ADD | libc::EV_ENABLE;
        event.fflags = libc::NOTE_EXIT;
        if unsafe {
            libc::kevent(
                self.queue.as_raw_fd(),
                &event,
                1,
                std::ptr::null_mut(),
                0,
                std::ptr::null(),
            )
        } < 0
        {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }
    fn watch_worker(&mut self, worker: libc::pid_t) -> io::Result<()> {
        self.watch(worker)
    }
    fn owner_dead(&mut self) -> io::Result<bool> {
        self.poll(Some(std::time::Duration::ZERO))
    }
    fn wait_owner(&mut self, delay: std::time::Duration) -> io::Result<bool> {
        self.poll(Some(delay))
    }
    fn wait(&mut self) -> io::Result<()> {
        self.poll(None).map(|_| ())
    }
    fn poll(&self, delay: Option<std::time::Duration>) -> io::Result<bool> {
        let timeout = delay.map(|d| libc::timespec {
            tv_sec: d.as_secs() as _,
            tv_nsec: d.subsec_nanos() as _,
        });
        loop {
            // SAFETY: valid queue, output event, optional immediate timeout.
            let mut event = unsafe { std::mem::zeroed::<libc::kevent>() };
            let result = unsafe {
                libc::kevent(
                    self.queue.as_raw_fd(),
                    std::ptr::null(),
                    0,
                    &mut event,
                    1,
                    timeout.as_ref().map_or(std::ptr::null(), |t| t),
                )
            };
            if result >= 0 {
                return Ok(result > 0);
            }
            let error = io::Error::last_os_error();
            if error.kind() != io::ErrorKind::Interrupted {
                return Err(error);
            }
        }
    }
}

struct CancellationSignals {
    reader: std::os::unix::net::UnixStream,
    registrations: Vec<signal_hook::SigId>,
}

impl CancellationSignals {
    fn new() -> io::Result<Self> {
        let (reader, writer) = std::os::unix::net::UnixStream::pair()?;
        let mut result = Self {
            reader,
            registrations: Vec::new(),
        };
        for signal in [libc::SIGTERM, libc::SIGINT, libc::SIGHUP] {
            result
                .registrations
                .push(signal_hook::low_level::pipe::register(
                    signal,
                    writer.try_clone()?,
                )?);
        }
        Ok(result)
    }
}

impl Drop for CancellationSignals {
    fn drop(&mut self) {
        for &registration in &self.registrations {
            signal_hook::low_level::unregister(registration);
        }
    }
}
