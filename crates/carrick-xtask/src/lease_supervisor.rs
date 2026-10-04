//! Lease ownership and workload lifetime share one supervisor process.
//! The caller is a proxy: its death requests cancellation, never unlocks flock.

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
        cancelled: Vec::new(),
    };
    let supervision = events
        .watch_worker(workload.child.id() as libc::pid_t)
        .and_then(|()| events.wait());

    // On owner death AND normal command exit, terminate remaining run-scoped
    // descendants. Retain exclusion across this whole operation and EOF.
    workload
        .cancel()
        .unwrap_or_else(|e| fail_closed("cancel workload", e));
    let status = workload
        .child
        .wait()
        .unwrap_or_else(|e| fail_closed("reap worker", e));
    workload.reaped = true;
    #[cfg(target_os = "linux")]
    reap_descendants().unwrap_or_else(|e| fail_closed("reap descendants", e));
    let mut bytes = [0; 256];
    loop {
        match lifetime.read(&mut bytes) {
            Ok(0) => break,
            Ok(_) => continue,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) => fail_closed("workload lifetime EOF", error),
        }
    }
    #[cfg(not(target_os = "linux"))]
    workload
        .wait_for_reaping()
        .unwrap_or_else(|e| fail_closed("descendant reaping", e));
    supervision.map_err(HostLeaseError::ChildWait)?;
    drop(lease);
    Ok(extract_exit_code(&status))
}

fn fail_closed(operation: &str, error: io::Error) -> ! {
    eprintln!("host-lease: {operation} failed: {error}; retaining exclusion");
    loop {
        std::thread::park();
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
    cancelled: Vec<libc::pid_t>,
}

impl Workload {
    fn cancel(&mut self) -> io::Result<()> {
        let group = self.child.id() as libc::pid_t;
        #[cfg(target_os = "macos")]
        {
            self.cancelled = self.scope.cancel(group)?;
        }
        // SAFETY: child created its own session/group before exec. The zombie
        // leader remains unreaped here, pinning its identity during cancellation.
        #[cfg(not(target_os = "macos"))]
        if unsafe { libc::kill(-group, libc::SIGKILL) } < 0
            && io::Error::last_os_error().raw_os_error() != Some(libc::ESRCH)
        {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    #[cfg(not(target_os = "linux"))]
    fn wait_for_reaping(&self) -> io::Result<()> {
        #[cfg(target_os = "macos")]
        for &pid in &self.cancelled {
            loop {
                // SAFETY: scoped members were stopped and killed before wait.
                if unsafe { libc::kill(pid, 0) } < 0
                    && io::Error::last_os_error().raw_os_error() == Some(libc::ESRCH)
                {
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
            // SAFETY: exact unreaped adopted child, cannot be a reused PID.
            if unsafe { libc::kill(pid, libc::SIGKILL) } < 0
                && io::Error::last_os_error().raw_os_error() != Some(libc::ESRCH)
            {
                return Err(io::Error::last_os_error());
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
                return Ok(events[0].revents != 0);
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
}

#[cfg(not(target_os = "linux"))]
impl ExitEvents {
    fn new(owner: libc::pid_t) -> io::Result<Self> {
        // SAFETY: kqueue creates a uniquely owned descriptor.
        let fd = unsafe { libc::kqueue() };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        let result = Self {
            queue: unsafe { OwnedFd::from_raw_fd(fd) },
        };
        if unsafe { libc::fcntl(fd, libc::F_SETFD, libc::FD_CLOEXEC) } < 0 {
            return Err(io::Error::last_os_error());
        }
        result.watch(owner)?;
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
