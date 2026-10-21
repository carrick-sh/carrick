//! Trusted, uid-scoped process retirement; never grants signal authority.
use std::path::Path;
use std::process::Command;

#[derive(clap::Args, Debug)]
pub struct RetireArgs {
    #[arg(long)]
    pub expected_uid: libc::uid_t,
}

#[derive(Debug, thiserror::Error)]
pub enum ProcessError {
    #[error("process retirement requires Linux and matching non-root real and effective uids")]
    Identity,
    #[error("process retirement signal failed: {0}")]
    Signal(#[source] std::io::Error),
}

pub fn command(binary: &Path, user: &str, uid: libc::uid_t) -> Command {
    let mut command = Command::new("/usr/bin/sudo");
    command
        .env_clear()
        .env("PATH", "/usr/local/bin:/usr/bin:/bin")
        .args(["-n", "-u", user, "--"])
        .arg(binary)
        .args(["retire-processes", "--expected-uid", &uid.to_string()])
        .current_dir("/");
    command
}

pub fn run_checked(command: &mut Command) -> Result<(), crate::ci_scaler::ScalerError> {
    crate::ci_scaler::execute(command, &[], std::time::Duration::from_secs(120))?;
    Ok(())
}

pub fn retire(args: RetireArgs) -> Result<(), ProcessError> {
    // SAFETY: identity reads have no preconditions.
    let (real, effective) = unsafe { (libc::getuid(), libc::geteuid()) };
    retire_with(args.expected_uid, real, effective, |signal| {
        // SAFETY: the identity guard below runs first. Linux excludes this caller.
        if unsafe { libc::kill(-1, signal) } == 0 {
            Ok(())
        } else {
            Err(std::io::Error::last_os_error())
        }
    })
}

fn retire_with(
    expected: libc::uid_t,
    real: libc::uid_t,
    effective: libc::uid_t,
    mut signal: impl FnMut(libc::c_int) -> std::io::Result<()>,
) -> Result<(), ProcessError> {
    if !cfg!(target_os = "linux") || expected == 0 || real != expected || effective != expected {
        return Err(ProcessError::Identity);
    }
    for value in [libc::SIGSTOP, libc::SIGKILL] {
        match signal(value) {
            Ok(()) => {}
            Err(error) if error.raw_os_error() == Some(libc::ESRCH) => {}
            Err(error) => return Err(ProcessError::Signal(error)),
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;
    #[test]
    fn argv_and_helper_failure_are_preserved() {
        let command = command(Path::new("/trusted/tool"), "worker", 1234);
        let args: Vec<_> = command
            .get_args()
            .map(|arg| arg.to_str().unwrap())
            .collect();
        assert_eq!(command.get_program(), "/usr/bin/sudo");
        assert_eq!(
            args,
            [
                "-n",
                "-u",
                "worker",
                "--",
                "/trusted/tool",
                "retire-processes",
                "--expected-uid",
                "1234"
            ]
        );
        assert_eq!(command.get_current_dir(), Some(Path::new("/")));
        let mut failed = Command::new("/bin/sh");
        failed.args(["-c", "exit 23"]);
        let error = run_checked(&mut failed).unwrap_err().to_string();
        assert!(error.contains("exited with code 23"), "{error}");
    }
    #[test]
    #[cfg(target_os = "linux")]
    fn signals_are_ordered_and_only_esrch_is_tolerated() {
        let mut signals = Vec::new();
        retire_with(1234, 1234, 1234, |value| {
            signals.push(value);
            Err(std::io::Error::from_raw_os_error(libc::ESRCH))
        })
        .unwrap();
        assert_eq!(signals, [libc::SIGSTOP, libc::SIGKILL]);
        assert!(matches!(
            retire_with(1234, 1234, 1234, |_| Err(
                std::io::Error::from_raw_os_error(libc::EPERM)
            )),
            Err(ProcessError::Signal(_))
        ));
        for (expected, real, effective) in [(0, 0, 0), (1234, 1234, 0), (1234, 0, 1234)] {
            assert!(matches!(
                retire_with(expected, real, effective, |_| panic!(
                    "signal before uid validation"
                )),
                Err(ProcessError::Identity)
            ));
        }
    }
}
