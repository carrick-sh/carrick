//! Signal dispatch, delivery, inheritance, and consumption semantics suite.
//!
//! Citations:
//! - `man 2 kill` (send signal to process)
//! - `man 2 rt_sigprocmask` (examine and change blocked signals; child inherits mask)
//! - `man 2 rt_sigaction` (examine and change signal action; SIG_IGN ignores signal)
//! - `man 2 rt_sigtimedwait` (synchronously wait for queued signals)
//! - `man 2 signalfd4` (create file descriptor for accepting signals)

use crate::common::*;

/// Sending a terminating signal to a process results in signal death reported by `wait4`.
///
/// Authority: `man 2 kill`, `man 2 wait4` (WIFSIGNALED and WTERMSIG report terminating signal).
#[test]
fn kill_child_with_sigterm_produces_signal_death() {
    let script = vec![
        pipe_to_slots(0, 1),
        Step::Sys(sys::fork()),
        Step::ChildMarker(vec![
            // Notify parent child is running
            Step::Sys(sys::write(slot(1), b"C").ret(1)),
            // Child self-terminates with SIGTERM
            Step::Sys(sys::kill(2, LINUX_SIGTERM).death(LINUX_SIGTERM)),
        ]),
        Step::Sys(sys::read(slot(0), 1).ret(1)),
        Step::Sys(wait4_labeled("wait_child", 2, 0)),
        Step::Sys(sys::exit_group(0)),
    ];
    let run = run(script);
    assert_eq!(run.exit_code(), 0);
    let status = wait_status(&run, "wait_child");
    assert!(wifsignaled(status));
    assert_eq!(wtermsig(status), LINUX_SIGTERM);
}

/// SIGCHLD is delivered to parent upon child exit with exit code and child PID.
///
/// Authority: `man 2 sigaction`, `man 2 rt_sigtimedwait` (SIGCHLD carries si_pid and si_status).
#[test]
fn sigchld_is_delivered_on_child_exit() {
    const CLD_EXITED: i32 = 1;
    let sigchld_mask = 1u64 << (LINUX_SIGCHLD - 1);
    let script = vec![
        Step::Sys(sys::rt_sigprocmask_block(sigchld_mask).ret(0)),
        Step::Sys(sys::fork()),
        Step::ChildMarker(vec![
            await_parked(1, "rt_sigtimedwait"),
            Step::Sys(sys::exit_group(37)),
        ]),
        Step::Sys(sys::rt_sigtimedwait_siginfo(sigchld_mask).ret(LINUX_SIGCHLD as i64)),
        Step::Sys(sys::wait4(last_child(), 0)),
        Step::Sys(sys::exit_group(0)),
    ];
    let run = run(script);
    assert_eq!(run.exit_code(), 0);
    let siginfo_bytes = run.output("rt_sigtimedwait");
    assert_eq!(siginfo_bytes.len(), 128);
    let si_signo = i32::from_le_bytes(siginfo_bytes[0..4].try_into().unwrap());
    let si_code = i32::from_le_bytes(siginfo_bytes[8..12].try_into().unwrap());
    let si_pid = i32::from_le_bytes(siginfo_bytes[16..20].try_into().unwrap());
    let si_status = i32::from_le_bytes(siginfo_bytes[24..28].try_into().unwrap());
    assert_eq!(si_signo, LINUX_SIGCHLD);
    assert_eq!(si_code, CLD_EXITED);
    assert_eq!(si_pid, 2);
    assert_eq!(si_status, 37);
}

/// Child process inherits parent's signal mask across fork.
///
/// Authority: `man 2 fork` (child inherits copies of parent's signal masks).
#[test]
fn signal_mask_is_inherited_across_fork() {
    let mask = 1u64 << (LINUX_SIGUSR1 - 1);
    let script = vec![
        // Block SIGUSR1 in parent
        Step::Sys(sys::rt_sigprocmask_block(mask).ret(0)),
        Step::Sys(sys::fork()),
        Step::ChildMarker(vec![
            // Query current mask in child using set=NULL, oldset=Out(8)
            Step::Sys(sys::rt_sigprocmask(0, 0, Operand::Out(8), 8).ret(0)),
            Step::Sys(sys::exit_group(0)),
        ]),
        Step::Sys(sys::wait4(last_child(), 0)),
        Step::Sys(sys::exit_group(0)),
    ];
    let run = run(script);
    assert_eq!(run.exit_code(), 0);
    let child_mask_bytes = run.output("rt_sigprocmask");
    let child_mask = u64::from_le_bytes(child_mask_bytes[0..8].try_into().unwrap());
    assert_eq!(
        child_mask & mask,
        mask,
        "child must inherit blocked SIGUSR1"
    );
}

/// signalfd4 delivers pending signal as a structured 128-byte read record.
///
/// Authority: `man 2 signalfd` (reading signalfd returns struct signalfd_siginfo).
#[test]
fn signalfd4_delivers_pending_signal_as_read() {
    let mask = 1u64 << (LINUX_SIGUSR1 - 1);
    let script = vec![
        // Block SIGUSR1 so it can be accepted via signalfd
        Step::Sys(sys::rt_sigprocmask_block(mask).ret(0)),
        // Create signalfd
        Step::Sys(
            sys::signalfd4(-1, mask.to_le_bytes().as_slice(), 8, 0)
                .ret(3)
                .save(0),
        ),
        // Send SIGUSR1 to self
        Step::Sys(sys::kill(1, LINUX_SIGUSR1).ret(0)),
        // Read from signalfd
        Step::Sys(sys::read(slot(0), 128).ret(128)),
        Step::Sys(sys::close(slot(0)).ret(0)),
        Step::Sys(sys::exit_group(0)),
    ];
    let run = run(script);
    assert_eq!(run.exit_code(), 0);
    let sfd_bytes = run.output("read");
    let ssi_signo = u32::from_le_bytes(sfd_bytes[0..4].try_into().unwrap());
    assert_eq!(ssi_signo, LINUX_SIGUSR1 as u32);
}

/// Setting `SIG_IGN` for a signal drops the signal without terminating the process.
///
/// Authority: `man 2 sigaction` (SIG_IGN causes signal to be ignored).
#[test]
fn ignored_signal_does_not_terminate_process() {
    let script = vec![
        Step::Sys(sys::rt_sigaction_ign(LINUX_SIGUSR1).ret(0)),
        // Send ignored signal to self
        Step::Sys(sys::kill(1, LINUX_SIGUSR1).ret(0)),
        // Process must survive and exit normally
        Step::Sys(sys::exit_group(0)),
    ];
    let run = run(script);
    assert_eq!(run.exit_code(), 0);
}

/// `tgkill` directs signal specifically to the requested thread within a thread group.
///
/// Authority: `man 2 tgkill` (tgkill sends signal to the thread with thread ID tid in the thread group tgid).
#[test]
fn tgkill_targets_specific_thread() {
    let mask = 1u64 << (LINUX_SIGUSR1 - 1);
    let script = vec![
        Step::Sys(sys::fork()),
        Step::ChildMarker(vec![
            pipe_to_slots(0, 1),
            Step::Sys(sys::getpid().save(3)),
            // Spawn target thread (tid saved in slot 2)
            Step::Sys(sys::clone_thread(0).save(2)),
            Step::ChildMarker(vec![
                Step::Sys(sys::rt_sigprocmask_block(mask).ret(0)),
                Step::Sys(sys::rt_sigtimedwait_siginfo(mask).ret(LINUX_SIGUSR1 as i64)),
                Step::Sys(sys::write(slot(1), b"TARGET_HIT").ret(10)),
                Step::Sys(sys::exit_thread(0)),
            ]),
            await_parked(slot(2), "rt_sigtimedwait"),
            // Send SIGUSR1 specifically to target thread in this thread group
            Step::Sys(sys::tgkill(slot(3), slot(2), LINUX_SIGUSR1).ret(0)),
            Step::Sys(sys::read(slot(0), 10).ret(10)),
            Step::Sys(sys::exit_group(0)),
        ]),
        Step::Sys(sys::wait4(last_child(), 0)),
        Step::Sys(sys::exit_group(0)),
    ];

    let run = run(script);
    assert_eq!(run.exit_code(), 0);
    assert_eq!(run.output("read"), b"TARGET_HIT");
    assert_eq!(run.dispatches_for_tid(3, "rt_sigtimedwait"), 2);
}
