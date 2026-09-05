//! Conformance probe verifying that `/proc/<child>/task/` and
//! `/proc/<child>/task/<tid>/status` answer from the kernel task graph.
//!
//! LTP futex_wake02 (and tests using futex_utils.h) opens
//! `/proc/<child>/task/` from the parent to discover the child's threads.
//!
//! Invariants verified:
//! - `/proc/<child>/task` lists the child's process ID (thread group leader).
//! - After the child creates a secondary thread, `/proc/<child>/task` lists both TIDs.
//! - `/proc/<child>/task/<child_pid>/status` is readable and reports matching Pid and Tgid.
//! - `/proc/<child>/task/<thread_tid>/status` is readable and reports matching Pid and Tgid.
//! - After the child exits and is reaped, `/proc/<child>/task` returns ENOENT.

use conformance_probes::{errno, pipe2, reap, report};

static THREAD_TID: std::sync::atomic::AtomicI64 = std::sync::atomic::AtomicI64::new(0);

extern "C" fn worker(_: *mut libc::c_void) -> *mut libc::c_void {
    let tid = unsafe { libc::syscall(libc::SYS_gettid) };
    THREAD_TID.store(tid, std::sync::atomic::Ordering::Release);
    let ts = libc::timespec {
        tv_sec: 60,
        tv_nsec: 0,
    };
    unsafe {
        libc::nanosleep(&ts, std::ptr::null_mut());
    }
    std::ptr::null_mut()
}

fn status_field(status: &str, key: &str) -> i64 {
    status
        .lines()
        .find_map(|l| {
            l.strip_prefix(key)
                .map(|v| v.trim().parse::<i64>().unwrap_or(-1))
        })
        .unwrap_or(-2)
}

fn main() {
    unsafe {
        let (pipe_c2p_rd, pipe_c2p_wr) = pipe2();
        let (pipe_p2c_rd, pipe_p2c_wr) = pipe2();

        let pid = libc::fork();
        if pid < 0 {
            panic!("fork() failed: errno={}", errno());
        }

        if pid == 0 {
            libc::close(pipe_c2p_rd);
            libc::close(pipe_p2c_wr);

            let child_pid = i64::from(libc::getpid());
            let mut th: libc::pthread_t = std::mem::zeroed();
            let rc = libc::pthread_create(&mut th, std::ptr::null(), worker, std::ptr::null_mut());
            if rc != 0 {
                panic!("pthread_create failed: rc={rc}");
            }

            let mut thread_tid = 0i64;
            for _ in 0..1000 {
                thread_tid = THREAD_TID.load(std::sync::atomic::Ordering::Acquire);
                if thread_tid != 0 {
                    break;
                }
                let ts = libc::timespec {
                    tv_sec: 0,
                    tv_nsec: 1_000_000,
                };
                libc::nanosleep(&ts, std::ptr::null_mut());
            }
            if thread_tid == 0 {
                panic!("worker thread tid was not published");
            }

            let msg = format!("{child_pid}:{thread_tid}\n");
            let mut written = 0usize;
            while written < msg.len() {
                let n = libc::write(
                    pipe_c2p_wr,
                    msg[written..].as_ptr().cast(),
                    msg.len() - written,
                );
                if n > 0 {
                    written += n as usize;
                } else if errno() != libc::EINTR {
                    break;
                }
            }
            libc::close(pipe_c2p_wr);

            let mut ack = [0u8; 1];
            let _ = libc::read(pipe_p2c_rd, ack.as_mut_ptr().cast(), 1);
            libc::close(pipe_p2c_rd);
            libc::_exit(0);
        }

        libc::close(pipe_c2p_wr);
        libc::close(pipe_p2c_rd);

        // Parent: read child_pid:thread_tid\n
        let mut line = Vec::new();
        let mut buf = [0u8; 1];
        while libc::read(pipe_c2p_rd, buf.as_mut_ptr().cast(), 1) == 1 {
            if buf[0] == b'\n' {
                break;
            }
            line.push(buf[0]);
        }
        libc::close(pipe_c2p_rd);

        let line_str = String::from_utf8(line).expect("valid utf-8 from child");
        let (child_pid_str, thread_tid_str) = line_str
            .trim()
            .split_once(':')
            .expect("child:tid format");
        let child_pid: i64 = child_pid_str.parse().expect("child pid parse");
        let thread_tid: i64 = thread_tid_str.parse().expect("thread tid parse");

        let task_dir = format!("/proc/{child_pid}/task");
        let task_entries = std::fs::read_dir(&task_dir)
            .ok()
            .map(|entries| {
                entries
                    .flatten()
                    .map(|e| e.file_name().to_string_lossy().into_owned())
                    .collect::<Vec<String>>()
            })
            .unwrap_or_default();

        let child_task_dir_contains_leader = task_entries.contains(&child_pid.to_string());
        let child_task_dir_contains_thread = task_entries.contains(&thread_tid.to_string());

        let leader_status_path = format!("/proc/{child_pid}/task/{child_pid}/status");
        let leader_status = std::fs::read_to_string(&leader_status_path).unwrap_or_default();
        let child_task_leader_status_readable = !leader_status.is_empty()
            && status_field(&leader_status, "Tgid:") == child_pid
            && status_field(&leader_status, "Pid:") == child_pid;

        let thread_status_path = format!("/proc/{child_pid}/task/{thread_tid}/status");
        let thread_status = std::fs::read_to_string(&thread_status_path).unwrap_or_default();
        let child_task_thread_status_readable = !thread_status.is_empty()
            && status_field(&thread_status, "Tgid:") == child_pid
            && status_field(&thread_status, "Pid:") == thread_tid;

        // Tell child to exit
        let ack = [1u8];
        let _ = libc::write(pipe_p2c_wr, ack.as_ptr().cast(), 1);
        libc::close(pipe_p2c_wr);

        let (reaped, status) = reap(pid);
        let child_reaped_cleanly =
            reaped == pid && libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0;

        let reaped_child_task_dir_enoent = std::fs::read_dir(&task_dir).is_err();

        report!(
            child_task_dir_contains_leader = child_task_dir_contains_leader,
            child_task_dir_contains_thread = child_task_dir_contains_thread,
            child_task_leader_status_readable = child_task_leader_status_readable,
            child_task_thread_status_readable = child_task_thread_status_readable,
            child_reaped_cleanly = child_reaped_cleanly,
            reaped_child_task_dir_enoent = reaped_child_task_dir_enoent,
        );
    }
}
