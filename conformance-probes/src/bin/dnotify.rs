//! Minimal `F_NOTIFY`/dnotify signal delivery probe.
//!
//! LTP fcntl38 gates on dnotify SIGIO/SIGRT delivery after directory metadata
//! changes. This probe keeps the reducer small: arm dnotify on parent/child
//! directories, mutate the child, then check blocked `sigtimedwait` and
//! unblocked SA_SIGINFO handler delivery preserve `si_fd`.

use conformance_probes::{block_signal, errno, report};
use std::ffi::CString;
use std::sync::atomic::{AtomicI32, AtomicU32, Ordering};

const F_NOTIFY: i32 = 1026;
const F_SETSIG: i32 = 10;
const DN_ATTRIB: i32 = 0x0000_0020;
const DN_RENAME: i32 = 0x0000_0010;
const DN_MULTISHOT: i32 = 0x8000_0000u32 as i32;

static HANDLER_HITS: AtomicU32 = AtomicU32::new(0);
static HANDLER_SI_FD: AtomicI32 = AtomicI32::new(-1);
static FIRST_HANDLER_FD: AtomicI32 = AtomicI32::new(-1);
static SECOND_HANDLER_FD: AtomicI32 = AtomicI32::new(-1);

extern "C" fn on_dnotify(_sig: i32, info: *mut libc::siginfo_t, _ctx: *mut libc::c_void) {
    let hit = HANDLER_HITS.fetch_add(1, Ordering::SeqCst);
    if !info.is_null() {
        unsafe {
            let base = info as *const libc::siginfo_t as *const u8;
            let si_fd = *(base.add(24) as *const i32);
            HANDLER_SI_FD.store(si_fd, Ordering::SeqCst);
            if hit == 0 {
                FIRST_HANDLER_FD.store(si_fd, Ordering::SeqCst);
            } else if hit == 1 {
                SECOND_HANDLER_FD.store(si_fd, Ordering::SeqCst);
            }
        }
    }
}

fn reset_handler_state() {
    HANDLER_HITS.store(0, Ordering::SeqCst);
    HANDLER_SI_FD.store(-1, Ordering::SeqCst);
    FIRST_HANDLER_FD.store(-1, Ordering::SeqCst);
    SECOND_HANDLER_FD.store(-1, Ordering::SeqCst);
}

fn wait_for_handler_hits(count: u32) {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
    while HANDLER_HITS.load(Ordering::SeqCst) < count && std::time::Instant::now() < deadline {
        std::hint::spin_loop();
    }
}

unsafe fn cstring(s: &str) -> CString {
    CString::new(s).unwrap_or_else(|_| CString::new("/tmp/dnotify-invalid").unwrap())
}

unsafe fn mkdir(path: &str) -> bool {
    let c = cstring(path);
    libc::mkdir(c.as_ptr(), 0o700) == 0 || errno() == libc::EEXIST
}

unsafe fn open_dir(path: &str) -> i32 {
    let c = cstring(path);
    libc::open(c.as_ptr(), libc::O_RDONLY | libc::O_DIRECTORY)
}

unsafe fn chdir(path: &str) -> bool {
    let c = cstring(path);
    libc::chdir(c.as_ptr()) == 0
}

unsafe fn arm_dnotify(fd: i32, mask: i32, sig: i32) -> bool {
    libc::fcntl(fd, F_SETSIG, sig) == 0 && libc::fcntl(fd, F_NOTIFY, mask | DN_MULTISHOT) == 0
}

unsafe fn install_handler(sig: i32) -> bool {
    let mut sa: libc::sigaction = std::mem::zeroed();
    sa.sa_sigaction = on_dnotify as *const () as usize;
    sa.sa_flags = libc::SA_SIGINFO;
    libc::sigemptyset(&mut sa.sa_mask);
    libc::sigaction(sig, &sa, std::ptr::null_mut()) == 0
}

unsafe fn consume_dnotify_sig(sig: i32, expected_fd: i32) -> bool {
    let mut set: libc::sigset_t = std::mem::zeroed();
    libc::sigemptyset(&mut set);
    libc::sigaddset(&mut set, sig);
    let ts = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    let mut info: libc::siginfo_t = std::mem::zeroed();
    let rc = libc::sigtimedwait(&set, &mut info, &ts);
    let base = &info as *const libc::siginfo_t as *const u8;
    let si_fd = *(base.add(24) as *const i32);
    rc == sig && si_fd == expected_fd
}

unsafe fn signal_is_blocked(sig: i32) -> bool {
    let mut set: libc::sigset_t = std::mem::zeroed();
    if libc::sigprocmask(libc::SIG_SETMASK, std::ptr::null(), &mut set) != 0 {
        return false;
    }
    libc::sigismember(&set, sig) == 1
}

unsafe fn signal_is_pending(sig: i32) -> bool {
    let mut set: libc::sigset_t = std::mem::zeroed();
    if libc::sigpending(&mut set) != 0 {
        return false;
    }
    libc::sigismember(&set, sig) == 1
}

unsafe fn handler_sequence(sig: i32, base: &str) -> bool {
    let sub = format!("{base}/sub");
    let setup = install_handler(sig) && mkdir(base) && mkdir(&sub) && chdir(base);
    let parent_fd = open_dir(".");
    let sub_fd = open_dir("sub");
    reset_handler_state();
    let armed = setup
        && parent_fd >= 0
        && sub_fd >= 0
        && arm_dnotify(parent_fd, DN_ATTRIB, sig)
        && arm_dnotify(sub_fd, DN_ATTRIB, sig);
    if armed && chmod("sub") {
        wait_for_handler_hits(2);
    }
    let ok = HANDLER_HITS.load(Ordering::SeqCst) == 2
        && FIRST_HANDLER_FD.load(Ordering::SeqCst) == parent_fd
        && SECOND_HANDLER_FD.load(Ordering::SeqCst) == sub_fd;
    if sub_fd >= 0 {
        libc::close(sub_fd);
    }
    if parent_fd >= 0 {
        libc::close(parent_fd);
    }
    ok
}

unsafe fn forked_handler_sequence(sig: i32, base: &str) -> bool {
    let pid = libc::fork();
    if pid == 0 {
        let ok = handler_sequence(sig, base);
        libc::_exit(if ok { 0 } else { 1 });
    }
    if pid < 0 {
        return false;
    }
    let mut status = 0;
    libc::waitpid(pid, &mut status, 0) == pid && libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0
}

unsafe fn chmod(path: &str) -> bool {
    let c = cstring(path);
    libc::chmod(c.as_ptr(), 0o755) == 0
}

unsafe fn rename_path(old: &str, new: &str) -> bool {
    let old = cstring(old);
    let new = cstring(new);
    libc::rename(old.as_ptr(), new.as_ptr()) == 0
}

unsafe fn relative_rename_sequence(sig: i32, base: &str) -> bool {
    let setup = block_signal(sig) && mkdir(base) && chdir(base) && mkdir("test_dir");
    let file = cstring("test_file");
    let file_fd = libc::open(file.as_ptr(), libc::O_WRONLY | libc::O_CREAT, 0o666);
    if file_fd >= 0 {
        libc::close(file_fd);
    }
    let parent_fd = open_dir(".");
    let sub_fd = open_dir("test_dir");
    let armed = setup
        && file_fd >= 0
        && parent_fd >= 0
        && sub_fd >= 0
        && arm_dnotify(parent_fd, DN_RENAME, sig)
        && arm_dnotify(sub_fd, DN_RENAME, sig);

    let moved_into_subdir = armed && rename_path("test_file", "test_dir/test_file");
    let no_parent_for_child_move = moved_into_subdir && !consume_dnotify_sig(sig, parent_fd);
    let no_subdir_for_child_move = moved_into_subdir && !consume_dnotify_sig(sig, sub_fd);
    let subdir_renamed = moved_into_subdir && rename_path("test_dir", "test_dir2");
    let parent_for_subdir_move = subdir_renamed && consume_dnotify_sig(sig, parent_fd);
    let no_subdir_for_self_move = subdir_renamed && !consume_dnotify_sig(sig, sub_fd);

    if sub_fd >= 0 {
        libc::close(sub_fd);
    }
    if parent_fd >= 0 {
        libc::close(parent_fd);
    }

    no_parent_for_child_move
        && no_subdir_for_child_move
        && parent_for_subdir_move
        && no_subdir_for_self_move
}

fn main() {
    unsafe {
        let base = format!("/tmp/dnotify-probe-{}", libc::getpid());
        let child = format!("{base}/child");
        let handler_base = format!("/tmp/dnotify-handler-{}", libc::getpid());

        let sig = libc::SIGRTMIN() + 1;
        let setup = block_signal(sig) && mkdir(&base) && mkdir(&child);
        let parent_fd = open_dir(&base);
        let child_fd = open_dir(&child);
        let armed = setup
            && parent_fd >= 0
            && child_fd >= 0
            && arm_dnotify(parent_fd, DN_ATTRIB, sig)
            && arm_dnotify(child_fd, DN_ATTRIB, sig);

        let child_chmod = armed && chmod(&child);
        let parent_attrib_pending = child_chmod && consume_dnotify_sig(sig, parent_fd);
        let child_attrib_pending = child_chmod && consume_dnotify_sig(sig, child_fd);

        let rename_base = format!("/tmp/dnotify-rename-{}", libc::getpid());
        let rename_child = format!("{rename_base}/child");
        let rename_moved = format!("{rename_base}/moved");
        let rename_sig = libc::SIGRTMIN() + 4;
        let rename_setup = block_signal(rename_sig) && mkdir(&rename_base) && mkdir(&rename_child);
        let rename_parent_fd = open_dir(&rename_base);
        let rename_child_fd = open_dir(&rename_child);
        let rename_armed = rename_setup
            && rename_parent_fd >= 0
            && rename_child_fd >= 0
            && arm_dnotify(rename_parent_fd, DN_RENAME, rename_sig)
            && arm_dnotify(rename_child_fd, DN_RENAME, rename_sig);
        let child_renamed = rename_armed && rename_path(&rename_child, &rename_moved);
        let parent_rename_pending =
            child_renamed && consume_dnotify_sig(rename_sig, rename_parent_fd);
        let child_rename_not_pending =
            child_renamed && !consume_dnotify_sig(rename_sig, rename_child_fd);
        let relative_rename_ok =
            relative_rename_sequence(libc::SIGRTMIN() + 5, &format!("/tmp/dnotify-relative-{}", libc::getpid()));

        let handler_sig = libc::SIGRTMIN() + 2;
        let handler_setup = install_handler(handler_sig) && mkdir(&handler_base);
        let handler_fd = open_dir(&handler_base);
        reset_handler_state();
        let handler_armed =
            handler_setup && handler_fd >= 0 && arm_dnotify(handler_fd, DN_ATTRIB, handler_sig);
        let handler_mutated = handler_armed && chmod(&handler_base);
        if handler_mutated {
            wait_for_handler_hits(1);
        }
        let handler_hits = HANDLER_HITS.load(Ordering::SeqCst);
        let handler_si_fd = HANDLER_SI_FD.load(Ordering::SeqCst);
        let handler_si_fd_matches = handler_hits == 1 && handler_si_fd == handler_fd;

        let seq_base = format!("/tmp/dnotify-seq-{}", libc::getpid());
        let seq_sub = format!("{seq_base}/sub");
        let seq_sig = libc::SIGRTMIN() + 3;
        let seq_setup =
            install_handler(seq_sig) && mkdir(&seq_base) && mkdir(&seq_sub) && chdir(&seq_base);
        let seq_parent_fd = open_dir(".");
        let seq_sub_fd = open_dir("sub");
        reset_handler_state();
        let seq_armed = seq_setup
            && seq_parent_fd >= 0
            && seq_sub_fd >= 0
            && arm_dnotify(seq_parent_fd, DN_ATTRIB, seq_sig)
            && arm_dnotify(seq_sub_fd, DN_ATTRIB, seq_sig);
        let seq_mutated = seq_armed && chmod("sub");
        if seq_mutated {
            wait_for_handler_hits(2);
        }
        let seq_hits_before_syscall = HANDLER_HITS.load(Ordering::SeqCst);
        let seq_sig_blocked_after_first_wait = signal_is_blocked(seq_sig);
        let seq_sig_pending_after_first_wait = signal_is_pending(seq_sig);
        if seq_hits_before_syscall < 2 {
            libc::getpid();
            wait_for_handler_hits(2);
        }
        let seq_hits = HANDLER_HITS.load(Ordering::SeqCst);
        let seq_first_fd = FIRST_HANDLER_FD.load(Ordering::SeqCst);
        let seq_second_fd = SECOND_HANDLER_FD.load(Ordering::SeqCst);
        let forked_seq_base = format!("/tmp/dnotify-forked-seq-{}", libc::getpid());
        let forked_seq_ok = forked_handler_sequence(libc::SIGRTMIN() + 3, &forked_seq_base);

        report!(
            dnotify_armed = armed,
            parent_attrib_pending = parent_attrib_pending,
            child_attrib_pending = child_attrib_pending,
            rename_armed = rename_armed,
            parent_rename_pending = parent_rename_pending,
            child_rename_not_pending = child_rename_not_pending,
            relative_rename_ok = relative_rename_ok,
            handler_armed = handler_armed,
            handler_delivered = handler_hits == 1,
            handler_si_fd_matches = handler_si_fd_matches,
            handler_seq_second_after_syscall = seq_hits_before_syscall < 2 && seq_hits == 2,
            handler_seq_sig_unblocked = !seq_sig_blocked_after_first_wait,
            handler_seq_sig_pending = seq_sig_pending_after_first_wait,
            handler_seq_two_hits = seq_hits == 2,
            handler_seq_parent_first = seq_first_fd == seq_parent_fd,
            handler_seq_child_first = seq_first_fd == seq_sub_fd,
            handler_seq_child_second = seq_second_fd == seq_sub_fd,
            forked_handler_seq_ok = forked_seq_ok,
        );

        if seq_sub_fd >= 0 {
            libc::close(seq_sub_fd);
        }
        if seq_parent_fd >= 0 {
            libc::close(seq_parent_fd);
        }
        if handler_fd >= 0 {
            libc::close(handler_fd);
        }
        if rename_child_fd >= 0 {
            libc::close(rename_child_fd);
        }
        if rename_parent_fd >= 0 {
            libc::close(rename_parent_fd);
        }
        if child_fd >= 0 {
            libc::close(child_fd);
        }
        if parent_fd >= 0 {
            libc::close(parent_fd);
        }
    }
}
