//! Conformance probe for SO_PEERCRED guest identity and send MSG_MORE coalescing.
//!
//! Pins Linux socket behaviour for two LTP gaps:
//! 1. Gap 1 (ltp-getsockopt02): `SO_PEERCRED` on AF_UNIX returns the peer's
//!    guest credentials (`pid`, `uid`, `gid`) established at connect or socketpair
//!    time, in guest PID/user namespace domain, and surviving peer exit.
//! 2. Gap 2 (ltp-send02): `send`/`sendto`/`sendmsg` with `MSG_MORE` coalesces
//!    multiple chunks into a single datagram on datagram sockets (UDP, AF_UNIX
//!    SOCK_DGRAM), emitting the datagram when MSG_MORE is omitted or on close.
//!
//! Expected Linux output:
//! parent_peercred_pid_is_child_getpid=true
//! child_peercred_pid_is_parent_getpid=true
//! peercred_uid_gid_match_getuid_getgid=true
//! connect_time_identity_survives_child_exit=true
//! path_parent_peercred_pid_is_child_getpid=true
//! path_child_peercred_pid_is_parent_getpid=true
//! path_connect_time_identity_survives_child_exit=true
//! socketpair_peercred_pid_matches_creator=true
//! udp_msg_more_coalesced_len=true
//! udp_plain_send_len=true
//! unix_dgram_msg_more_coalesced_len=false   (Linux does not cork AF_UNIX datagrams)
//! msg_more_then_close_flushes=false          (a corked datagram is discarded on close)

use conformance_probes::report;
use core::mem::MaybeUninit;

const LINUX_MSG_MORE: libc::c_int = 0x8000;
const SO_PEERCRED: libc::c_int = 17;

#[repr(C)]
#[derive(Clone, Copy, Default, Debug)]
struct LinuxUcred {
    pid: u32,
    uid: u32,
    gid: u32,
}

#[inline]
fn errno() -> i32 {
    std::io::Error::last_os_error().raw_os_error().unwrap_or(-1)
}

unsafe fn reap_child(pid: libc::pid_t) -> libc::c_int {
    let mut status = 0;
    loop {
        let rc = libc::waitpid(pid, &mut status, 0);
        if rc == -1 {
            let err = errno();
            if err == libc::EINTR {
                continue;
            }
            panic!("waitpid({pid}) failed: errno={err}");
        }
        if rc != pid {
            panic!("waitpid({pid}) returned unexpected pid={rc}");
        }
        return status;
    }
}

unsafe fn set_recv_timeout_ms(fd: i32, ms: i64) {
    let tv = libc::timeval {
        tv_sec: (ms / 1000) as _,
        tv_usec: ((ms % 1000) * 1000) as _,
    };
    let rc = libc::setsockopt(
        fd,
        libc::SOL_SOCKET,
        libc::SO_RCVTIMEO,
        (&tv as *const libc::timeval).cast(),
        core::mem::size_of::<libc::timeval>() as libc::socklen_t,
    );
    if rc != 0 {
        panic!("setsockopt(SO_RCVTIMEO) failed: errno={}", errno());
    }
}

fn main() {
    unsafe {
        // Suppress core dumps and arm an overall 10s watchdog alarm.
        let rlim = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        libc::setrlimit(libc::RLIMIT_CORE, &rlim);
        libc::alarm(10);

        let parent_pid = libc::getpid() as u32;
        let parent_uid = libc::geteuid() as u32;
        let parent_gid = libc::getegid() as u32;

        // ── Gap 1: SO_PEERCRED on socketpair ─────────────────────────────────
        let mut sv = [-1i32; 2];
        if libc::socketpair(libc::AF_UNIX, libc::SOCK_STREAM, 0, sv.as_mut_ptr()) != 0 {
            panic!("socketpair() failed: errno={}", errno());
        }
        let mut sp_cred = LinuxUcred::default();
        let mut sp_len = core::mem::size_of::<LinuxUcred>() as libc::socklen_t;
        if libc::getsockopt(
            sv[0],
            libc::SOL_SOCKET,
            SO_PEERCRED,
            (&mut sp_cred as *mut LinuxUcred).cast(),
            &mut sp_len,
        ) != 0
        {
            panic!("getsockopt(SO_PEERCRED) failed: errno={}", errno());
        }
        let socketpair_peercred_pid_matches_creator = sp_cred.pid == parent_pid;
        libc::close(sv[0]);
        libc::close(sv[1]);

        // ── Gap 1: SO_PEERCRED on path-connected AF_UNIX ─────────────────────
        let sock_path = b"/tmp/probe_socketcredmore.sock\0";
        libc::unlink(sock_path.as_ptr().cast());

        let listener = libc::socket(libc::AF_UNIX, libc::SOCK_STREAM, 0);
        if listener < 0 {
            panic!("socket(AF_UNIX) listener failed: errno={}", errno());
        }

        let mut sun: libc::sockaddr_un = MaybeUninit::zeroed().assume_init();
        sun.sun_family = libc::AF_UNIX as libc::sa_family_t;
        core::ptr::copy_nonoverlapping(
            sock_path.as_ptr().cast(),
            sun.sun_path.as_mut_ptr(),
            sock_path.len(),
        );

        let sun_len = core::mem::size_of::<libc::sa_family_t>() + sock_path.len();
        if libc::bind(
            listener,
            (&sun as *const libc::sockaddr_un).cast(),
            sun_len as libc::socklen_t,
        ) != 0
        {
            panic!("bind(AF_UNIX) failed: errno={}", errno());
        }
        if libc::listen(listener, 5) != 0 {
            panic!("listen() failed: errno={}", errno());
        }

        let mut child_pipe = [-1i32; 2];
        if libc::pipe(child_pipe.as_mut_ptr()) != 0 {
            panic!("pipe() failed: errno={}", errno());
        }

        let child_pid = libc::fork();
        if child_pid < 0 {
            panic!("fork() failed: errno={}", errno());
        }

        if child_pid == 0 {
            libc::alarm(3);
            libc::close(listener);
            libc::close(child_pipe[0]);

            let client = libc::socket(libc::AF_UNIX, libc::SOCK_STREAM, 0);
            if client < 0 {
                libc::_exit(1);
            }

            if libc::connect(
                client,
                (&sun as *const libc::sockaddr_un).cast(),
                sun_len as libc::socklen_t,
            ) != 0
            {
                libc::_exit(2);
            }

            let mut child_ucred = LinuxUcred::default();
            let mut child_len = core::mem::size_of::<LinuxUcred>() as libc::socklen_t;
            if libc::getsockopt(
                client,
                libc::SOL_SOCKET,
                SO_PEERCRED,
                (&mut child_ucred as *mut LinuxUcred).cast(),
                &mut child_len,
            ) != 0
            {
                libc::_exit(3);
            }

            let written = libc::write(
                child_pipe[1],
                (&child_ucred as *const LinuxUcred).cast(),
                core::mem::size_of::<LinuxUcred>(),
            );
            if written as usize != core::mem::size_of::<LinuxUcred>() {
                libc::_exit(4);
            }

            libc::close(client);
            libc::close(child_pipe[1]);
            libc::_exit(0);
        }

        libc::close(child_pipe[1]);
        let accepted = libc::accept(listener, core::ptr::null_mut(), core::ptr::null_mut());
        if accepted < 0 {
            panic!("accept() failed: errno={}", errno());
        }

        let mut child_obs = LinuxUcred::default();
        let read_bytes = libc::read(
            child_pipe[0],
            (&mut child_obs as *mut LinuxUcred).cast(),
            core::mem::size_of::<LinuxUcred>(),
        );
        libc::close(child_pipe[0]);
        if read_bytes as usize != core::mem::size_of::<LinuxUcred>() {
            panic!("failed to read child ucred from pipe");
        }

        let mut parent_ucred = LinuxUcred::default();
        let mut parent_len = core::mem::size_of::<LinuxUcred>() as libc::socklen_t;
        if libc::getsockopt(
            accepted,
            libc::SOL_SOCKET,
            SO_PEERCRED,
            (&mut parent_ucred as *mut LinuxUcred).cast(),
            &mut parent_len,
        ) != 0
        {
            panic!("parent getsockopt(SO_PEERCRED) failed: errno={}", errno());
        }

        let child_status = reap_child(child_pid);
        if !libc::WIFEXITED(child_status) || libc::WEXITSTATUS(child_status) != 0 {
            panic!("child exited abnormally: status={child_status}");
        }

        // After child exit, peercred on accepted connection must still report child's credentials.
        let mut after_exit_ucred = LinuxUcred::default();
        let mut after_len = core::mem::size_of::<LinuxUcred>() as libc::socklen_t;
        if libc::getsockopt(
            accepted,
            libc::SOL_SOCKET,
            SO_PEERCRED,
            (&mut after_exit_ucred as *mut LinuxUcred).cast(),
            &mut after_len,
        ) != 0
        {
            panic!("getsockopt after child exit failed: errno={}", errno());
        }

        libc::close(accepted);
        libc::close(listener);
        libc::unlink(sock_path.as_ptr().cast());

        let parent_peercred_pid_is_child_getpid = parent_ucred.pid == child_pid as u32;
        let child_peercred_pid_is_parent_getpid = child_obs.pid == parent_pid;
        let peercred_uid_gid_match_getuid_getgid = parent_ucred.uid == parent_uid
            && parent_ucred.gid == parent_gid
            && child_obs.uid == parent_uid
            && child_obs.gid == parent_gid;
        let connect_time_identity_survives_child_exit = after_exit_ucred.pid == child_pid as u32;

        let path_parent_peercred_pid_is_child_getpid = parent_peercred_pid_is_child_getpid;
        let path_child_peercred_pid_is_parent_getpid = child_peercred_pid_is_parent_getpid;
        let path_connect_time_identity_survives_child_exit =
            connect_time_identity_survives_child_exit;

        // ── Gap 2: UDP MSG_MORE coalescing and close flush ───────────────────
        let udp_rcv = libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0);
        if udp_rcv < 0 {
            panic!("socket(AF_INET, SOCK_DGRAM) failed: errno={}", errno());
        }
        set_recv_timeout_ms(udp_rcv, 500);

        let mut udp_sin: libc::sockaddr_in = MaybeUninit::zeroed().assume_init();
        udp_sin.sin_family = libc::AF_INET as libc::sa_family_t;
        udp_sin.sin_addr.s_addr = libc::htonl(libc::INADDR_LOOPBACK);
        udp_sin.sin_port = 0;

        if libc::bind(
            udp_rcv,
            (&udp_sin as *const libc::sockaddr_in).cast(),
            core::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
        ) != 0
        {
            panic!("bind(udp_rcv) failed: errno={}", errno());
        }

        let mut assigned_sin: libc::sockaddr_in = MaybeUninit::zeroed().assume_init();
        let mut assigned_len = core::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t;
        if libc::getsockname(
            udp_rcv,
            (&mut assigned_sin as *mut libc::sockaddr_in).cast(),
            &mut assigned_len,
        ) != 0
        {
            panic!("getsockname(udp_rcv) failed: errno={}", errno());
        }

        let udp_snd = libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0);
        if udp_snd < 0 {
            panic!("socket(AF_INET, SOCK_DGRAM) sender failed: errno={}", errno());
        }

        let chunk16 = [0x41u8; 16];
        let chunk1 = [0x42u8; 1];
        let mut rcv_buf = [0u8; 64];

        // 1. MSG_MORE coalesced: 16 bytes with MSG_MORE, then 1 byte without MSG_MORE -> 17 bytes
        let sent1 = libc::sendto(
            udp_snd,
            chunk16.as_ptr().cast(),
            chunk16.len(),
            LINUX_MSG_MORE,
            (&assigned_sin as *const libc::sockaddr_in).cast(),
            assigned_len,
        );
        let sent2 = libc::sendto(
            udp_snd,
            chunk1.as_ptr().cast(),
            chunk1.len(),
            0,
            (&assigned_sin as *const libc::sockaddr_in).cast(),
            assigned_len,
        );
        let rcv1 = libc::recv(udp_rcv, rcv_buf.as_mut_ptr().cast(), rcv_buf.len(), 0);
        let udp_msg_more_coalesced_len = sent1 == 16 && sent2 == 1 && rcv1 == 17;

        // 2. Plain send: 16 bytes without MSG_MORE -> 16 bytes
        let sent_plain = libc::sendto(
            udp_snd,
            chunk16.as_ptr().cast(),
            chunk16.len(),
            0,
            (&assigned_sin as *const libc::sockaddr_in).cast(),
            assigned_len,
        );
        let rcv2 = libc::recv(udp_rcv, rcv_buf.as_mut_ptr().cast(), rcv_buf.len(), 0);
        let udp_plain_send_len = sent_plain == 16 && rcv2 == 16;

        // 3. MSG_MORE then close flushes the datagram:
        let sent3 = libc::sendto(
            udp_snd,
            chunk16.as_ptr().cast(),
            chunk16.len(),
            LINUX_MSG_MORE,
            (&assigned_sin as *const libc::sockaddr_in).cast(),
            assigned_len,
        );
        libc::close(udp_snd);
        let rcv3 = libc::recv(udp_rcv, rcv_buf.as_mut_ptr().cast(), rcv_buf.len(), 0);
        let msg_more_then_close_flushes = sent3 == 16 && rcv3 == 16;
        libc::close(udp_rcv);

        // ── Gap 2: AF_UNIX datagram MSG_MORE coalescing ──────────────────────
        let dgram_path = b"/tmp/probe_socketcredmore_dgram.sock\0";
        libc::unlink(dgram_path.as_ptr().cast());

        let unix_rcv = libc::socket(libc::AF_UNIX, libc::SOCK_DGRAM, 0);
        if unix_rcv < 0 {
            panic!("socket(AF_UNIX, SOCK_DGRAM) failed: errno={}", errno());
        }
        set_recv_timeout_ms(unix_rcv, 500);

        let mut unix_sun: libc::sockaddr_un = MaybeUninit::zeroed().assume_init();
        unix_sun.sun_family = libc::AF_UNIX as libc::sa_family_t;
        core::ptr::copy_nonoverlapping(
            dgram_path.as_ptr().cast(),
            unix_sun.sun_path.as_mut_ptr(),
            dgram_path.len(),
        );
        let unix_sun_len = core::mem::size_of::<libc::sa_family_t>() + dgram_path.len();

        if libc::bind(
            unix_rcv,
            (&unix_sun as *const libc::sockaddr_un).cast(),
            unix_sun_len as libc::socklen_t,
        ) != 0
        {
            panic!("bind(AF_UNIX, SOCK_DGRAM) failed: errno={}", errno());
        }

        let unix_snd = libc::socket(libc::AF_UNIX, libc::SOCK_DGRAM, 0);
        if unix_snd < 0 {
            panic!("socket(AF_UNIX, SOCK_DGRAM) snd failed: errno={}", errno());
        }
        if libc::connect(
            unix_snd,
            (&unix_sun as *const libc::sockaddr_un).cast(),
            unix_sun_len as libc::socklen_t,
        ) != 0
        {
            panic!("connect(unix_snd) failed: errno={}", errno());
        }

        let u_sent1 = libc::send(unix_snd, chunk16.as_ptr().cast(), chunk16.len(), LINUX_MSG_MORE);
        let u_sent2 = libc::send(unix_snd, chunk1.as_ptr().cast(), chunk1.len(), 0);
        let u_rcv = libc::recv(unix_rcv, rcv_buf.as_mut_ptr().cast(), rcv_buf.len(), 0);
        let unix_dgram_msg_more_coalesced_len = u_sent1 == 16 && u_sent2 == 1 && u_rcv == 17;

        libc::close(unix_snd);
        libc::close(unix_rcv);
        libc::unlink(dgram_path.as_ptr().cast());

        libc::alarm(0);

        report!(
            parent_peercred_pid_is_child_getpid = parent_peercred_pid_is_child_getpid,
            child_peercred_pid_is_parent_getpid = child_peercred_pid_is_parent_getpid,
            peercred_uid_gid_match_getuid_getgid = peercred_uid_gid_match_getuid_getgid,
            connect_time_identity_survives_child_exit =
                connect_time_identity_survives_child_exit,
            path_parent_peercred_pid_is_child_getpid = path_parent_peercred_pid_is_child_getpid,
            path_child_peercred_pid_is_parent_getpid = path_child_peercred_pid_is_parent_getpid,
            path_connect_time_identity_survives_child_exit =
                path_connect_time_identity_survives_child_exit,
            socketpair_peercred_pid_matches_creator =
                socketpair_peercred_pid_matches_creator,
            udp_msg_more_coalesced_len = udp_msg_more_coalesced_len,
            udp_plain_send_len = udp_plain_send_len,
            unix_dgram_msg_more_coalesced_len = unix_dgram_msg_more_coalesced_len,
            msg_more_then_close_flushes = msg_more_then_close_flushes,
        );
    }
}
