//! AF_UNIX bind(pathname) must materialise a stat-able S_IFSOCK node at the
//! GUEST path, exactly like Linux. CPython's multiprocessing forkserver binds
//! a listener at a temp path and then `os.chmod(addr)`s / `os.path.exists()`s /
//! `os.unlink()`s it; on carrick the host socket lived at a hashed scratch path
//! so a stat/chmod/unlink of the guest path was ENOENT and the forkserver died.
//!
//! Deterministic, line-exact carrick-vs-Linux. We bind under /tmp (a writable
//! overlay path on both) using a fixed name so the output is stable.

use conformance_probes::errno;

const SOCK_PATH: &[u8] = b"/tmp/carrick_bindunixnode.sock\0";

fn sun(path: &[u8]) -> (libc::sockaddr_un, libc::socklen_t) {
    unsafe {
        let mut a: libc::sockaddr_un = std::mem::zeroed();
        a.sun_family = libc::AF_UNIX as _;
        // path includes the trailing NUL; copy it in.
        for (i, &b) in path.iter().enumerate() {
            a.sun_path[i] = b as libc::c_char;
        }
        // addrlen = offsetof(sun_path) + strlen(path) + 1 (incl NUL), the glibc
        // convention for a pathname socket.
        let base = std::mem::size_of::<libc::sa_family_t>();
        let len = (base + path.len()) as libc::socklen_t;
        (a, len)
    }
}

fn main() {
    unsafe {
        // Clean any leftover from a prior run so bind() doesn't EADDRINUSE.
        libc::unlink(SOCK_PATH.as_ptr() as *const libc::c_char);

        let s = libc::socket(libc::AF_UNIX, libc::SOCK_STREAM, 0);
        println!("socket_ok={}", s >= 0);

        let (addr, len) = sun(SOCK_PATH);
        let b = libc::bind(s, &addr as *const _ as *const libc::sockaddr, len);
        println!("bind_ok={}", b == 0);

        // stat the bound path → must exist and be a socket (S_ISSOCK).
        let mut st: libc::stat = std::mem::zeroed();
        let r = libc::stat(SOCK_PATH.as_ptr() as *const libc::c_char, &mut st);
        println!("stat_ok={}", r == 0);
        println!(
            "is_sock={}",
            r == 0 && (st.st_mode & libc::S_IFMT) == libc::S_IFSOCK
        );

        // access(F_OK) on the node → success.
        let acc = libc::access(SOCK_PATH.as_ptr() as *const libc::c_char, libc::F_OK);
        println!("access_ok={}", acc == 0);

        // chmod the node (forkserver does os.chmod(addr, 0o600)). Then re-stat
        // and check the low permission bits took.
        let ch = libc::chmod(SOCK_PATH.as_ptr() as *const libc::c_char, 0o600);
        println!("chmod_ok={}", ch == 0);
        let mut st2: libc::stat = std::mem::zeroed();
        let r2 = libc::stat(SOCK_PATH.as_ptr() as *const libc::c_char, &mut st2);
        println!(
            "chmod_bits_600={}",
            r2 == 0 && (st2.st_mode & 0o777) == 0o600
        );
        // It must still report as a socket after chmod.
        println!(
            "still_sock={}",
            r2 == 0 && (st2.st_mode & libc::S_IFMT) == libc::S_IFSOCK
        );

        // unlink the node → success, then it must no longer exist.
        let u = libc::unlink(SOCK_PATH.as_ptr() as *const libc::c_char);
        println!("unlink_ok={}", u == 0);
        let mut st3: libc::stat = std::mem::zeroed();
        let r3 = libc::stat(SOCK_PATH.as_ptr() as *const libc::c_char, &mut st3);
        println!("gone_after_unlink={}", r3 == -1 && errno() == libc::ENOENT);

        libc::close(s);
    }
}
