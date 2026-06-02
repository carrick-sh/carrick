//! A guest must be able to resolve its OWN hostname:
//! `getaddrinfo(gethostname(), ...)` (equivalently `gethostbyname`) succeeds on
//! every Linux host and Docker container, because the system seeds `/etc/hosts`
//! with the configured hostname. Countless apps look up their own name to find
//! their IP (servers binding, logging, clustering, `socket` self-tests).
//!
//! carrick reports the hostname (`carrick`) via uname but used to synthesize an
//! `/etc/hosts` with only `localhost` — so `getaddrinfo("carrick")` fell through
//! to DNS and failed (EAI_NONAME / gaierror). CPython test_mmap... err test_socket
//! testHostnameRes + testSockName SKIP on that failure (vs run+pass on Docker).
//! Fix: seed `/etc/hosts` with the hostname on 127.0.1.1 (Debian convention),
//! derived from the single canonical UTS-nodename source. --net=host contract:
//! one global hostname on loopback. INVARIANT: the guest resolves its own name.

use conformance_probes::report;

fn main() {
    unsafe {
        // gethostname() into a NUL-terminated buffer.
        let mut buf = [0 as libc::c_char; 256];
        let gh = libc::gethostname(buf.as_mut_ptr(), buf.len() - 1);
        let name_ptr: *const libc::c_char = buf.as_ptr();

        // getaddrinfo(hostname, NULL, {AF_INET}) — the resolution every app does.
        let mut hints: libc::addrinfo = core::mem::zeroed();
        hints.ai_family = libc::AF_INET;
        hints.ai_socktype = libc::SOCK_STREAM;
        let mut res: *mut libc::addrinfo = core::ptr::null_mut();
        let rc = libc::getaddrinfo(name_ptr, core::ptr::null(), &hints, &mut res);
        let resolved = rc == 0 && !res.is_null();

        // Pull the resolved IPv4 (sanity: a dotted address, like the test asserts).
        let mut got_v4 = false;
        if resolved {
            let ai = &*res;
            if ai.ai_family == libc::AF_INET && !ai.ai_addr.is_null() {
                got_v4 = true;
            }
            libc::freeaddrinfo(res);
        }

        report!(
            gethostname_ok = gh == 0,
            self_hostname_resolves = resolved,
            resolves_to_ipv4 = got_v4,
        );
    }
}
