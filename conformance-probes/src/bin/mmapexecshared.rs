//! A `MAP_SHARED` file mmap requesting `PROT_READ | PROT_EXEC` (no `PROT_WRITE`)
//! must SUCCEED, exactly as it does on Linux — e.g. the dynamic loader maps
//! executable file segments this way, and CPython's `test_mmap`
//! `test_access_parameter` opens `mmap.mmap(fd, n, prot=PROT_READ|PROT_EXEC)`.
//!
//! carrick backs such a mapping with a host `mmap(MAP_SHARED, fd)` alias. macOS
//! REJECTS `MAP_SHARED | PROT_EXEC` of an ordinary file with EPERM (hardened
//! runtime: only code-signed/validated pages may be shared-executable). carrick
//! used to forward the guest's `PROT_EXEC` straight to that host mmap, so the
//! host mmap failed and the whole alias build errored — which wedged the guest
//! (the syscall never returned: an apparent hang).
//!
//! The host backing does NOT need to be executable: the guest executes through
//! HVF's stage-2 (mapped RWX) and its own stage-1 page tables (UXN clear), never
//! through the host pointer, which carrick only ever reads. So carrick must drop
//! `PROT_EXEC` from the host mmap. INVARIANT: the mmap returns a valid pointer
//! and the file content is readable through it.

use conformance_probes::report;

fn main() {
    unsafe {
        let path = c"/tmp/mmapexecshared.bin";
        let fd = libc::open(
            path.as_ptr(),
            libc::O_RDWR | libc::O_CREAT | libc::O_TRUNC,
            0o644,
        );
        if fd < 0 {
            report!(open_ok = false);
            return;
        }
        let payload: [u8; 10] = *b"abcdefghij";
        let _ = libc::write(fd, payload.as_ptr().cast(), payload.len());

        // The exact request CPython's test_access_parameter makes: a MAP_SHARED
        // file mapping with PROT_READ | PROT_EXEC and no PROT_WRITE.
        let p = libc::mmap(
            core::ptr::null_mut(),
            payload.len(),
            libc::PROT_READ | libc::PROT_EXEC,
            libc::MAP_SHARED,
            fd,
            0,
        );
        let mmap_ok = p != libc::MAP_FAILED;

        // Read the file content back through the executable mapping.
        let mut first_byte_ok = false;
        if mmap_ok {
            let s = core::slice::from_raw_parts(p as *const u8, payload.len());
            first_byte_ok = s[0] == b'a' && s[9] == b'j';
            libc::munmap(p, payload.len());
        }
        libc::close(fd);

        report!(
            shared_exec_mmap_ok = mmap_ok,
            content_readable = first_byte_ok,
        );
    }
}
