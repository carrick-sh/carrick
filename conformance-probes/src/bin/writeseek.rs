//! Regular-file overwrite/rewind: the write/lseek mechanism from inotify09.
//! Linux authority: write(2), lseek(2), getrlimit(2). This is not a timing probe.
//! `writeseek [1|8|32|128] [path]`; generic oracle default is eight iterations.
//! No watchers are created. Each write starts at offset zero and must preserve
//! exactly 64 bytes. The structural binding separately meters host offset queries.
use conformance_probes::report;
use std::ffi::CString;

fn main() {
    let args: Vec<_> = std::env::args().skip(1).collect();
    if args.as_slice() == ["lease-alias"] {
        lease_alias();
        return;
    }
    let scale = args.first().map_or(Ok(8usize), |s| s.parse()).unwrap_or(0);
    if ![1, 8, 32, 128].contains(&scale) {
        std::process::exit(2);
    }
    let path = args
        .get(1)
        .cloned()
        .unwrap_or_else(|| format!("/tmp/carrick-writeseek-{}", std::process::id()));
    let path = CString::new(path).expect("path without NUL");
    let mut completed_writes = 0;
    let mut completed_rewinds = 0;
    let mut bytes_match = false;
    let mut offset_matches = false;
    let mut length_matches = false;
    let mut closed = false;
    let mut removed = false;
    unsafe {
        let mut limit: libc::rlimit = std::mem::zeroed();
        let unlimited = libc::getrlimit(libc::RLIMIT_FSIZE, &mut limit) == 0
            && limit.rlim_cur == libc::RLIM_INFINITY;
        let fd = libc::open(
            path.as_ptr(),
            libc::O_CREAT | libc::O_EXCL | libc::O_RDWR,
            0o600,
        );
        if fd >= 0 {
            for _ in 0..scale {
                if libc::write(fd, [0x5au8; 64].as_ptr().cast(), 64) != 64 {
                    break;
                }
                completed_writes += 1;
                if libc::lseek(fd, 0, libc::SEEK_SET) != 0 {
                    break;
                }
                completed_rewinds += 1;
            }
            let mut bytes = [0u8; 64];
            bytes_match =
                libc::read(fd, bytes.as_mut_ptr().cast(), 64) == 64 && bytes == [0x5a; 64];
            offset_matches = libc::lseek(fd, 0, libc::SEEK_CUR) == 64;
            let mut st: libc::stat = std::mem::zeroed();
            length_matches = libc::fstat(fd, &mut st) == 0 && st.st_size == 64;
            closed = libc::close(fd) == 0;
            removed = libc::unlink(path.as_ptr()) == 0;
        }
        report!(
            iterations = scale,
            completed_writes = completed_writes,
            completed_rewinds = completed_rewinds,
            file_limit_unlimited = unlimited,
            bytes_match = bytes_match,
            offset_matches = offset_matches,
            length_matches = length_matches,
            closed = closed,
            removed = removed
        );
    }
}

/// A successful alias write advances the same open-file-description offset,
/// including after another seek has attempted to reacquire an execution lease.
fn lease_alias() {
    let path = CString::new(format!("/tmp/carrick-lease-alias-{}", std::process::id())).unwrap();
    unsafe {
        let fd = libc::open(path.as_ptr(), libc::O_CREAT | libc::O_EXCL | libc::O_RDWR, 0o600);
        assert!(fd >= 0);
        assert_eq!(libc::lseek(fd, 0, libc::SEEK_SET), 0);
        let alias = libc::dup(fd);
        assert!(alias >= 0);
        assert_eq!(libc::lseek(fd, 0, libc::SEEK_SET), 0);
        let written = libc::write(alias, b"x".as_ptr().cast(), 1);
        let offset = libc::lseek(fd, 0, libc::SEEK_CUR);
        let mut byte = [0u8; 1];
        let read = libc::pread(fd, byte.as_mut_ptr().cast(), 1, 0);
        assert_eq!(libc::close(alias), 0);
        assert_eq!(libc::close(fd), 0);
        assert_eq!(libc::unlink(path.as_ptr()), 0);
        report!(alias_write = written, shared_offset = offset, read = read, byte = byte[0]);
    }
}
