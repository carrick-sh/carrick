//! memfd_create(name, flags): an anonymous in-memory file. carrick modelled it
//! ENOSYS (LTP TCONF'd "not supported"); now it creates an unlinked writable
//! file and validates flags/name like Linux. Stands in for LTP memfd_create02
//! (flag + name validation; NO sealing). Uses the raw syscall so musl's wrapper
//! can't pre-validate. Deterministic booleans, line-exact vs Linux.

use conformance_probes::errno;

const MFD_CLOEXEC: i64 = 0x0001;
const MFD_ALLOW_SEALING: i64 = 0x0002;

fn main() {
    unsafe {
        let nm = b"probe\0".as_ptr() as i64;

        // Valid: MFD_CLOEXEC alone → a real fd.
        let r1 = libc::syscall(libc::SYS_memfd_create, nm, MFD_CLOEXEC);
        println!("memfd_cloexec_ok={}", r1 >= 0);
        if r1 >= 0 {
            libc::close(r1 as i32);
        }

        // Valid: MFD_ALLOW_SEALING alone → a real fd.
        let r2 = libc::syscall(libc::SYS_memfd_create, nm, MFD_ALLOW_SEALING);
        println!("memfd_sealing_ok={}", r2 >= 0);
        if r2 >= 0 {
            libc::close(r2 as i32);
        }

        // Invalid flag bit (0x100) → EINVAL.
        let r3 = libc::syscall(libc::SYS_memfd_create, nm, 0x100i64);
        println!(
            "memfd_bad_flag_einval={}",
            r3 == -1 && errno() == libc::EINVAL
        );

        // NULL name → EFAULT.
        let r4 = libc::syscall(libc::SYS_memfd_create, 0i64, 0i64);
        println!(
            "memfd_null_name_efault={}",
            r4 == -1 && errno() == libc::EFAULT
        );

        // 250-char name (> MFD_NAME_MAX_LEN 249) → EINVAL.
        let mut buf = [b'a'; 251];
        buf[250] = 0;
        let r5 = libc::syscall(libc::SYS_memfd_create, buf.as_ptr() as i64, 0i64);
        println!(
            "memfd_long_name_einval={}",
            r5 == -1 && errno() == libc::EINVAL
        );
    }
}
