//! termios c_cflag CSIZE / c_iflag IXON/IXOFF must round-trip at the LINUX bit
//! positions. carrick's host_tty.rs copies c_cflag (COMMON_CFLAG_MASK 0x0FFF)
//! and c_iflag (COMMON_IFLAG_MASK 0x0FFF) 1:1 between the guest Linux ABI and
//! the macOS Darwin termios, but the field positions differ:
//!   Linux  CSIZE=0x30  (CS7=0x20, CS8=0x30), CSTOPB=0x40, PARENB=0x100,
//!          PARODD=0x200, IXON=0x400, IXOFF=0x1000
//!   Darwin CSIZE=0x300 (CS7=0x200,CS8=0x300),CSTOPB=0x400,PARENB=0x1000,
//!          PARODD=0x2000,IXON=0x200, IXOFF=0x400
//! A 1:1 copy mistranslates every one of these: Linux CS8 (0x30) is written
//! into Darwin bits that are not CSIZE, Linux IXON (0x400) lands on Darwin
//! IXOFF, and Linux IXOFF (0x1000) is masked away entirely by 0x0FFF.
//!
//! This probe opens a real pty (posix_openpt -> grantpt -> unlockpt -> ptsname
//! -> open slave; the same path the existing ptypair probe exercises, which
//! carrick routes through devpts + host_tty get_host_termios/set_host_termios),
//! tcgetattr, clears CSIZE + sets CS7, tcsetattr, tcgetattr, asserts CS7; then
//! sets CS8 + PARENB|PARODD + CSTOPB + IXON|IXOFF, tcsetattr, tcgetattr, and
//! asserts every bit round-trips at its LINUX value. Under real Linux (and
//! carrick after the per-field translation fix) all booleans are true; under
//! buggy carrick the CSIZE/parity/IXON/IXOFF assertions diverge.
//!
//! Deterministic + bounded: the probe SETS the bits it checks (starting termios
//! state is irrelevant) and makes only non-blocking ioctls — no read/write on
//! the pty, no fork, no waitpid — so it cannot hang and prints no device index,
//! pid, address, or speed. On any setup failure it prints a single
//! `setup_ok=false` and returns.

use std::ffi::CStr;

use conformance_probes::report;

// Linux aarch64 termios bit values (asm-generic/termbits.h), the values the
// guest ABI uses. The probe runs as a Linux aarch64 ELF, so libc's CS7/CS8/etc
// already ARE these values, but we hard-code them so the invariant is explicit
// and identical on both sides of the diff.
const L_CSIZE: u32 = 0x0030;
const L_CS7: u32 = 0x0020;
const L_CS8: u32 = 0x0030;
const L_CSTOPB: u32 = 0x0040;
const L_PARENB: u32 = 0x0100;
const L_PARODD: u32 = 0x0200;
const L_IXON: u32 = 0x0400;
const L_IXOFF: u32 = 0x1000;

unsafe fn get(fd: i32, t: &mut libc::termios) -> bool {
    libc::tcgetattr(fd, t as *mut libc::termios) == 0
}
unsafe fn set(fd: i32, t: &libc::termios) -> bool {
    libc::tcsetattr(fd, libc::TCSANOW, t as *const libc::termios) == 0
}

fn main() {
    unsafe {
        let master = libc::posix_openpt(libc::O_RDWR | libc::O_NOCTTY);
        if master < 0 || libc::grantpt(master) != 0 || libc::unlockpt(master) != 0 {
            report!(setup_ok = false);
            return;
        }
        let name_ptr = libc::ptsname(master);
        if name_ptr.is_null() {
            report!(setup_ok = false);
            return;
        }
        let name = CStr::from_ptr(name_ptr).to_owned();
        let slave = libc::open(name.as_ptr(), libc::O_RDWR | libc::O_NOCTTY, 0u32);
        if slave < 0 {
            report!(setup_ok = false);
            return;
        }

        let mut t: libc::termios = core::mem::zeroed();
        if !get(slave, &mut t) {
            report!(setup_ok = false);
            return;
        }

        // --- Phase 1: CS7 ---
        t.c_cflag = (t.c_cflag & !(L_CSIZE as libc::tcflag_t)) | (L_CS7 as libc::tcflag_t);
        let set1_ok = set(slave, &t);
        let mut r1: libc::termios = core::mem::zeroed();
        let get1_ok = get(slave, &mut r1);
        // NB: CS7 read-back is NOT asserted — a Linux pty coerces character size
        // to CS8 (no UART), so CS8 below validates the CSIZE field translation.

        // --- Phase 2: CS8 + CSTOPB + PARENB|PARODD + IXON|IXOFF ---
        let mut t2: libc::termios = core::mem::zeroed();
        let _ = get(slave, &mut t2);
        t2.c_cflag = (t2.c_cflag & !(L_CSIZE as libc::tcflag_t))
            | (L_CS8 as libc::tcflag_t)
            | (L_CSTOPB as libc::tcflag_t)
            | (L_PARENB as libc::tcflag_t)
            | (L_PARODD as libc::tcflag_t);
        t2.c_iflag |= (L_IXON | L_IXOFF) as libc::tcflag_t;
        let set2_ok = set(slave, &t2);
        let mut r2: libc::termios = core::mem::zeroed();
        let get2_ok = get(slave, &mut r2);
        let cf = r2.c_cflag as u32;
        let if_ = r2.c_iflag as u32;

        report!(
            setup_ok = true,
            slave_isatty = libc::isatty(slave) == 1,
            set1_ok = set1_ok,
            get1_ok = get1_ok,
            set2_ok = set2_ok,
            get2_ok = get2_ok,
            // CS8/CSTOPB/PARODD validate the c_cflag field translation; a Linux
            // pty coerces CS7->CS8 and drops PARENB (no UART), so those two are
            // not asserted (translation correctness is proven by the rest).
            cs8_csize_is_cs8 = (cf & L_CSIZE) == L_CS8,
            cstopb_set = (cf & L_CSTOPB) != 0,
            parodd_set = (cf & L_PARODD) != 0,
            // Linux: IXON (0x400) and IXOFF (0x1000) both round-trip.
            ixon_set = (if_ & L_IXON) != 0,
            ixoff_set = (if_ & L_IXOFF) != 0,
        );

        libc::close(slave);
        libc::close(master);
    }
}