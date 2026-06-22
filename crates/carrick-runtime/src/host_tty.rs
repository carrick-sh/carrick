//! Host TTY plumbing for guest TCGETS / TCSETS / TIOCGWINSZ ioctls.
//!
//! When carrick's host fd 0/1/2 is a real macOS terminal we want the
//! guest to see the *actual* terminal state — current `c_lflag`
//! (ICANON/ECHO bits), current `c_cc` control characters, and the live
//! window size — not the synthesised "default cooked" values we used
//! while bootstrapping.
//!
//! This module is the thin libc bridge. The flag layouts on Linux
//! (`include/uapi/asm-generic/termbits.h`) and Darwin (`<sys/termios.h>`)
//! differ in width (`u32` vs `u64`) and in the presence of `c_line`,
//! but every POSIX bit we actually care about — ICANON, ECHO, ECHOE,
//! ECHOK, ECHONL, ISIG, IEXTEN, ICRNL, INLCR, ONLCR, OPOST, ISTRIP —
//! shares the same numeric value across the two platforms, so a
//! 32-bit truncation is safe. Anything outside the well-known POSIX
//! mask is dropped on the floor; if a guest probes for a Linux-specific
//! bit we don't translate, the round-trip just reports it as 0 and
//! tcsetattr on the host side is a no-op for that bit. This is the
//! "well known bits 1:1, zero anything we don't understand" policy
//! the comment in the dispatch module describes.
//!
//! We also install a process-wide `Drop` guard that snapshots the
//! host fd-0 termios on first observation and restores it on
//! shutdown, so a guest that crashes mid-`stty raw` doesn't leave
//! the user's real terminal wedged in raw mode. The guard is
//! best-effort: it is registered via `atexit` semantics by living
//! in a `OnceLock`-owned static plus a `host_signal`-style cleanup
//! call from `runtime::run_combined_syscall_loop_with_dispatcher`.

use std::collections::HashMap;

use parking_lot::Mutex;

use crate::linux_abi::{LinuxTermios, LinuxWinsize};

// The Linux↔Darwin termios bit/index translation tables and helpers below are
// macOS-only (Darwin's bit positions and `c_cc` order differ from Linux's). Every
// non-macOS host translates field-by-field against its OWN `libc::` termios bits
// (see the `cfg(not(target_os = "macos"))` impls of
// `host_to_linux_termios`/`linux_to_host_termios`): on Linux those `libc::` values
// EQUAL the guest-Linux values, so the translation is identity-equivalent (the
// Linux box is unchanged); on FreeBSD/NetBSD they are that host's native bits, so
// the translation is faithful by construction. Every Darwin-only item is gated
// under macOS so the non-macOS build stays dead-code-free (clippy denies warns).

/// POSIX `c_iflag` bits that share VALUES between Linux and Darwin:
/// IGNBRK 0x01..ICRNL 0x100 (=0x1FF), IXANY 0x800, IUTF8 0x4000.
/// IXON/IXOFF do NOT share values (Linux 0x400/0x1000 vs Darwin
/// 0x200/0x400) and are translated explicitly below. (audit M4; probe termiosbits)
#[cfg(target_os = "macos")]
const COMMON_IFLAG_MASK: u32 = 0x0000_49FF;
#[cfg(target_os = "macos")]
const LINUX_IXON: u32 = 0x0400;
#[cfg(target_os = "macos")]
const LINUX_IXOFF: u32 = 0x1000;
#[cfg(target_os = "macos")]
const DARWIN_IXON: carrick_portable::TcFlag = 0x0200;
#[cfg(target_os = "macos")]
const DARWIN_IXOFF: carrick_portable::TcFlag = 0x0400;

/// POSIX `c_oflag` bits with matching values: OPOST 0x0001,
/// ONLCR 0x0004 (Linux) — Darwin uses 0x0002 for ONLCR. To keep
/// the round-trip honest we mask only OPOST here; ONLCR is
/// translated explicitly below.
#[cfg(target_os = "macos")]
const COMMON_OFLAG_MASK: u32 = 0x0000_0001;
#[cfg(target_os = "macos")]
const LINUX_ONLCR: u32 = 0x0004;
#[cfg(target_os = "macos")]
const DARWIN_ONLCR: carrick_portable::TcFlag = 0x0002;
#[cfg(target_os = "macos")]
const LINUX_OCRNL: u32 = 0x0008;
#[cfg(target_os = "macos")]
const DARWIN_OCRNL: carrick_portable::TcFlag = 0x0010;

/// c_cflag field values. Linux and Darwin use DIFFERENT bit positions for the
/// CSIZE/CSTOPB/parity group, so each is translated per-field (not masked 1:1).
/// The CBAUD baud nibble is NOT copied (baud rides in c_ispeed/c_ospeed).
/// (audit M4; probe termiosbits)
#[cfg(target_os = "macos")]
const LINUX_CSIZE: u32 = 0x0030;
#[cfg(target_os = "macos")]
const LINUX_CS6: u32 = 0x0010;
#[cfg(target_os = "macos")]
const LINUX_CS7: u32 = 0x0020;
#[cfg(target_os = "macos")]
const LINUX_CS8: u32 = 0x0030;
#[cfg(target_os = "macos")]
const LINUX_CSTOPB: u32 = 0x0040;
#[cfg(target_os = "macos")]
const LINUX_CREAD: u32 = 0x0080;
#[cfg(target_os = "macos")]
const LINUX_PARENB: u32 = 0x0100;
#[cfg(target_os = "macos")]
const LINUX_PARODD: u32 = 0x0200;
#[cfg(target_os = "macos")]
const LINUX_HUPCL: u32 = 0x0400;
#[cfg(target_os = "macos")]
const LINUX_CLOCAL: u32 = 0x0800;
#[cfg(target_os = "macos")]
const DARWIN_CSIZE: carrick_portable::TcFlag = 0x0300;
#[cfg(target_os = "macos")]
const DARWIN_CS6: carrick_portable::TcFlag = 0x0100;
#[cfg(target_os = "macos")]
const DARWIN_CS7: carrick_portable::TcFlag = 0x0200;
#[cfg(target_os = "macos")]
const DARWIN_CS8: carrick_portable::TcFlag = 0x0300;
#[cfg(target_os = "macos")]
const DARWIN_CSTOPB: carrick_portable::TcFlag = 0x0400;
#[cfg(target_os = "macos")]
const DARWIN_CREAD: carrick_portable::TcFlag = 0x0800;
#[cfg(target_os = "macos")]
const DARWIN_PARENB: carrick_portable::TcFlag = 0x1000;
#[cfg(target_os = "macos")]
const DARWIN_PARODD: carrick_portable::TcFlag = 0x2000;
#[cfg(target_os = "macos")]
const DARWIN_HUPCL: carrick_portable::TcFlag = 0x4000;
#[cfg(target_os = "macos")]
const DARWIN_CLOCAL: carrick_portable::TcFlag = 0x8000;

/// POSIX `c_lflag` bits ISIG 0x01, ICANON 0x02, ECHO 0x08, ECHOE
/// 0x10, ECHOK 0x20, ECHONL 0x40, NOFLSH 0x80, TOSTOP 0x100,
/// IEXTEN 0x8000 — all match Linux. Darwin uses different values
/// for some of these so we translate them explicitly.
#[cfg(target_os = "macos")]
const LINUX_LFLAG_ISIG: u32 = 0x0000_0001;
#[cfg(target_os = "macos")]
const LINUX_LFLAG_ICANON: u32 = 0x0000_0002;
#[cfg(target_os = "macos")]
const LINUX_LFLAG_ECHO: u32 = 0x0000_0008;
#[cfg(target_os = "macos")]
const LINUX_LFLAG_ECHOE: u32 = 0x0000_0010;
#[cfg(target_os = "macos")]
const LINUX_LFLAG_ECHOK: u32 = 0x0000_0020;
#[cfg(target_os = "macos")]
const LINUX_LFLAG_ECHONL: u32 = 0x0000_0040;
#[cfg(target_os = "macos")]
const LINUX_LFLAG_NOFLSH: u32 = 0x0000_0080;
#[cfg(target_os = "macos")]
const LINUX_LFLAG_TOSTOP: u32 = 0x0000_0100;
#[cfg(target_os = "macos")]
const LINUX_LFLAG_IEXTEN: u32 = 0x0000_8000;

// Darwin values from <sys/termios.h>.
#[cfg(target_os = "macos")]
const DARWIN_LFLAG_ECHOKE: carrick_portable::TcFlag = 0x0000_0001; // unused on linux side; ignore inbound
#[cfg(target_os = "macos")]
const DARWIN_LFLAG_ECHOE: carrick_portable::TcFlag = 0x0000_0002;
#[cfg(target_os = "macos")]
const DARWIN_LFLAG_ECHOK: carrick_portable::TcFlag = 0x0000_0004;
#[cfg(target_os = "macos")]
const DARWIN_LFLAG_ECHO: carrick_portable::TcFlag = 0x0000_0008;
#[cfg(target_os = "macos")]
const DARWIN_LFLAG_ECHONL: carrick_portable::TcFlag = 0x0000_0010;
#[cfg(target_os = "macos")]
const DARWIN_LFLAG_ECHOPRT: carrick_portable::TcFlag = 0x0000_0020;
#[cfg(target_os = "macos")]
const DARWIN_LFLAG_ECHOCTL: carrick_portable::TcFlag = 0x0000_0040;
#[cfg(target_os = "macos")]
const DARWIN_LFLAG_ISIG: carrick_portable::TcFlag = 0x0000_0080;
#[cfg(target_os = "macos")]
const DARWIN_LFLAG_ICANON: carrick_portable::TcFlag = 0x0000_0100;
#[cfg(target_os = "macos")]
const DARWIN_LFLAG_IEXTEN: carrick_portable::TcFlag = 0x0000_0400;
#[cfg(target_os = "macos")]
const DARWIN_LFLAG_NOFLSH: carrick_portable::TcFlag = 0x8000_0000;
#[cfg(target_os = "macos")]
const DARWIN_LFLAG_TOSTOP: carrick_portable::TcFlag = 0x0040_0000;

// VINTR/VQUIT/VERASE/etc indices differ between Linux and Darwin.
// Linux ordering (asm-generic/termbits.h):
//   0 VINTR, 1 VQUIT, 2 VERASE, 3 VKILL, 4 VEOF, 5 VTIME, 6 VMIN,
//   7 VSWTC, 8 VSTART, 9 VSTOP, 10 VSUSP, 11 VEOL, 12 VREPRINT,
//   13 VDISCARD, 14 VWERASE, 15 VLNEXT, 16 VEOL2.
// Darwin ordering (<sys/ttydefaults.h>):
//   0 VEOF, 1 VEOL, 2 VEOL2, 3 VERASE, 4 VWERASE, 5 VKILL,
//   6 VREPRINT, 7 (spare), 8 VINTR, 9 VQUIT, 10 VSUSP, 11 VDSUSP,
//   12 VSTART, 13 VSTOP, 14 VLNEXT, 15 VDISCARD, 16 VMIN, 17 VTIME,
//   18 VSTATUS.

/// Map "Linux VINTR-style index" -> "Darwin index". `None` means the
/// slot has no direct equivalent on Darwin (e.g. VSWTC) and we leave
/// the byte at 0.
#[cfg(target_os = "macos")]
const LINUX_TO_DARWIN_CC: [Option<usize>; 17] = [
    Some(8),  // 0 VINTR
    Some(9),  // 1 VQUIT
    Some(3),  // 2 VERASE
    Some(5),  // 3 VKILL
    Some(0),  // 4 VEOF
    Some(17), // 5 VTIME
    Some(16), // 6 VMIN
    None,     // 7 VSWTC (Linux-only)
    Some(12), // 8 VSTART
    Some(13), // 9 VSTOP
    Some(10), // 10 VSUSP
    Some(1),  // 11 VEOL
    Some(6),  // 12 VREPRINT
    Some(15), // 13 VDISCARD
    Some(4),  // 14 VWERASE
    Some(14), // 15 VLNEXT
    Some(2),  // 16 VEOL2
];

/// True when `fd` refers to a real macOS terminal.
pub fn host_isatty(fd: i32) -> bool {
    // SAFETY: libc::isatty takes a raw fd and returns 0/1; no
    // memory dereference. Safe to call from anywhere.
    unsafe { libc::isatty(fd) == 1 }
}

/// Pull the host's current termios via `tcgetattr` and translate to
/// the Linux ABI layout. Returns `None` if the fd isn't a TTY or the
/// libc call fails.
pub fn get_host_termios(fd: i32) -> Option<LinuxTermios> {
    if !host_isatty(fd) {
        return None;
    }
    // SAFETY: zero-initialised termios is the documented "uninitialised
    // input, kernel fills it" form for tcgetattr.
    unsafe {
        let mut host: libc::termios = core::mem::zeroed();
        if libc::tcgetattr(fd, &mut host) != 0 {
            return None;
        }
        Some(host_to_linux_termios(&host))
    }
}

/// Translate a host `libc::termios` into the guest Linux `LinuxTermios`.
/// On macOS the field VALUES/positions differ from Linux, so each flag group
/// is remapped by `darwin_to_linux_termios`.
#[cfg(target_os = "macos")]
fn host_to_linux_termios(d: &libc::termios) -> LinuxTermios {
    darwin_to_linux_termios(d)
}

/// Translate a host `libc::termios` into the guest Linux `LinuxTermios` for any
/// NON-macOS host (Linux + the BSDs). Each guest-Linux bit/`c_cc` index is filled
/// from the HOST's NATIVE `libc::` flag, so the value lands at the position the
/// guest expects regardless of where the host keeps it. On Linux every `libc::`
/// flag EQUALS the guest-Linux value, so this is identity-equivalent (the Linux
/// box is byte-for-byte unchanged); on FreeBSD/NetBSD `libc::ICRNL`, `libc::IXON`,
/// `libc::CS8`, `libc::ICANON`, the `libc::V*` indices, … are that host's native
/// positions, so the translation is faithful by construction. Anything outside
/// the well-known POSIX set is dropped (matching the documented policy).
#[cfg(not(target_os = "macos"))]
fn host_to_linux_termios(d: &libc::termios) -> LinuxTermios {
    use guest_linux_termios as g;
    let h = d;

    let mut c_iflag = 0u32;
    for (host_bit, linux_bit) in iflag_pairs(h) {
        if (h.c_iflag & host_bit) != 0 {
            c_iflag |= linux_bit;
        }
    }
    let mut c_oflag = 0u32;
    for (host_bit, linux_bit) in oflag_pairs(h) {
        if (h.c_oflag & host_bit) != 0 {
            c_oflag |= linux_bit;
        }
    }
    let mut c_cflag = host_csize_to_linux(h.c_cflag);
    for (host_bit, linux_bit) in cflag_pairs(h) {
        if (h.c_cflag & host_bit) != 0 {
            c_cflag |= linux_bit;
        }
    }
    let mut c_lflag = 0u32;
    for (host_bit, linux_bit) in lflag_pairs(h) {
        if (h.c_lflag & host_bit) != 0 {
            c_lflag |= linux_bit;
        }
    }

    // c_cc: copy each control char from its HOST `libc::V*` slot into the
    // guest-Linux slot. On Linux the indices coincide; on the BSDs they differ
    // (e.g. Darwin/BSD VEOF=0, Linux VEOF=4), so go index-by-index.
    let mut c_cc = [0u8; 19];
    for (linux_idx, host_idx) in g::CC_INDEX_PAIRS {
        if linux_idx < c_cc.len() && host_idx < h.c_cc.len() {
            c_cc[linux_idx] = h.c_cc[host_idx] as u8;
        }
    }

    // Baud rides in c_ispeed/c_ospeed; read via the POSIX accessors (the raw
    // fields differ in width/type across hosts).
    // SAFETY: `h` is a fully-initialised termios; cfget*speed only read it.
    let ispeed = unsafe { libc::cfgetispeed(h) } as u32;
    let ospeed = unsafe { libc::cfgetospeed(h) } as u32;
    LinuxTermios {
        c_iflag,
        c_oflag,
        c_cflag,
        c_lflag,
        c_line: 0,
        c_cc,
        c_ispeed: ispeed,
        c_ospeed: ospeed,
    }
}

/// Push a Linux termios down to the host fd via `tcsetattr`. Returns
/// `true` on success.
pub fn set_host_termios(fd: i32, linux: &LinuxTermios) -> bool {
    if !host_isatty(fd) {
        return false;
    }
    // SAFETY: zero-initialised termios then overwritten field-by-field
    // before being passed to tcsetattr.
    unsafe {
        let mut host: libc::termios = core::mem::zeroed();
        // Preserve any bits we don't translate by reading the current
        // state first; that way we don't blow away platform-specific bits.
        let _ = libc::tcgetattr(fd, &mut host);
        linux_to_host_termios(linux, &mut host);
        #[cfg(feature = "trace-io")]
        {
            let (li, lo, ll) = (linux.c_iflag, linux.c_oflag, linux.c_lflag);
            let (di, do_, dl) = (host.c_iflag, host.c_oflag, host.c_lflag);
            eprintln!(
                "[TERMDBG] fd={fd} linux iflag={li:#06x} oflag={lo:#06x} lflag={ll:#06x} -> host iflag={di:#06x} oflag={do_:#06x} lflag={dl:#06x}"
            );
        }
        libc::tcsetattr(fd, libc::TCSANOW, &host) == 0
    }
}

/// Translate a guest Linux `LinuxTermios` into the host `libc::termios` in
/// place. On macOS the flag groups are remapped to Darwin positions by
/// `linux_to_darwin_termios`.
#[cfg(target_os = "macos")]
fn linux_to_host_termios(l: &LinuxTermios, d: &mut libc::termios) {
    linux_to_darwin_termios(l, d);
}

/// Translate a guest Linux `LinuxTermios` into the host `libc::termios` for any
/// NON-macOS host (Linux + the BSDs). The inverse of the non-macOS
/// `host_to_linux_termios`: each guest-Linux bit/`c_cc` index is written to the
/// HOST's NATIVE `libc::` position. On Linux the positions coincide so this is
/// identity-equivalent (the Linux box is unchanged); on FreeBSD/NetBSD it lands
/// each bit at that host's native position, so a guest CS8/IXON/ICANON/VINTR
/// takes effect correctly. Host-specific bits the guest never sets are preserved
/// by clearing only the well-known POSIX mask before OR-ing the translated bits.
#[cfg(not(target_os = "macos"))]
fn linux_to_host_termios(l: &LinuxTermios, d: &mut libc::termios) {
    // Clear the well-known POSIX bits we translate, preserve everything else.
    let (i_mask, o_mask, c_mask, l_mask) = host_posix_masks(d);
    let mut iflag = d.c_iflag & !i_mask;
    for (host_bit, linux_bit) in iflag_pairs(d) {
        if (l.c_iflag & linux_bit) != 0 {
            iflag |= host_bit;
        }
    }
    let mut oflag = d.c_oflag & !o_mask;
    for (host_bit, linux_bit) in oflag_pairs(d) {
        if (l.c_oflag & linux_bit) != 0 {
            oflag |= host_bit;
        }
    }
    let mut cflag = d.c_cflag & !c_mask;
    cflag |= linux_csize_to_host(l.c_cflag);
    for (host_bit, linux_bit) in cflag_pairs(d) {
        if (l.c_cflag & linux_bit) != 0 {
            cflag |= host_bit;
        }
    }
    let mut lflag = d.c_lflag & !l_mask;
    for (host_bit, linux_bit) in lflag_pairs(d) {
        if (l.c_lflag & linux_bit) != 0 {
            lflag |= host_bit;
        }
    }

    d.c_iflag = iflag;
    d.c_oflag = oflag;
    d.c_cflag = cflag;
    d.c_lflag = lflag;

    for (linux_idx, host_idx) in guest_linux_termios::CC_INDEX_PAIRS {
        if host_idx < d.c_cc.len() && linux_idx < l.c_cc.len() {
            d.c_cc[host_idx] = l.c_cc[linux_idx] as libc::cc_t;
        }
    }

    carrick_portable::set_termios_speeds(d, l.c_ispeed, l.c_ospeed);
}

/// Guest-Linux termios ABI constants (asm-generic/termbits.h) — the canonical
/// values the guest uses, independent of the host. Used by the non-macOS
/// translation to pair each host `libc::` bit with the guest-Linux bit it maps
/// to. (On a Linux host these equal the corresponding `libc::` value, so the
/// translation collapses to identity; on the BSDs the host `libc::` side differs
/// and these stay fixed at the guest values.)
#[cfg(not(target_os = "macos"))]
mod guest_linux_termios {
    // c_iflag
    pub const IGNBRK: u32 = 0x0001;
    pub const BRKINT: u32 = 0x0002;
    pub const IGNPAR: u32 = 0x0004;
    pub const PARMRK: u32 = 0x0008;
    pub const INPCK: u32 = 0x0010;
    pub const ISTRIP: u32 = 0x0020;
    pub const INLCR: u32 = 0x0040;
    pub const IGNCR: u32 = 0x0080;
    pub const ICRNL: u32 = 0x0100;
    pub const IXON: u32 = 0x0400;
    pub const IXANY: u32 = 0x0800;
    pub const IXOFF: u32 = 0x1000;
    pub const IMAXBEL: u32 = 0x2000;
    /// `IUTF8` is Linux-only on the host side (`libc::IUTF8` exists only there),
    /// so the guest-Linux constant is referenced only on Linux. Gate it to avoid
    /// a dead-code warning on the BSD builds (clippy denies warnings).
    #[cfg(target_os = "linux")]
    pub const IUTF8: u32 = 0x4000;
    // c_oflag
    pub const OPOST: u32 = 0x0001;
    pub const ONLCR: u32 = 0x0004;
    pub const OCRNL: u32 = 0x0008;
    pub const ONOCR: u32 = 0x0010;
    pub const ONLRET: u32 = 0x0020;
    // c_cflag (CSIZE field handled separately)
    pub const CSTOPB: u32 = 0x0040;
    pub const CREAD: u32 = 0x0080;
    pub const PARENB: u32 = 0x0100;
    pub const PARODD: u32 = 0x0200;
    pub const HUPCL: u32 = 0x0400;
    pub const CLOCAL: u32 = 0x0800;
    pub const CSIZE: u32 = 0x0030;
    pub const CS6: u32 = 0x0010;
    pub const CS7: u32 = 0x0020;
    pub const CS8: u32 = 0x0030;
    // c_lflag
    pub const ISIG: u32 = 0x0001;
    pub const ICANON: u32 = 0x0002;
    pub const ECHO: u32 = 0x0008;
    pub const ECHOE: u32 = 0x0010;
    pub const ECHOK: u32 = 0x0020;
    pub const ECHONL: u32 = 0x0040;
    pub const NOFLSH: u32 = 0x0080;
    pub const TOSTOP: u32 = 0x0100;
    pub const ECHOCTL: u32 = 0x0200;
    pub const ECHOPRT: u32 = 0x0400;
    pub const ECHOKE: u32 = 0x0800;
    pub const IEXTEN: u32 = 0x8000;

    /// `(linux_cc_index, host_libc_cc_index)` pairs. On Linux the two are equal;
    /// on the BSDs the host index comes from `libc::V*`. The host indices are the
    /// `libc::V*` constants resolved at the call site; this table is just the
    /// guest-Linux ordering (asm-generic/termbits.h). The host side is filled in
    /// by `CC_INDEX_PAIRS` below using the host `libc::V*` values.
    pub const LINUX_VINTR: usize = 0;
    pub const LINUX_VQUIT: usize = 1;
    pub const LINUX_VERASE: usize = 2;
    pub const LINUX_VKILL: usize = 3;
    pub const LINUX_VEOF: usize = 4;
    pub const LINUX_VTIME: usize = 5;
    pub const LINUX_VMIN: usize = 6;
    pub const LINUX_VSTART: usize = 8;
    pub const LINUX_VSTOP: usize = 9;
    pub const LINUX_VSUSP: usize = 10;
    pub const LINUX_VEOL: usize = 11;
    pub const LINUX_VREPRINT: usize = 12;
    pub const LINUX_VDISCARD: usize = 13;
    pub const LINUX_VWERASE: usize = 14;
    pub const LINUX_VLNEXT: usize = 15;
    pub const LINUX_VEOL2: usize = 16;

    /// `(linux_index, host_index)` pairs, host index from the host `libc::V*`.
    /// On Linux `libc::VINTR == 0 == LINUX_VINTR`, etc., so every pair is the
    /// identity `(n, n)`; on the BSDs the host side differs.
    pub const CC_INDEX_PAIRS: [(usize, usize); 16] = [
        (LINUX_VINTR, libc::VINTR),
        (LINUX_VQUIT, libc::VQUIT),
        (LINUX_VERASE, libc::VERASE),
        (LINUX_VKILL, libc::VKILL),
        (LINUX_VEOF, libc::VEOF),
        (LINUX_VTIME, libc::VTIME),
        (LINUX_VMIN, libc::VMIN),
        (LINUX_VSTART, libc::VSTART),
        (LINUX_VSTOP, libc::VSTOP),
        (LINUX_VSUSP, libc::VSUSP),
        (LINUX_VEOL, libc::VEOL),
        (LINUX_VREPRINT, libc::VREPRINT),
        (LINUX_VDISCARD, libc::VDISCARD),
        (LINUX_VWERASE, libc::VWERASE),
        (LINUX_VLNEXT, libc::VLNEXT),
        (LINUX_VEOL2, libc::VEOL2),
    ];
}

/// `(host_libc_bit, guest_linux_bit)` pairs for c_iflag. The `_d` arg pins the
/// `libc::tcflag_t` width to the host's. Both sides are simple boolean bits
/// (CSIZE is handled separately), so the translation is a per-bit copy.
///
/// `IUTF8` exists in `libc` only on Linux (the BSDs have no such input-processing
/// bit), so it is included only there — a guest `IUTF8` bit simply has no host
/// equivalent on the BSDs and is dropped, matching the documented
/// "zero anything the host doesn't understand" policy.
#[cfg(not(target_os = "macos"))]
fn iflag_pairs(_d: &libc::termios) -> Vec<(libc::tcflag_t, u32)> {
    use guest_linux_termios as g;
    // `IUTF8` only exists in `libc` on Linux; on the BSDs there is no host bit to
    // pair, so the optional tail is empty there (a guest IUTF8 bit is dropped,
    // per the "zero anything the host doesn't understand" policy).
    #[cfg(target_os = "linux")]
    let optional: &[(libc::tcflag_t, u32)] = &[(libc::IUTF8, g::IUTF8)];
    #[cfg(not(target_os = "linux"))]
    let optional: &[(libc::tcflag_t, u32)] = &[];
    let mut pairs = vec![
        (libc::IGNBRK, g::IGNBRK),
        (libc::BRKINT, g::BRKINT),
        (libc::IGNPAR, g::IGNPAR),
        (libc::PARMRK, g::PARMRK),
        (libc::INPCK, g::INPCK),
        (libc::ISTRIP, g::ISTRIP),
        (libc::INLCR, g::INLCR),
        (libc::IGNCR, g::IGNCR),
        (libc::ICRNL, g::ICRNL),
        (libc::IXON, g::IXON),
        (libc::IXANY, g::IXANY),
        (libc::IXOFF, g::IXOFF),
        (libc::IMAXBEL, g::IMAXBEL),
    ];
    pairs.extend_from_slice(optional);
    pairs
}

/// `(host_libc_bit, guest_linux_bit)` pairs for c_oflag. ONLCR/OCRNL/ONOCR/ONLRET
/// are the post-processing bits the guest cares about; OPOST gates them.
#[cfg(not(target_os = "macos"))]
fn oflag_pairs(_d: &libc::termios) -> [(libc::tcflag_t, u32); 5] {
    use guest_linux_termios as g;
    [
        (libc::OPOST, g::OPOST),
        (libc::ONLCR, g::ONLCR),
        (libc::OCRNL, g::OCRNL),
        (libc::ONOCR, g::ONOCR),
        (libc::ONLRET, g::ONLRET),
    ]
}

/// `(host_libc_bit, guest_linux_bit)` pairs for c_cflag, EXCLUDING the CSIZE
/// field (translated by `host_csize_to_linux`/`linux_csize_to_host`).
#[cfg(not(target_os = "macos"))]
fn cflag_pairs(_d: &libc::termios) -> [(libc::tcflag_t, u32); 6] {
    use guest_linux_termios as g;
    [
        (libc::CSTOPB, g::CSTOPB),
        (libc::CREAD, g::CREAD),
        (libc::PARENB, g::PARENB),
        (libc::PARODD, g::PARODD),
        (libc::HUPCL, g::HUPCL),
        (libc::CLOCAL, g::CLOCAL),
    ]
}

/// `(host_libc_bit, guest_linux_bit)` pairs for c_lflag.
#[cfg(not(target_os = "macos"))]
fn lflag_pairs(_d: &libc::termios) -> [(libc::tcflag_t, u32); 12] {
    use guest_linux_termios as g;
    [
        (libc::ISIG, g::ISIG),
        (libc::ICANON, g::ICANON),
        (libc::ECHO, g::ECHO),
        (libc::ECHOE, g::ECHOE),
        (libc::ECHOK, g::ECHOK),
        (libc::ECHONL, g::ECHONL),
        (libc::NOFLSH, g::NOFLSH),
        (libc::TOSTOP, g::TOSTOP),
        (libc::ECHOCTL, g::ECHOCTL),
        (libc::ECHOPRT, g::ECHOPRT),
        (libc::ECHOKE, g::ECHOKE),
        (libc::IEXTEN, g::IEXTEN),
    ]
}

/// Translate the host's CSIZE field (a 2-bit field whose VALUE differs between
/// hosts) to the guest-Linux CSIZE field. CS5 is 0 on every host.
#[cfg(not(target_os = "macos"))]
fn host_csize_to_linux(host_cflag: libc::tcflag_t) -> u32 {
    use guest_linux_termios as g;
    match host_cflag & libc::CSIZE {
        x if x == libc::CS8 => g::CS8,
        x if x == libc::CS7 => g::CS7,
        x if x == libc::CS6 => g::CS6,
        _ => 0, // CS5
    }
}

/// Inverse of `host_csize_to_linux`: guest-Linux CSIZE field -> host CSIZE field.
#[cfg(not(target_os = "macos"))]
fn linux_csize_to_host(linux_cflag: u32) -> libc::tcflag_t {
    use guest_linux_termios as g;
    match linux_cflag & g::CSIZE {
        x if x == g::CS8 => libc::CS8,
        x if x == g::CS7 => libc::CS7,
        x if x == g::CS6 => libc::CS6,
        _ => 0, // CS5
    }
}

/// The host's well-known POSIX bit masks per flag word — the union of every bit
/// the translation owns, so `linux_to_host_termios` can clear exactly those and
/// preserve any host-specific bits the guest never names.
#[cfg(not(target_os = "macos"))]
fn host_posix_masks(
    d: &libc::termios,
) -> (
    libc::tcflag_t,
    libc::tcflag_t,
    libc::tcflag_t,
    libc::tcflag_t,
) {
    let i = iflag_pairs(d).iter().fold(0, |m, (b, _)| m | *b);
    let o = oflag_pairs(d).iter().fold(0, |m, (b, _)| m | *b);
    let c = cflag_pairs(d).iter().fold(libc::CSIZE, |m, (b, _)| m | *b);
    let l = lflag_pairs(d).iter().fold(0, |m, (b, _)| m | *b);
    (i, o, c, l)
}

/// Read the host fd's window size. Returns `None` if the fd isn't a
/// TTY or the ioctl fails.
pub fn get_host_winsize(fd: i32) -> Option<LinuxWinsize> {
    if !host_isatty(fd) {
        return None;
    }
    // SAFETY: libc::winsize layout matches the kernel's; we pass a
    // valid pointer to stack-allocated storage.
    unsafe {
        let mut ws: libc::winsize = core::mem::zeroed();
        if libc::ioctl(fd, libc::TIOCGWINSZ, &mut ws) != 0 {
            return None;
        }
        Some(LinuxWinsize {
            ws_row: ws.ws_row,
            ws_col: ws.ws_col,
            ws_xpixel: ws.ws_xpixel,
            ws_ypixel: ws.ws_ypixel,
        })
    }
}

#[cfg(target_os = "macos")]
fn darwin_to_linux_termios(d: &libc::termios) -> LinuxTermios {
    let mut iflag = (d.c_iflag as u32) & COMMON_IFLAG_MASK;
    if d.c_iflag & DARWIN_IXON != 0 {
        iflag |= LINUX_IXON;
    }
    if d.c_iflag & DARWIN_IXOFF != 0 {
        iflag |= LINUX_IXOFF;
    }

    let mut oflag = (d.c_oflag as u32) & COMMON_OFLAG_MASK;
    if d.c_oflag & DARWIN_ONLCR != 0 {
        oflag |= LINUX_ONLCR;
    }
    if d.c_oflag & DARWIN_OCRNL != 0 {
        oflag |= LINUX_OCRNL;
    }

    // CSIZE is a 2-bit FIELD; match the whole field (CS5==0 on both).
    let mut cflag = match d.c_cflag & DARWIN_CSIZE {
        x if x == DARWIN_CS8 => LINUX_CS8,
        x if x == DARWIN_CS7 => LINUX_CS7,
        x if x == DARWIN_CS6 => LINUX_CS6,
        _ => 0,
    };
    if d.c_cflag & DARWIN_CSTOPB != 0 {
        cflag |= LINUX_CSTOPB;
    }
    if d.c_cflag & DARWIN_CREAD != 0 {
        cflag |= LINUX_CREAD;
    }
    if d.c_cflag & DARWIN_PARENB != 0 {
        cflag |= LINUX_PARENB;
    }
    if d.c_cflag & DARWIN_PARODD != 0 {
        cflag |= LINUX_PARODD;
    }
    if d.c_cflag & DARWIN_HUPCL != 0 {
        cflag |= LINUX_HUPCL;
    }
    if d.c_cflag & DARWIN_CLOCAL != 0 {
        cflag |= LINUX_CLOCAL;
    }

    let mut lflag = 0u32;
    let dl = d.c_lflag;
    if dl & DARWIN_LFLAG_ISIG != 0 {
        lflag |= LINUX_LFLAG_ISIG;
    }
    if dl & DARWIN_LFLAG_ICANON != 0 {
        lflag |= LINUX_LFLAG_ICANON;
    }
    if dl & DARWIN_LFLAG_ECHO != 0 {
        lflag |= LINUX_LFLAG_ECHO;
    }
    if dl & DARWIN_LFLAG_ECHOE != 0 {
        lflag |= LINUX_LFLAG_ECHOE;
    }
    if dl & DARWIN_LFLAG_ECHOK != 0 {
        lflag |= LINUX_LFLAG_ECHOK;
    }
    if dl & DARWIN_LFLAG_ECHONL != 0 {
        lflag |= LINUX_LFLAG_ECHONL;
    }
    if dl & DARWIN_LFLAG_NOFLSH != 0 {
        lflag |= LINUX_LFLAG_NOFLSH;
    }
    if dl & DARWIN_LFLAG_TOSTOP != 0 {
        lflag |= LINUX_LFLAG_TOSTOP;
    }
    if dl & DARWIN_LFLAG_IEXTEN != 0 {
        lflag |= LINUX_LFLAG_IEXTEN;
    }
    // ECHOKE/ECHOPRT/ECHOCTL are non-POSIX Darwin extras; drop.
    let _ = (
        DARWIN_LFLAG_ECHOKE,
        DARWIN_LFLAG_ECHOPRT,
        DARWIN_LFLAG_ECHOCTL,
    );

    let mut c_cc = [0u8; 19];
    for (linux_idx, darwin_idx) in LINUX_TO_DARWIN_CC.iter().enumerate() {
        if let Some(di) = darwin_idx
            && *di < d.c_cc.len()
        {
            c_cc[linux_idx] = d.c_cc[*di];
        }
    }

    LinuxTermios {
        c_iflag: iflag,
        c_oflag: oflag,
        c_cflag: cflag,
        c_lflag: lflag,
        c_line: 0,
        c_cc,
        c_ispeed: d.c_ispeed as u32,
        c_ospeed: d.c_ospeed as u32,
    }
}

#[cfg(target_os = "macos")]
fn linux_to_darwin_termios(l: &LinuxTermios, d: &mut libc::termios) {
    // Preserve any host-specific bits outside the masks we translate.
    let preserved_iflag =
        d.c_iflag & !((COMMON_IFLAG_MASK as carrick_portable::TcFlag) | DARWIN_IXON | DARWIN_IXOFF);
    let preserved_oflag = d.c_oflag
        & !((COMMON_OFLAG_MASK as carrick_portable::TcFlag) | DARWIN_ONLCR | DARWIN_OCRNL);
    let preserved_cflag = d.c_cflag
        & !(DARWIN_CSIZE
            | DARWIN_CSTOPB
            | DARWIN_CREAD
            | DARWIN_PARENB
            | DARWIN_PARODD
            | DARWIN_HUPCL
            | DARWIN_CLOCAL);
    let preserved_lflag = d.c_lflag
        & !(DARWIN_LFLAG_ISIG
            | DARWIN_LFLAG_ICANON
            | DARWIN_LFLAG_ECHO
            | DARWIN_LFLAG_ECHOE
            | DARWIN_LFLAG_ECHOK
            | DARWIN_LFLAG_ECHONL
            | DARWIN_LFLAG_NOFLSH
            | DARWIN_LFLAG_TOSTOP
            | DARWIN_LFLAG_IEXTEN);

    let mut iflag = preserved_iflag
        | (l.c_iflag as carrick_portable::TcFlag & COMMON_IFLAG_MASK as carrick_portable::TcFlag);
    if l.c_iflag & LINUX_IXON != 0 {
        iflag |= DARWIN_IXON;
    }
    if l.c_iflag & LINUX_IXOFF != 0 {
        iflag |= DARWIN_IXOFF;
    }

    let mut oflag = preserved_oflag
        | (l.c_oflag as carrick_portable::TcFlag & COMMON_OFLAG_MASK as carrick_portable::TcFlag);
    if l.c_oflag & LINUX_ONLCR != 0 {
        oflag |= DARWIN_ONLCR;
    }
    if l.c_oflag & LINUX_OCRNL != 0 {
        oflag |= DARWIN_OCRNL;
    }

    let mut cflag = preserved_cflag;
    cflag |= match l.c_cflag & LINUX_CSIZE {
        x if x == LINUX_CS8 => DARWIN_CS8,
        x if x == LINUX_CS7 => DARWIN_CS7,
        x if x == LINUX_CS6 => DARWIN_CS6,
        _ => 0,
    };
    if l.c_cflag & LINUX_CSTOPB != 0 {
        cflag |= DARWIN_CSTOPB;
    }
    if l.c_cflag & LINUX_CREAD != 0 {
        cflag |= DARWIN_CREAD;
    }
    if l.c_cflag & LINUX_PARENB != 0 {
        cflag |= DARWIN_PARENB;
    }
    if l.c_cflag & LINUX_PARODD != 0 {
        cflag |= DARWIN_PARODD;
    }
    if l.c_cflag & LINUX_HUPCL != 0 {
        cflag |= DARWIN_HUPCL;
    }
    if l.c_cflag & LINUX_CLOCAL != 0 {
        cflag |= DARWIN_CLOCAL;
    }

    let mut lflag = preserved_lflag;
    if l.c_lflag & LINUX_LFLAG_ISIG != 0 {
        lflag |= DARWIN_LFLAG_ISIG;
    }
    if l.c_lflag & LINUX_LFLAG_ICANON != 0 {
        lflag |= DARWIN_LFLAG_ICANON;
    }
    if l.c_lflag & LINUX_LFLAG_ECHO != 0 {
        lflag |= DARWIN_LFLAG_ECHO;
    }
    if l.c_lflag & LINUX_LFLAG_ECHOE != 0 {
        lflag |= DARWIN_LFLAG_ECHOE;
    }
    if l.c_lflag & LINUX_LFLAG_ECHOK != 0 {
        lflag |= DARWIN_LFLAG_ECHOK;
    }
    if l.c_lflag & LINUX_LFLAG_ECHONL != 0 {
        lflag |= DARWIN_LFLAG_ECHONL;
    }
    if l.c_lflag & LINUX_LFLAG_NOFLSH != 0 {
        lflag |= DARWIN_LFLAG_NOFLSH;
    }
    if l.c_lflag & LINUX_LFLAG_TOSTOP != 0 {
        lflag |= DARWIN_LFLAG_TOSTOP;
    }
    if l.c_lflag & LINUX_LFLAG_IEXTEN != 0 {
        lflag |= DARWIN_LFLAG_IEXTEN;
    }

    d.c_iflag = iflag as libc::tcflag_t;
    d.c_oflag = oflag as libc::tcflag_t;
    d.c_cflag = cflag as libc::tcflag_t;
    d.c_lflag = lflag as libc::tcflag_t;

    for (linux_idx, darwin_idx) in LINUX_TO_DARWIN_CC.iter().enumerate() {
        if let Some(di) = darwin_idx
            && *di < d.c_cc.len()
            && linux_idx < l.c_cc.len()
        {
            d.c_cc[*di] = l.c_cc[linux_idx];
        }
    }

    carrick_portable::set_termios_speeds(d, l.c_ispeed, l.c_ospeed);
}

/// Per-fd snapshot of termios captured before the guest (or `make_raw`)
/// mutates a terminal.  The key is the host fd number; the value is the
/// termios at the moment the fd was first recorded.  `restore_stdin_termios`
/// drains this map and restores every fd it contains.
///
/// `libc::termios` does not implement `Send` on all platforms because it can
/// contain pointer-width fields, but in practice it is just a bag of integers
/// and we never move the underlying fd.  The `Mutex` provides the required
/// exclusive-access guarantee.
static SAVED_TERMIOS: Mutex<Option<HashMap<i32, libc::termios>>> = Mutex::new(None);

/// Snapshot `fd`'s current termios into `SAVED_TERMIOS` if it is a TTY and
/// not already recorded.  Returns `true` if a snapshot was taken or already
/// existed, `false` if the fd is not a TTY or `tcgetattr` failed.
///
/// This is "first write wins": calling it again after the terminal has been
/// put into raw mode does **not** overwrite the original cooked snapshot.
fn snapshot_fd(fd: i32) -> bool {
    if !host_isatty(fd) {
        return false;
    }
    // SAFETY: zero-initialised termios, then filled by tcgetattr.
    let mut t: libc::termios = unsafe { core::mem::zeroed() };
    if unsafe { libc::tcgetattr(fd, &mut t) } != 0 {
        return false;
    }
    let mut guard = SAVED_TERMIOS.lock();
    let map = guard.get_or_insert_with(HashMap::new);
    map.entry(fd).or_insert(t);
    true
}

/// Capture the current host stdin (fd 0) termios so it can be restored on
/// shutdown. Idempotent; subsequent calls for fd 0 are no-ops. Must be called
/// *before* the guest has a chance to invoke `tcsetattr` against us.
pub fn arm_stdin_restore() {
    snapshot_fd(0);
}

/// Mark that `fd`'s termios has been (or is about to be) mutated.  Snapshots
/// the *current* (pre-mutation) termios so `restore_stdin_termios` can undo
/// the change.  For fd 0 this preserves the same "arm-then-mark" semantics as
/// before; for other fds it provides per-fd restoration used by `make_raw`.
fn mark_dirty(fd: i32) {
    // Snapshot first (no-op if already recorded); the caller must invoke this
    // before applying any mutation so the original state is preserved.
    snapshot_fd(fd);
}

/// Restore every previously-captured termios snapshot and clear the store.
/// Safe to call multiple times; subsequent calls after the store is empty are
/// cheap no-ops.
pub fn restore_stdin_termios() {
    let snapshots = {
        let mut guard = SAVED_TERMIOS.lock();
        guard.take()
    };
    if let Some(map) = snapshots {
        for (fd, saved) in map {
            // SAFETY: `saved` is a fully-initialised termios captured via
            // tcgetattr. tcsetattr on a valid fd is well-defined.
            unsafe {
                libc::tcsetattr(fd, libc::TCSANOW, &saved);
            }
        }
    }
}

/// RAII guard returned from `install_termios_restore_guard`. When it
/// drops it runs `restore_stdin_termios`. The runtime stashes one of
/// these on the stack for the duration of the syscall loop.
pub struct TermiosRestoreGuard {
    _private: (),
}

impl TermiosRestoreGuard {
    pub fn new() -> Self {
        arm_stdin_restore();
        Self { _private: () }
    }
}

impl Default for TermiosRestoreGuard {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for TermiosRestoreGuard {
    fn drop(&mut self) {
        restore_stdin_termios();
    }
}

/// Public wrapper that both pushes the new termios to the host and
/// records the dirty bit so the restore guard knows it has work.
pub fn set_host_termios_tracking(fd: i32, linux: &LinuxTermios) -> bool {
    // Snapshot before mutation so restore_stdin_termios can undo it.
    mark_dirty(fd);
    set_host_termios(fd, linux)
}

/// Return the foreground process-group ID of the terminal `fd`, or `None` if
/// `fd` is not a real tty or the call fails.  On failure the raw `errno` from
/// `tcgetpgrp(3)` is returned as the `Err` variant so callers can translate it.
///
/// This is the get-half used by the stdio TIOCGPGRP passthrough.
pub fn host_tty_tcgetpgrp(fd: i32) -> Result<i32, i32> {
    if !host_isatty(fd) {
        return Err(carrick_portable::errno());
    }
    // SAFETY: fd has been confirmed to be a tty; tcgetpgrp returns a pid_t
    // (i32 on macOS) or -1 on error.
    let pgrp = unsafe { libc::tcgetpgrp(fd) };
    if pgrp < 0 {
        Err(carrick_portable::errno())
    } else {
        Ok(pgrp)
    }
}

/// Return the session ID of the terminal `fd`, or the raw host errno on
/// failure. This backs stdio `TIOCGSID` for interactive `-t` pty runs.
pub fn host_tty_tcgetsid(fd: i32) -> Result<i32, i32> {
    if !host_isatty(fd) {
        return Err(carrick_portable::errno());
    }
    // SAFETY: fd has been confirmed to be a tty; tcgetsid returns a pid_t
    // (i32 on macOS) or -1 on error.
    let sid = unsafe { libc::tcgetsid(fd) };
    if sid < 0 {
        Err(carrick_portable::errno())
    } else {
        Ok(sid)
    }
}

/// Run `f` with host SIGTTOU blocked on the calling thread when `block` is true
/// (otherwise a plain passthrough), restoring the previous mask afterward.
///
/// carrick runs the guest and its job-control children as real macOS processes
/// on a real host pty, so the host kernel's tty layer is live. A tty *control*
/// op (`tcsetpgrp`/`tcsetattr`) issued from a background process group raises
/// SIGTTOU regardless of TOSTOP, and would STOP the real carrick process. On
/// Linux the same op completes silently because a job-control shell installs
/// `SIG_IGN` for SIGTTOU — a disposition carrick only records in its *emulated*
/// table, so the host process is unprotected. Blocking host SIGTTOU around the
/// passthrough reproduces the POSIX "ignored/blocked SIGTTOU ⇒ the call just
/// succeeds" rule. Callers gate `block` on the guest's SIGTTOU disposition so a
/// genuinely-default background caller still stops (matching Linux). Mirrors the
/// guard the pty relay already uses for its own TIOCSWINSZ writes.
pub fn with_sigttou_blocked<R>(block: bool, f: impl FnOnce() -> R) -> R {
    if !block {
        return f();
    }
    // SAFETY: standard sigset_t manipulation + pthread_sigmask on the current
    // thread; the closure runs between block and restore.
    unsafe {
        let mut set: libc::sigset_t = core::mem::zeroed();
        let mut old: libc::sigset_t = core::mem::zeroed();
        libc::sigemptyset(&mut set);
        libc::sigaddset(&mut set, libc::SIGTTOU);
        let masked = libc::pthread_sigmask(libc::SIG_BLOCK, &set, &mut old) == 0;
        let r = f();
        if masked {
            libc::pthread_sigmask(libc::SIG_SETMASK, &old, core::ptr::null_mut());
        }
        r
    }
}

/// Set the foreground process-group of terminal `fd` to `pgrp`.  Returns `Ok(())`
/// on success or `Err(errno)` on failure (raw macOS errno, not translated).
///
/// This is the set-half used by the stdio TIOCSPGRP passthrough.
pub fn host_tty_tcsetpgrp(fd: i32, pgrp: i32) -> Result<(), i32> {
    // SAFETY: fd is a raw file descriptor; pgrp is a plain integer.
    // tcsetpgrp validates both; we propagate any error.
    let r = unsafe { libc::tcsetpgrp(fd, pgrp) };
    if r < 0 {
        Err(carrick_portable::errno())
    } else {
        Ok(())
    }
}

/// Drain `fd`'s output queue (block until all written output is transmitted).
/// Maps the Linux `tcdrain`/`TCSBRK(arg!=0)` semantics onto Darwin `tcdrain(2)`.
/// Returns `Ok(())` or `Err(macos_errno)`.
pub fn host_tty_tcdrain(fd: i32) -> Result<(), i32> {
    // SAFETY: fd is a raw descriptor; tcdrain validates it (ENOTTY for non-tty).
    let r = unsafe { libc::tcdrain(fd) };
    if r < 0 {
        Err(carrick_portable::errno())
    } else {
        Ok(())
    }
}

/// Send a break (stream of zero bits) on `fd`. Maps Linux `tcsendbreak`/`TCSBRK`/
/// `TCSBRKP` onto Darwin `tcsendbreak(2)`. `duration` is passed through; Darwin
/// (like Linux) treats the exact non-zero value loosely. Returns `Ok(())` or
/// `Err(macos_errno)`.
pub fn host_tty_tcsendbreak(fd: i32, duration: i32) -> Result<(), i32> {
    // SAFETY: fd is a raw descriptor; tcsendbreak validates it.
    let r = unsafe { libc::tcsendbreak(fd, duration) };
    if r < 0 {
        Err(carrick_portable::errno())
    } else {
        Ok(())
    }
}

/// Discard buffered tty data for `fd`. `linux_queue` is the *Linux* TCFLSH
/// selector (TCIFLUSH=0, TCOFLUSH=1, TCIOFLUSH=2) which is translated to the
/// corresponding Darwin selector (Darwin uses 1/2/3) before calling
/// `tcflush(2)`. An unknown selector returns `Err(EINVAL)` to mirror Linux,
/// which rejects out-of-range queue values in the TCFLSH path.
pub fn host_tty_tcflush(fd: i32, linux_queue: i64) -> Result<(), i32> {
    // Linux value → Darwin value. Darwin's selectors are Linux+1.
    let darwin_queue = match linux_queue {
        0 => libc::TCIFLUSH,  // Linux TCIFLUSH (0)  → Darwin 1
        1 => libc::TCOFLUSH,  // Linux TCOFLUSH (1)  → Darwin 2
        2 => libc::TCIOFLUSH, // Linux TCIOFLUSH (2) → Darwin 3
        _ => return Err(libc::EINVAL),
    };
    // SAFETY: fd is a raw descriptor; darwin_queue is a validated selector.
    let r = unsafe { libc::tcflush(fd, darwin_queue) };
    if r < 0 {
        Err(carrick_portable::errno())
    } else {
        Ok(())
    }
}

/// Suspend/resume tty input or output for `fd`. `linux_action` is the *Linux*
/// TCXONC action (TCOOFF=0, TCOON=1, TCIOFF=2, TCION=3) translated to the
/// Darwin action (Darwin uses 1/2/3/4) before calling `tcflow(2)`. An unknown
/// action returns `Err(EINVAL)` to mirror Linux's TCXONC validation.
pub fn host_tty_tcflow(fd: i32, linux_action: i64) -> Result<(), i32> {
    let darwin_action = match linux_action {
        0 => libc::TCOOFF, // Linux TCOOFF (0) → Darwin 1
        1 => libc::TCOON,  // Linux TCOON  (1) → Darwin 2
        2 => libc::TCIOFF, // Linux TCIOFF (2) → Darwin 3
        3 => libc::TCION,  // Linux TCION  (3) → Darwin 4
        _ => return Err(libc::EINVAL),
    };
    // SAFETY: fd is a raw descriptor; darwin_action is a validated selector.
    let r = unsafe { libc::tcflow(fd, darwin_action) };
    if r < 0 {
        Err(carrick_portable::errno())
    } else {
        Ok(())
    }
}

/// Put `fd` into raw mode (cfmakeraw semantics) after recording its current
/// termios for restoration via the existing dirty-tracking guard.  Errors if
/// `fd` is not a tty.
///
/// A later call to `restore_stdin_termios()` (e.g. from `TermiosRestoreGuard`
/// on shutdown) will put the terminal back to its original cooked state.
pub fn make_raw(fd: i32) -> std::io::Result<()> {
    // SAFETY: fd is validated by tcgetattr; termios is a valid out-param.
    let mut t: libc::termios = unsafe { std::mem::zeroed() };
    if unsafe { libc::tcgetattr(fd, &mut t) } != 0 {
        return Err(std::io::Error::last_os_error());
    }
    // Snapshot the original (cooked) state BEFORE applying cfmakeraw so that
    // restore_stdin_termios has the pre-raw termios to restore.
    mark_dirty(fd);
    // SAFETY: cfmakeraw mutates termios in place; the struct is valid.
    unsafe { libc::cfmakeraw(&mut t) };
    if unsafe { libc::tcsetattr(fd, libc::TCSANOW, &t) } != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn isatty_for_pipe_is_false() {
        // Create a pipe; neither end is a TTY.
        let mut fds = [0i32; 2];
        // SAFETY: standard pipe(2) call.
        let rc = unsafe { libc::pipe(fds.as_mut_ptr()) };
        assert_eq!(rc, 0);
        assert!(!host_isatty(fds[0]));
        assert!(!host_isatty(fds[1]));
        // SAFETY: closing fds we just opened.
        unsafe {
            libc::close(fds[0]);
            libc::close(fds[1]);
        }
    }

    #[test]
    fn get_host_termios_returns_none_for_non_tty() {
        let mut fds = [0i32; 2];
        // SAFETY: standard pipe(2).
        let rc = unsafe { libc::pipe(fds.as_mut_ptr()) };
        assert_eq!(rc, 0);
        assert!(get_host_termios(fds[0]).is_none());
        assert!(get_host_winsize(fds[0]).is_none());
        // SAFETY: closing pipe fds we just opened.
        unsafe {
            libc::close(fds[0]);
            libc::close(fds[1]);
        }
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn cc_index_table_is_within_darwin_bounds() {
        // libc::NCCS on Darwin is 20.
        for entry in LINUX_TO_DARWIN_CC.iter().flatten() {
            assert!(*entry < 20, "Darwin VINTR index {entry} out of bounds");
        }
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn round_trip_lflag_canonical_bits() {
        // Synthesize a Darwin termios with ICANON+ECHO+ISIG set,
        // translate to Linux, translate back, and verify the well-known
        // bits survive the trip.
        // SAFETY: zero-initialised termios.
        let mut d: libc::termios = unsafe { core::mem::zeroed() };
        d.c_lflag = (DARWIN_LFLAG_ICANON | DARWIN_LFLAG_ECHO | DARWIN_LFLAG_ISIG) as libc::tcflag_t;
        let l = darwin_to_linux_termios(&d);
        assert!(l.c_lflag & LINUX_LFLAG_ICANON != 0);
        assert!(l.c_lflag & LINUX_LFLAG_ECHO != 0);
        assert!(l.c_lflag & LINUX_LFLAG_ISIG != 0);

        // SAFETY: zero-initialised target termios.
        let mut d2: libc::termios = unsafe { core::mem::zeroed() };
        linux_to_darwin_termios(&l, &mut d2);
        assert!(d2.c_lflag as carrick_portable::TcFlag & DARWIN_LFLAG_ICANON != 0);
        assert!(d2.c_lflag as carrick_portable::TcFlag & DARWIN_LFLAG_ECHO != 0);
        assert!(d2.c_lflag as carrick_portable::TcFlag & DARWIN_LFLAG_ISIG != 0);
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn cc_table_round_trip_vintr() {
        // Plant VINTR (Linux idx 0) -> Darwin idx 8 -> Linux idx 0.
        let mut l = LinuxTermios::default_cooked();
        l.c_cc[0] = 0x42;
        // SAFETY: zero-initialised termios.
        let mut d: libc::termios = unsafe { core::mem::zeroed() };
        linux_to_darwin_termios(&l, &mut d);
        assert_eq!(d.c_cc[8], 0x42);
        let l2 = darwin_to_linux_termios(&d);
        assert_eq!(l2.c_cc[0], 0x42);
    }

    static TTY_TEST_LOCK: Mutex<()> = Mutex::new(());

    // ---- helpers for make_raw tests ----

    #[cfg(target_os = "macos")]
    fn open_test_pty_for_raw() -> (i32, i32) {
        let m = unsafe { libc::posix_openpt(libc::O_RDWR | libc::O_NOCTTY) };
        assert!(m >= 0, "posix_openpt failed");
        unsafe {
            libc::grantpt(m);
            libc::unlockpt(m);
        }
        let name = unsafe { std::ffi::CStr::from_ptr(libc::ptsname(m)) }.to_owned();
        let s = unsafe { libc::open(name.as_ptr(), libc::O_RDWR | libc::O_NOCTTY) };
        assert!(s >= 0, "open slave pty failed");
        (m, s)
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn make_raw_clears_icanon_and_echo() {
        let _guard = TTY_TEST_LOCK.lock();
        let (master, slave) = open_test_pty_for_raw();
        let before = unsafe {
            let mut t: libc::termios = std::mem::zeroed();
            libc::tcgetattr(slave, &mut t);
            t
        };
        assert!(
            before.c_lflag as carrick_portable::TcFlag & (DARWIN_LFLAG_ICANON | DARWIN_LFLAG_ECHO)
                != 0,
            "slave starts cooked (ICANON|ECHO must be set)"
        );
        make_raw(slave).unwrap();
        let raw = unsafe {
            let mut t: libc::termios = std::mem::zeroed();
            libc::tcgetattr(slave, &mut t);
            t
        };
        assert_eq!(
            raw.c_lflag as carrick_portable::TcFlag & (DARWIN_LFLAG_ICANON | DARWIN_LFLAG_ECHO),
            0,
            "raw clears ICANON|ECHO"
        );
        unsafe {
            libc::close(master);
            libc::close(slave);
        }
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn make_raw_snapshot_survives_restore() {
        let _guard = TTY_TEST_LOCK.lock();
        // Open a fresh pty slave so we don't interfere with fd-0 restore state.
        let (master, slave) = open_test_pty_for_raw();

        // Capture original cooked state.
        let cooked = unsafe {
            let mut t: libc::termios = std::mem::zeroed();
            assert_eq!(libc::tcgetattr(slave, &mut t), 0);
            t
        };

        // make_raw should snapshot the cooked state, then apply raw mode.
        make_raw(slave).unwrap();

        // Verify raw is active.
        let raw = unsafe {
            let mut t: libc::termios = std::mem::zeroed();
            libc::tcgetattr(slave, &mut t);
            t
        };
        assert_eq!(
            raw.c_lflag as carrick_portable::TcFlag & DARWIN_LFLAG_ICANON,
            0,
            "raw clears ICANON"
        );

        // Now restore and verify it goes back to cooked.
        restore_stdin_termios();

        let restored = unsafe {
            let mut t: libc::termios = std::mem::zeroed();
            assert_eq!(libc::tcgetattr(slave, &mut t), 0);
            t
        };
        assert_eq!(
            restored.c_lflag as carrick_portable::TcFlag & DARWIN_LFLAG_ICANON,
            cooked.c_lflag as carrick_portable::TcFlag & DARWIN_LFLAG_ICANON,
            "ICANON is restored to original value"
        );

        unsafe {
            libc::close(master);
            libc::close(slave);
        }
    }

    #[test]
    fn make_raw_non_tty_returns_error() {
        let mut fds = [0i32; 2];
        let rc = unsafe { libc::pipe(fds.as_mut_ptr()) };
        assert_eq!(rc, 0);
        let result = make_raw(fds[0]);
        assert!(result.is_err(), "make_raw on a pipe should return Err");
        unsafe {
            libc::close(fds[0]);
            libc::close(fds[1]);
        }
    }

    fn sigttou_blocked_now() -> bool {
        // SAFETY: query-only pthread_sigmask with a null `set`.
        unsafe {
            let mut cur: libc::sigset_t = std::mem::zeroed();
            libc::pthread_sigmask(libc::SIG_BLOCK, std::ptr::null(), &mut cur);
            libc::sigismember(&cur, libc::SIGTTOU) == 1
        }
    }

    #[test]
    fn with_sigttou_blocked_masks_during_closure_and_restores() {
        let _guard = TTY_TEST_LOCK.lock();
        // Start from a known state: SIGTTOU unblocked.
        // SAFETY: standard sigset/pthread_sigmask use.
        unsafe {
            let mut set: libc::sigset_t = std::mem::zeroed();
            libc::sigemptyset(&mut set);
            libc::sigaddset(&mut set, libc::SIGTTOU);
            libc::pthread_sigmask(libc::SIG_UNBLOCK, &set, std::ptr::null_mut());
        }
        assert!(!sigttou_blocked_now(), "precondition: SIGTTOU unblocked");

        let inside = with_sigttou_blocked(true, sigttou_blocked_now);
        assert!(inside, "SIGTTOU must be blocked inside the closure");
        assert!(
            !sigttou_blocked_now(),
            "SIGTTOU must be restored (unblocked) after the closure"
        );

        // block = false is a transparent passthrough that touches no mask.
        let passthrough = with_sigttou_blocked(false, sigttou_blocked_now);
        assert!(!passthrough, "block=false must not change the mask");
        assert_eq!(with_sigttou_blocked(false, || 7), 7, "returns the value");
    }
}
