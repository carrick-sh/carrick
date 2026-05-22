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
use std::sync::Mutex;

use crate::linux_abi::{LinuxTermios, LinuxWinsize};

/// POSIX `c_iflag` bits that share values between Linux and Darwin.
/// IGNBRK 0x0001, BRKINT 0x0002, IGNPAR 0x0004, PARMRK 0x0008,
/// INPCK 0x0010, ISTRIP 0x0020, INLCR 0x0040, IGNCR 0x0080,
/// ICRNL 0x0100, IXON 0x0200, IXANY 0x0800, IXOFF 0x0400 (Linux
/// uses 0x1000; we leave that one out of the shared mask). Same
/// for IUTF8 (Linux 0x4000, Darwin 0x4000 — matches on modern macOS).
const COMMON_IFLAG_MASK: u32 = 0x0000_0FFF;

/// POSIX `c_oflag` bits with matching values: OPOST 0x0001,
/// ONLCR 0x0004 (Linux) — Darwin uses 0x0002 for ONLCR. To keep
/// the round-trip honest we mask only OPOST here; ONLCR is
/// translated explicitly below.
const COMMON_OFLAG_MASK: u32 = 0x0000_0001;
const LINUX_ONLCR: u32 = 0x0004;
const DARWIN_ONLCR: u64 = 0x0002;
const LINUX_OCRNL: u32 = 0x0008;
const DARWIN_OCRNL: u64 = 0x0010;

/// POSIX `c_cflag` bits CS5/CS6/CS7/CS8 (0x00/0x10/0x20/0x30 mask
/// 0x30), CSTOPB 0x40, CREAD 0x80, PARENB 0x100, PARODD 0x200,
/// HUPCL 0x400, CLOCAL 0x800.
const COMMON_CFLAG_MASK: u32 = 0x0000_0FFF;

/// POSIX `c_lflag` bits ISIG 0x01, ICANON 0x02, ECHO 0x08, ECHOE
/// 0x10, ECHOK 0x20, ECHONL 0x40, NOFLSH 0x80, TOSTOP 0x100,
/// IEXTEN 0x8000 — all match Linux. Darwin uses different values
/// for some of these so we translate them explicitly.
const LINUX_LFLAG_ISIG: u32 = 0x0000_0001;
const LINUX_LFLAG_ICANON: u32 = 0x0000_0002;
const LINUX_LFLAG_ECHO: u32 = 0x0000_0008;
const LINUX_LFLAG_ECHOE: u32 = 0x0000_0010;
const LINUX_LFLAG_ECHOK: u32 = 0x0000_0020;
const LINUX_LFLAG_ECHONL: u32 = 0x0000_0040;
const LINUX_LFLAG_NOFLSH: u32 = 0x0000_0080;
const LINUX_LFLAG_TOSTOP: u32 = 0x0000_0100;
const LINUX_LFLAG_IEXTEN: u32 = 0x0000_8000;

// Darwin values from <sys/termios.h>.
const DARWIN_LFLAG_ECHOKE: u64 = 0x0000_0001; // unused on linux side; ignore inbound
const DARWIN_LFLAG_ECHOE: u64 = 0x0000_0002;
const DARWIN_LFLAG_ECHOK: u64 = 0x0000_0004;
const DARWIN_LFLAG_ECHO: u64 = 0x0000_0008;
const DARWIN_LFLAG_ECHONL: u64 = 0x0000_0010;
const DARWIN_LFLAG_ECHOPRT: u64 = 0x0000_0020;
const DARWIN_LFLAG_ECHOCTL: u64 = 0x0000_0040;
const DARWIN_LFLAG_ISIG: u64 = 0x0000_0080;
const DARWIN_LFLAG_ICANON: u64 = 0x0000_0100;
const DARWIN_LFLAG_IEXTEN: u64 = 0x0000_0400;
const DARWIN_LFLAG_NOFLSH: u64 = 0x8000_0000;
const DARWIN_LFLAG_TOSTOP: u64 = 0x0040_0000;

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
        let mut darwin: libc::termios = core::mem::zeroed();
        if libc::tcgetattr(fd, &mut darwin) != 0 {
            return None;
        }
        Some(darwin_to_linux_termios(&darwin))
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
        let mut darwin: libc::termios = core::mem::zeroed();
        // Preserve any bits we don't translate by reading the current
        // state first; that way we don't blow away platform-specific
        // bits like Darwin's ECHOKE.
        let _ = libc::tcgetattr(fd, &mut darwin);
        linux_to_darwin_termios(linux, &mut darwin);
        libc::tcsetattr(fd, libc::TCSANOW, &darwin) == 0
    }
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

fn darwin_to_linux_termios(d: &libc::termios) -> LinuxTermios {
    let iflag = (d.c_iflag as u32) & COMMON_IFLAG_MASK;

    let mut oflag = (d.c_oflag as u32) & COMMON_OFLAG_MASK;
    if d.c_oflag & DARWIN_ONLCR != 0 {
        oflag |= LINUX_ONLCR;
    }
    if d.c_oflag & DARWIN_OCRNL != 0 {
        oflag |= LINUX_OCRNL;
    }

    let cflag = (d.c_cflag as u32) & COMMON_CFLAG_MASK;

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

fn linux_to_darwin_termios(l: &LinuxTermios, d: &mut libc::termios) {
    // Preserve any host-specific bits outside the masks we translate.
    let preserved_iflag = d.c_iflag & !(COMMON_IFLAG_MASK as u64);
    let preserved_oflag = d.c_oflag & !((COMMON_OFLAG_MASK as u64) | DARWIN_ONLCR | DARWIN_OCRNL);
    let preserved_cflag = d.c_cflag & !(COMMON_CFLAG_MASK as u64);
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

    let iflag = preserved_iflag | (l.c_iflag as u64 & COMMON_IFLAG_MASK as u64);

    let mut oflag = preserved_oflag | (l.c_oflag as u64 & COMMON_OFLAG_MASK as u64);
    if l.c_oflag & LINUX_ONLCR != 0 {
        oflag |= DARWIN_ONLCR;
    }
    if l.c_oflag & LINUX_OCRNL != 0 {
        oflag |= DARWIN_OCRNL;
    }

    let cflag = preserved_cflag | (l.c_cflag as u64 & COMMON_CFLAG_MASK as u64);

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

    d.c_ispeed = l.c_ispeed as libc::speed_t;
    d.c_ospeed = l.c_ospeed as libc::speed_t;
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
static SAVED_TERMIOS: Mutex<Option<HashMap<i32, libc::termios>>> =
    Mutex::new(None);

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
    let mut guard = SAVED_TERMIOS.lock().unwrap();
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
        let mut guard = SAVED_TERMIOS.lock().unwrap();
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

    #[test]
    fn cc_index_table_is_within_darwin_bounds() {
        // libc::NCCS on Darwin is 20.
        for entry in LINUX_TO_DARWIN_CC.iter().flatten() {
            assert!(*entry < 20, "Darwin VINTR index {entry} out of bounds");
        }
    }

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
        assert!(d2.c_lflag as u64 & DARWIN_LFLAG_ICANON != 0);
        assert!(d2.c_lflag as u64 & DARWIN_LFLAG_ECHO != 0);
        assert!(d2.c_lflag as u64 & DARWIN_LFLAG_ISIG != 0);
    }

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

    // ---- helpers for make_raw tests ----

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

    #[test]
    fn make_raw_clears_icanon_and_echo() {
        let (master, slave) = open_test_pty_for_raw();
        let before = unsafe {
            let mut t: libc::termios = std::mem::zeroed();
            libc::tcgetattr(slave, &mut t);
            t
        };
        assert!(
            before.c_lflag as u64 & (DARWIN_LFLAG_ICANON | DARWIN_LFLAG_ECHO) != 0,
            "slave starts cooked (ICANON|ECHO must be set)"
        );
        make_raw(slave).unwrap();
        let raw = unsafe {
            let mut t: libc::termios = std::mem::zeroed();
            libc::tcgetattr(slave, &mut t);
            t
        };
        assert_eq!(
            raw.c_lflag as u64 & (DARWIN_LFLAG_ICANON | DARWIN_LFLAG_ECHO),
            0,
            "raw clears ICANON|ECHO"
        );
        unsafe {
            libc::close(master);
            libc::close(slave);
        }
    }

    #[test]
    fn make_raw_snapshot_survives_restore() {
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
            raw.c_lflag as u64 & DARWIN_LFLAG_ICANON,
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
            restored.c_lflag as u64 & DARWIN_LFLAG_ICANON,
            cooked.c_lflag as u64 & DARWIN_LFLAG_ICANON,
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
}
