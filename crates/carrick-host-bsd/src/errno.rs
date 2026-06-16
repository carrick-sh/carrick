//! BSD-family (macOS/FreeBSD) host-errno → Linux-errno translation.
//!
//! Lifted from `carrick-runtime`'s `dispatch/mod.rs`. Driven off the host's
//! `libc::E*` constants (resolved per target), NOT off numeric equality, so it
//! compiles correctly for FreeBSD even though high extension errnos differ.

/// Linux UAPI errno values, re-exported under their bare names from the
/// canonical table in `carrick-abi`. The Linux numbers live in exactly one
/// place (`carrick_abi::LINUX_E*`) so the translation can't drift from the ABI.
#[allow(dead_code)]
pub mod linux_errno {
    pub use carrick_abi::{
        LINUX_E2BIG as E2BIG, LINUX_EACCES as EACCES, LINUX_EADDRINUSE as EADDRINUSE,
        LINUX_EADDRNOTAVAIL as EADDRNOTAVAIL, LINUX_EAFNOSUPPORT as EAFNOSUPPORT,
        LINUX_EAGAIN as EAGAIN, LINUX_EALREADY as EALREADY, LINUX_EBADF as EBADF,
        LINUX_EBADMSG as EBADMSG, LINUX_EBUSY as EBUSY, LINUX_ECANCELED as ECANCELED,
        LINUX_ECHILD as ECHILD, LINUX_ECONNABORTED as ECONNABORTED,
        LINUX_ECONNREFUSED as ECONNREFUSED, LINUX_ECONNRESET as ECONNRESET,
        LINUX_EDEADLK as EDEADLK, LINUX_EDESTADDRREQ as EDESTADDRREQ, LINUX_EDOM as EDOM,
        LINUX_EDQUOT as EDQUOT, LINUX_EEXIST as EEXIST, LINUX_EFAULT as EFAULT,
        LINUX_EFBIG as EFBIG, LINUX_EHOSTDOWN as EHOSTDOWN, LINUX_EHOSTUNREACH as EHOSTUNREACH,
        LINUX_EIDRM as EIDRM, LINUX_EILSEQ as EILSEQ, LINUX_EINPROGRESS as EINPROGRESS,
        LINUX_EINTR as EINTR, LINUX_EINVAL as EINVAL, LINUX_EIO as EIO, LINUX_EISCONN as EISCONN,
        LINUX_EISDIR as EISDIR, LINUX_ELOOP as ELOOP, LINUX_EMFILE as EMFILE,
        LINUX_EMLINK as EMLINK, LINUX_EMSGSIZE as EMSGSIZE, LINUX_ENAMETOOLONG as ENAMETOOLONG,
        LINUX_ENETDOWN as ENETDOWN, LINUX_ENETRESET as ENETRESET, LINUX_ENETUNREACH as ENETUNREACH,
        LINUX_ENFILE as ENFILE, LINUX_ENOBUFS as ENOBUFS, LINUX_ENODEV as ENODEV,
        LINUX_ENOENT as ENOENT, LINUX_ENOEXEC as ENOEXEC, LINUX_ENOLCK as ENOLCK,
        LINUX_ENOLINK as ENOLINK, LINUX_ENOMEM as ENOMEM, LINUX_ENOMSG as ENOMSG,
        LINUX_ENOPROTOOPT as ENOPROTOOPT, LINUX_ENOSPC as ENOSPC, LINUX_ENOSYS as ENOSYS,
        LINUX_ENOTBLK as ENOTBLK, LINUX_ENOTCONN as ENOTCONN, LINUX_ENOTDIR as ENOTDIR,
        LINUX_ENOTEMPTY as ENOTEMPTY, LINUX_ENOTSOCK as ENOTSOCK, LINUX_ENOTTY as ENOTTY,
        LINUX_ENXIO as ENXIO, LINUX_EOPNOTSUPP as EOPNOTSUPP, LINUX_EOVERFLOW as EOVERFLOW,
        LINUX_EPERM as EPERM, LINUX_EPFNOSUPPORT as EPFNOSUPPORT, LINUX_EPIPE as EPIPE,
        LINUX_EPROTONOSUPPORT as EPROTONOSUPPORT, LINUX_EPROTOTYPE as EPROTOTYPE,
        LINUX_ERANGE as ERANGE, LINUX_EREMOTE as EREMOTE, LINUX_EROFS as EROFS,
        LINUX_ESHUTDOWN as ESHUTDOWN, LINUX_ESOCKTNOSUPPORT as ESOCKTNOSUPPORT,
        LINUX_ESPIPE as ESPIPE, LINUX_ESRCH as ESRCH, LINUX_ESTALE as ESTALE,
        LINUX_ETIMEDOUT as ETIMEDOUT, LINUX_ETOOMANYREFS as ETOOMANYREFS, LINUX_ETXTBSY as ETXTBSY,
        LINUX_EUCLEAN as EUCLEAN, LINUX_EXDEV as EXDEV,
    };
}

/// Robust, systematic BSD-errno → Linux-errno translation. Driven off the
/// host's `libc::E*` constants so we don't hard-code BSD numeric values —
/// and so this compiles correctly on FreeBSD where high extension errnos
/// differ from macOS. Codes 1..=34 overlap between the two and pass through
/// unchanged, EXCEPT the explicit divergence arms below (e.g. EDEADLK, whose
/// BSD value 11 must NOT pass through to Linux 11 = EAGAIN).
/// Sources:
/// - macOS/FreeBSD: <sys/errno.h>
/// - Linux: asm-generic/errno-base.h + asm-generic/errno.h
pub fn bsd_to_linux_errno(host: i32) -> i32 {
    #[cfg(any(
        target_os = "macos",
        target_os = "ios",
        target_os = "freebsd",
        target_os = "netbsd",
        target_os = "openbsd",
        target_os = "dragonfly"
    ))]
    {
        use linux_errno::*;

        match host {
            x if x == libc::EAGAIN => EAGAIN,
            x if x == libc::EINPROGRESS => EINPROGRESS,
            x if x == libc::EALREADY => EALREADY,
            x if x == libc::ENOTSOCK => ENOTSOCK,
            x if x == libc::EDESTADDRREQ => EDESTADDRREQ,
            x if x == libc::EMSGSIZE => EMSGSIZE,
            x if x == libc::EPROTOTYPE => EPROTOTYPE,
            x if x == libc::ENOPROTOOPT => ENOPROTOOPT,
            x if x == libc::EPROTONOSUPPORT => EPROTONOSUPPORT,
            x if x == libc::ESOCKTNOSUPPORT => ESOCKTNOSUPPORT,
            x if x == libc::EOPNOTSUPP => EOPNOTSUPP,
            x if x == libc::EPFNOSUPPORT => EPFNOSUPPORT,
            x if x == libc::EAFNOSUPPORT => EAFNOSUPPORT,
            x if x == libc::EADDRINUSE => EADDRINUSE,
            x if x == libc::EADDRNOTAVAIL => EADDRNOTAVAIL,
            x if x == libc::ENETDOWN => ENETDOWN,
            x if x == libc::ENETUNREACH => ENETUNREACH,
            x if x == libc::ENETRESET => ENETRESET,
            x if x == libc::ECONNABORTED => ECONNABORTED,
            x if x == libc::ECONNRESET => ECONNRESET,
            x if x == libc::ENOBUFS => ENOBUFS,
            x if x == libc::EISCONN => EISCONN,
            x if x == libc::ENOTCONN => ENOTCONN,
            x if x == libc::ESHUTDOWN => ESHUTDOWN,
            x if x == libc::ETOOMANYREFS => ETOOMANYREFS,
            x if x == libc::ETIMEDOUT => ETIMEDOUT,
            x if x == libc::ECONNREFUSED => ECONNREFUSED,
            x if x == libc::ELOOP => ELOOP,
            x if x == libc::ENAMETOOLONG => ENAMETOOLONG,
            x if x == libc::EHOSTDOWN => EHOSTDOWN,
            x if x == libc::EHOSTUNREACH => EHOSTUNREACH,
            x if x == libc::ENOTEMPTY => ENOTEMPTY,
            x if x == libc::EDQUOT => EDQUOT,
            x if x == libc::ESTALE => ESTALE,
            x if x == libc::EREMOTE => EREMOTE,
            x if x == libc::ENOLCK => ENOLCK,
            x if x == libc::ENOSYS => ENOSYS,
            x if x == libc::EOVERFLOW => EOVERFLOW,
            x if x == libc::ECANCELED => ECANCELED,
            x if x == libc::EIDRM => EIDRM,
            x if x == libc::ENOMSG => ENOMSG,
            x if x == libc::EILSEQ => EILSEQ,
            x if x == libc::EBADMSG => EBADMSG,
            // BSD EDEADLK = 11 collides with Linux EAGAIN = 11. Without this
            // explicit arm it falls through the 1..=34 passthrough below and
            // mistranslates to Linux EAGAIN. Linux EDEADLK = 35. (Regression
            // test: edeadlk_does_not_collapse_to_eagain.)
            x if x == libc::EDEADLK => EDEADLK,
            // macOS/FreeBSD ENOATTR ("attribute not found") is Linux ENODATA —
            // what getxattr/removexattr return for a missing xattr. Without
            // this it collapsed to EIO and LTP getxattr01/removexattr* failed
            // their ENODATA expectation.
            x if x == libc::ENOATTR => carrick_abi::LINUX_ENODATA,
            // Codes 1..=34 overlap; unmapped BSD extension errnos above that
            // range are not Linux numbers, so collapse them to EIO rather than
            // leaking host-specific values to the guest.
            other if (1..=34).contains(&other) => other,
            _ => EIO,
        }
    }
    #[cfg(not(any(
        target_os = "macos",
        target_os = "ios",
        target_os = "freebsd",
        target_os = "netbsd",
        target_os = "openbsd",
        target_os = "dragonfly"
    )))]
    {
        host
    }
}

#[cfg(test)]
#[cfg(any(
    target_os = "macos",
    target_os = "ios",
    target_os = "freebsd",
    target_os = "netbsd",
    target_os = "openbsd",
    target_os = "dragonfly"
))]
mod tests {
    use super::{bsd_to_linux_errno, linux_errno};

    #[test]
    fn errno_translation_covers_every_divergent_code() {
        // Overlap zone: 1..=34 must pass through (except the explicit
        // divergence arms tested separately, e.g. EDEADLK).
        for code in 1..=34 {
            if code == libc::EDEADLK {
                continue;
            }
            assert_eq!(
                bsd_to_linux_errno(code),
                code,
                "code {} should be identity in overlap zone",
                code
            );
        }
        assert_eq!(
            bsd_to_linux_errno(libc::EINPROGRESS),
            linux_errno::EINPROGRESS
        );
        assert_ne!(
            bsd_to_linux_errno(libc::EINPROGRESS),
            36,
            "EINPROGRESS != Linux ENAMETOOLONG"
        );
        assert_eq!(bsd_to_linux_errno(libc::EAGAIN), linux_errno::EAGAIN);
        assert_eq!(
            bsd_to_linux_errno(libc::ECONNREFUSED),
            linux_errno::ECONNREFUSED
        );
        assert_eq!(
            bsd_to_linux_errno(libc::EHOSTUNREACH),
            linux_errno::EHOSTUNREACH
        );
        assert_eq!(bsd_to_linux_errno(libc::ETIMEDOUT), linux_errno::ETIMEDOUT);
        assert_eq!(bsd_to_linux_errno(libc::ENOTCONN), linux_errno::ENOTCONN);
        assert_eq!(
            bsd_to_linux_errno(libc::ECONNRESET),
            linux_errno::ECONNRESET
        );
        assert_eq!(
            bsd_to_linux_errno(libc::EADDRINUSE),
            linux_errno::EADDRINUSE
        );
        assert_eq!(
            bsd_to_linux_errno(libc::EAFNOSUPPORT),
            linux_errno::EAFNOSUPPORT
        );
        assert_eq!(
            bsd_to_linux_errno(libc::ENAMETOOLONG),
            linux_errno::ENAMETOOLONG
        );
        assert_eq!(bsd_to_linux_errno(libc::ENOTEMPTY), linux_errno::ENOTEMPTY);
        assert_eq!(bsd_to_linux_errno(libc::ELOOP), linux_errno::ELOOP);
        assert_eq!(bsd_to_linux_errno(libc::ENOSYS), linux_errno::ENOSYS);
        assert_eq!(bsd_to_linux_errno(libc::ENOLCK), linux_errno::ENOLCK);
        assert_eq!(bsd_to_linux_errno(libc::EIDRM), linux_errno::EIDRM);
        assert_eq!(bsd_to_linux_errno(libc::EILSEQ), linux_errno::EILSEQ);
        assert_eq!(bsd_to_linux_errno(libc::ECANCELED), linux_errno::ECANCELED);
    }

    #[test]
    fn errno_translation_maps_unknown_extensions_to_eio() {
        // ENOATTR ("attribute not found") maps to Linux ENODATA.
        assert_eq!(
            bsd_to_linux_errno(libc::ENOATTR),
            carrick_abi::LINUX_ENODATA
        );
        assert_eq!(bsd_to_linux_errno(999), linux_errno::EIO);
    }

    /// Regression for the latent EDEADLK bug: BSD EDEADLK = 11 must translate
    /// to Linux EDEADLK = 35, NOT collapse through the 1..=34 passthrough to
    /// Linux 11 = EAGAIN. (carrick-abi: LINUX_EDEADLK=35, LINUX_EAGAIN=11.)
    #[test]
    fn edeadlk_does_not_collapse_to_eagain() {
        assert_eq!(
            libc::EDEADLK,
            11,
            "guard: this test assumes BSD EDEADLK == 11"
        );
        assert_eq!(
            bsd_to_linux_errno(libc::EDEADLK),
            carrick_abi::LINUX_EDEADLK
        );
        assert_eq!(bsd_to_linux_errno(libc::EDEADLK), 35);
        assert_ne!(
            bsd_to_linux_errno(libc::EDEADLK),
            linux_errno::EAGAIN,
            "EDEADLK must not mistranslate to EAGAIN"
        );
    }
}

/// FreeBSD-specific errno translation pins. These lock down the three arms most
/// likely to silently regress on FreeBSD: the EAGAIN/EDEADLK numeric collision
/// (BSD 35/11 vs Linux 11/35) and the ENOATTR → ENODATA xattr mapping.
#[cfg(all(test, target_os = "freebsd"))]
mod freebsd_errno_tests {
    use super::*;

    #[test]
    fn collision_and_xattr_arms_are_freebsd_correct() {
        // FreeBSD EAGAIN = 35; Linux EAGAIN = 11.
        // Without the explicit arm, BSD 35 would fall through the 1..=34
        // passthrough unchanged and reach the guest as Linux 35 = EDEADLK.
        assert_eq!(
            bsd_to_linux_errno(libc::EAGAIN),
            carrick_abi::LINUX_EAGAIN as i32,
            "BSD EAGAIN({}) must map to Linux EAGAIN({})",
            libc::EAGAIN,
            carrick_abi::LINUX_EAGAIN
        );

        // FreeBSD EDEADLK = 11; Linux EDEADLK = 35.
        // Without the explicit arm, BSD 11 passes through the 1..=34 zone and
        // reaches the guest as Linux 11 = EAGAIN.
        assert_eq!(
            bsd_to_linux_errno(libc::EDEADLK),
            carrick_abi::LINUX_EDEADLK as i32,
            "BSD EDEADLK({}) must map to Linux EDEADLK({})",
            libc::EDEADLK,
            carrick_abi::LINUX_EDEADLK
        );

        // FreeBSD ENOATTR ("attribute not found") → Linux ENODATA.
        assert_eq!(
            bsd_to_linux_errno(libc::ENOATTR),
            carrick_abi::LINUX_ENODATA as i32,
            "BSD ENOATTR({}) must map to Linux ENODATA({})",
            libc::ENOATTR,
            carrick_abi::LINUX_ENODATA
        );
    }
}
