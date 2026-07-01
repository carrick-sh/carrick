//! The platform-NEUTRAL host-signal driver glue: the routed/nudge sigaction
//! handlers and the disposition control flow, generic over a backend's
//! [`HostSignalGlue`]. This is the consolidation of the three byte-identical
//! `*_disposition.rs` + `*_xsig.rs` modules (KVM/bhyve/NVMM) into ONE generic —
//! the per-backend delta (signum translation, claimed set, kick number, pump
//! poke) is exactly `G`'s methods. KVM's old identity form falls out because
//! `KvmGlue::host_to_linux`/`linux_to_host` are identity; the BSD backends pass a
//! translation table and the SAME code services them.
//!
//! Every `extern "C"` handler here is async-signal-safe: a pure-arithmetic / table
//! translation through `G`, an atomic store, and one `write(2)` (`G::poke`).

use std::os::raw::{c_int, c_void};

use crate::backend::HostSignalGlue;
use crate::host_disposition;

// ─── signum translation (the runtime's host_to_linux_signum / linux_to_host) ───

/// Translate a host signum to the guest's Linux signum for backend `G`.
pub fn glue_host_to_linux<G: HostSignalGlue>(host_signum: i32) -> i32 {
    G::host_to_linux(host_signum)
}

/// Translate a guest Linux signum to backend `G`'s host signum.
pub fn glue_linux_to_host<G: HostSignalGlue>(linux_signum: i32) -> i32 {
    G::linux_to_host(linux_signum)
}

// ─── disposition mirror (was kvm/bhyve/nvmm_disposition.rs) ────────────────────

/// Whether `linux_signum` is eligible for a mirrored host disposition on backend
/// `G`: the SHARED neutral base policy ANDed with `!G::is_claimed`. This is the
/// complement of the DEFAULT `HostSignalGlue::skip_install_routing`; the
/// disposition fns now consult the per-function `G::skip_*` gates (so a backend
/// like HVF that routes the fault set can differ per function), and this remains
/// as the test oracle for the default routability.
#[cfg(test)]
fn is_routable<G: HostSignalGlue>(linux_signum: i32) -> bool {
    host_disposition::is_host_routable(linux_signum) && !G::is_claimed(linux_signum)
}

/// ASYNC-SIGNAL-SAFE host routed handler: a sibling guest process `kill`ed us with
/// a HOST signum; translate to the guest Linux signum, record the sender, publish
/// it pending, and poke the pump so the generic loop runs the guest handler. Does
/// ONLY: `record_sender` (atomic), `proc_pending_fetch_or` (atomic), `G::poke`
/// (one `write(2)`). On KVM `G::host_to_linux` is identity, so this monomorphizes
/// to the old `kvm_routed_handler`; on BSD it translates first.
extern "C" fn shared_routed_handler<G: HostSignalGlue>(
    host_signum: c_int,
    info: *mut libc::siginfo_t,
    _ctx: *mut c_void,
) {
    let linux_signum = G::host_to_linux(host_signum);
    if !info.is_null() {
        // si_code > 0 ⇒ hardware/kernel-generated (a real fault at the faulting
        // PC), i.e. carrick's OWN bug: restore the default disposition and return
        // so the process crashes visibly with the true signal. si_code <= 0 ⇒
        // SI_USER/SI_QUEUE/SI_TKILL, sent by another process ⇒ route to the guest.
        // `is_synchronous_self_fault` is `false` for every backend whose guest
        // faults are vmexits (KVM/bhyve/NVMM), so this is a no-op there; HVF
        // overrides it for the fault set it routes.
        let si_code = unsafe { (*info).si_code };
        if G::is_synchronous_self_fault(linux_signum, si_code) {
            // SAFETY: zeroed sigaction with SIG_DFL is the documented default
            // disposition form; signal-safe.
            unsafe {
                let mut dfl: libc::sigaction = std::mem::zeroed();
                dfl.sa_sigaction = libc::SIG_DFL;
                libc::sigemptyset(&mut dfl.sa_mask);
                libc::sigaction(host_signum, &dfl, std::ptr::null_mut());
            }
            return;
        }
        // SAFETY: the kernel hands a valid siginfo_t to an SA_SIGINFO handler;
        // `si_pid()` reads the POSIX union member. `record_sender` is one atomic
        // store — async-signal-safe.
        crate::record_sender(linux_signum, unsafe { (*info).si_pid() });
    }
    if let Some(bit) = crate::pending_bit(linux_signum) {
        crate::proc_pending_fetch_or(bit);
    }
    G::poke();
}

/// Install `handler` (a routed handler fn, `SIG_IGN`, or `SIG_DFL`) as the host
/// disposition for the guest `linux_signum`, on backend `G`'s HOST signum. A
/// routed handler gets `SA_RESTART | SA_SIGINFO` (it reads `si_pid`);
/// `SIG_IGN`/`SIG_DFL` get no flags. Helper; the public fns gate on `is_routable`.
fn install_sigaction<G: HostSignalGlue>(linux_signum: i32, handler: libc::sighandler_t) {
    let host_signum = G::linux_to_host(linux_signum);
    let is_action = handler != libc::SIG_IGN && handler != libc::SIG_DFL;
    // SAFETY: a zeroed `sigaction` is the documented "no flags, empty mask" form;
    // we set the handler + flags before calling libc. `host_signum` is a valid
    // host signal (the `is_routable` / install-mask gate guarantees the linux
    // signum is in 1..=64 and the translation maps it into the host range).
    unsafe {
        let mut action: libc::sigaction = std::mem::zeroed();
        action.sa_sigaction = handler;
        libc::sigemptyset(&mut action.sa_mask);
        action.sa_flags = if is_action {
            libc::SA_RESTART | libc::SA_SIGINFO
        } else {
            0
        };
        libc::sigaction(host_signum, &action, std::ptr::null_mut());
    }
}

/// Install a host routed handler for the guest `linux_signum` so a sibling guest
/// process's host `kill` runs THIS guest's handler instead of host-default
/// terminating us. Idempotent; no-op for non-routable / `G`-claimed signals.
pub fn ensure_host_handler<G: HostSignalGlue>(linux_signum: i32) {
    if G::skip_install_routing(linux_signum) {
        return;
    }
    if host_disposition::mark_installed(linux_signum) {
        return; // already installed (idempotent)
    }
    install_sigaction::<G>(
        linux_signum,
        shared_routed_handler::<G> as *const () as libc::sighandler_t,
    );
}

/// Mirror a guest `SIG_IGN` onto the HOST disposition so a sibling's host `kill` is
/// DROPPED (honoring the ignore). Clears the routed-handler INSTALLED bit so a
/// later `SIG_IGN -> handler` transition re-installs the route. No-op for
/// non-routable / `G`-claimed signals.
pub fn set_host_ignore<G: HostSignalGlue>(linux_signum: i32) {
    if G::skip_ignore_mirror(linux_signum) {
        return;
    }
    install_sigaction::<G>(linux_signum, libc::SIG_IGN);
    host_disposition::clear_installed(linux_signum);
}

/// Reset a mirrored signal's HOST disposition back to `SIG_DFL` (the guest reset it
/// to default), clearing any inherited host ignore/route. No-op for non-routable /
/// `G`-claimed signals.
pub fn set_host_default<G: HostSignalGlue>(linux_signum: i32) {
    if G::skip_ignore_mirror(linux_signum) {
        return;
    }
    install_sigaction::<G>(linux_signum, libc::SIG_DFL);
    host_disposition::clear_installed(linux_signum);
}

/// Reset host dispositions installed only to route guest caught-signal handlers, as
/// a guest `execve` does (caught -> default; `SIG_IGN` preserved). Walks the shared
/// install mask; for each installed signal NOT in `ignored` reset the host to
/// `SIG_DFL`. `G`-claimed signals are skipped defensively.
///
/// `ignored` is a typed [`carrick_abi::SigSet`] — this function previously took a
/// bare `u64` in a bit=SIGNUM convention (bit 0 unused) while computing the
/// install bit as `1 << (signum - 1)` three lines up: two bit conventions on
/// identical raw types in one function, self-consistent only by luck. The
/// `SigSet` newtype (bit `signum-1` everywhere) retires the second convention.
pub fn reset_routed_handlers_after_execve<G: HostSignalGlue>(ignored: carrick_abi::SigSet) {
    let installed = host_disposition::installed_mask();
    for linux_signum in 1..=64i32 {
        let install_bit = 1u64 << (linux_signum - 1);
        if installed & install_bit == 0 {
            continue;
        }
        if G::skip_execve_reset(linux_signum) {
            continue;
        }
        if ignored.contains(linux_signum) {
            continue; // the new image keeps it ignored
        }
        install_sigaction::<G>(linux_signum, libc::SIG_DFL);
        host_disposition::clear_installed(linux_signum);
    }
}

// ─── xsignal nudge (was kvm/bhyve/nvmm_xsig.rs) ────────────────────────────────

/// Nudge `target_host_pid` to drain its xsignal entries (host `G::nudge_signum()`).
/// A nudge to a dead pid returns ESRCH, ignored (the slot is simply never drained).
pub fn xsig_nudge<G: HostSignalGlue>(target_host_pid: i32) {
    // SAFETY: kill(2) with a pid and a valid signal.
    unsafe {
        libc::kill(target_host_pid, G::nudge_signum());
    }
}

/// The xsignal nudge handler: a sibling queued a guest signal for us in the shared
/// ring. ASYNC-SIGNAL-SAFE — exactly `mark_xsig_dirty()` (one atomic store) then
/// `G::poke()` (one `write(2)`).
extern "C" fn shared_xsig_nudge_handler<G: HostSignalGlue>(_sig: c_int) {
    crate::xsig::mark_xsig_dirty();
    G::poke();
}

/// Install the [`HostSignalGlue::nudge_signum`] handler. `sa_flags = 0` (NO
/// SA_RESTART, like the kick) so a nudge landing directly on a vCPU thread also
/// EINTRs its in-progress run-loop ioctl. Idempotent via the disposition mask is
/// not used here (the caller's `Once` guards it); installing twice is harmless.
pub fn install_xsig_nudge_handler<G: HostSignalGlue>() {
    // SAFETY: zeroed sigaction = "no flags, empty mask"; we set the handler, an
    // empty mask, and sa_flags = 0. `shared_xsig_nudge_handler::<G>` is a valid
    // `extern "C"` handler.
    unsafe {
        let mut action: libc::sigaction = std::mem::zeroed();
        action.sa_sigaction = shared_xsig_nudge_handler::<G> as *const () as libc::sighandler_t;
        libc::sigemptyset(&mut action.sa_mask);
        action.sa_flags = 0; // NO SA_RESTART — a direct nudge must EINTR the run loop.
        libc::sigaction(G::nudge_signum(), &action, std::ptr::null_mut());
    }
}

/// Initialise the xsignal ring + install the nudge handler for backend `G`. MUST
/// run pre-fork so the `MAP_SHARED` ring is inherited by every child. `xsig_init`
/// no-ops on an already-mapped ring; the caller (`GenericForkCoordinator`) guards
/// the handler install with a `Once`, so the post-fork re-assert is free.
pub fn init_xsig<G: HostSignalGlue>() {
    crate::xsig::xsig_init();
    // The FASYNC (signal-driven I/O) registry shares the same pre-fork lifetime
    // requirement: it must be MAP_SHARED-mapped before any guest fork so every
    // process inherits ONE table (a writer process looks up a reader's arming).
    crate::fasync::fasync_init();
    install_xsig_nudge_handler::<G>();
}

#[cfg(test)]
mod tests {
    use super::*;

    // Tests use LINUX signum literals (1=HUP, 2=INT, 3=QUIT, 13=PIPE, 15=TERM,
    // 17=CHLD, 34=SIGRTMIN, 35=nudge), NOT `libc::SIG*` — the generic logic keys on
    // the guest's Linux numbers, and `libc::SIGRTMIN()`/`SIGCHLD` differ on (or are
    // absent from) the macOS host this crate also compiles for.
    const L_HUP: i32 = 1;
    const L_INT: i32 = 2;
    const L_QUIT: i32 = 3;
    const L_PIPE: i32 = 13;
    const L_TERM: i32 = 15;
    const L_CHLD: i32 = 17;
    const L_RTMIN: i32 = 34;

    /// Identity backend (KVM shape): host signum == linux signum, claims the four
    /// pumped signals + SIGCHLD + SIGPIPE + the kick/nudge.
    struct IdentityGlue;
    impl HostSignalGlue for IdentityGlue {
        fn kick_signal() -> i32 {
            L_RTMIN
        }
        fn host_to_linux(s: i32) -> i32 {
            s
        }
        fn linux_to_host(s: i32) -> i32 {
            s
        }
        fn is_claimed(s: i32) -> bool {
            matches!(s, L_HUP | L_INT | L_QUIT | L_TERM)
                || s == L_CHLD
                || s == L_PIPE
                || s == L_RTMIN
                || s == L_RTMIN + 1
        }
        fn poke() {}
        fn install_kick_handler() {}
    }

    /// BSD-like backend: a non-identity translation (host = linux + 100 for the
    /// test, both directions) proves the routed handler records under the LINUX
    /// number and `install_sigaction` uses the HOST number.
    struct BsdLikeGlue;
    impl HostSignalGlue for BsdLikeGlue {
        fn kick_signal() -> i32 {
            65
        }
        fn host_to_linux(s: i32) -> i32 {
            if s > 100 { s - 100 } else { s }
        }
        fn linux_to_host(s: i32) -> i32 {
            if s < 100 { s + 100 } else { s }
        }
        fn is_claimed(s: i32) -> bool {
            matches!(s, 1 | 2 | 3 | 15) || s == 17 || s == 13
        }
        fn poke() {}
        fn install_kick_handler() {}
    }

    #[test]
    fn nudge_distinct_from_kick_and_pumped() {
        assert_eq!(IdentityGlue::nudge_signum(), L_RTMIN + 1);
        assert_ne!(IdentityGlue::nudge_signum(), IdentityGlue::kick_signal());
        assert_eq!(BsdLikeGlue::nudge_signum(), 66);
        for s in [L_HUP, L_INT, L_QUIT, L_TERM] {
            assert_ne!(IdentityGlue::nudge_signum(), s);
        }
    }

    #[test]
    fn routable_excludes_claimed_and_faults() {
        assert!(is_routable::<IdentityGlue>(10)); // SIGUSR1
        assert!(is_routable::<IdentityGlue>(12)); // SIGUSR2
        assert!(!is_routable::<IdentityGlue>(L_TERM));
        assert!(!is_routable::<IdentityGlue>(L_CHLD));
        assert!(!is_routable::<IdentityGlue>(L_PIPE));
        assert!(!is_routable::<IdentityGlue>(L_RTMIN));
        for s in [4, 5, 6, 7, 8, 11] {
            assert!(!is_routable::<IdentityGlue>(s), "fault {s} not routable");
        }
        assert!(!is_routable::<IdentityGlue>(9)); // SIGKILL
        assert!(!is_routable::<IdentityGlue>(19)); // SIGSTOP
    }

    #[test]
    fn install_ignore_default_roundtrip_tracks_mask_identity() {
        const SIG: i32 = 23; // SIGURG — routable, not claimed.
        assert!(is_routable::<IdentityGlue>(SIG));
        host_disposition::clear_installed(SIG);

        ensure_host_handler::<IdentityGlue>(SIG);
        assert!(host_disposition::is_installed(SIG));
        ensure_host_handler::<IdentityGlue>(SIG); // idempotent
        assert!(host_disposition::is_installed(SIG));

        set_host_ignore::<IdentityGlue>(SIG);
        assert!(
            !host_disposition::is_installed(SIG),
            "ignore drops the route bit"
        );

        ensure_host_handler::<IdentityGlue>(SIG);
        assert!(host_disposition::is_installed(SIG));
        set_host_default::<IdentityGlue>(SIG);
        assert!(
            !host_disposition::is_installed(SIG),
            "default clears the bit"
        );

        // Claimed signal is a no-op.
        host_disposition::clear_installed(libc::SIGTERM);
        ensure_host_handler::<IdentityGlue>(libc::SIGTERM);
        assert!(!host_disposition::is_installed(libc::SIGTERM));

        set_host_default::<IdentityGlue>(SIG);
        host_disposition::clear_installed(SIG);
    }

    #[test]
    fn ignore_then_handler_reinstalls_route() {
        const SIG: i32 = 10; // SIGUSR1
        host_disposition::clear_installed(SIG);
        set_host_ignore::<IdentityGlue>(SIG);
        assert!(!host_disposition::is_installed(SIG));
        ensure_host_handler::<IdentityGlue>(SIG);
        assert!(
            host_disposition::is_installed(SIG),
            "ignore->handler re-installs"
        );
        set_host_default::<IdentityGlue>(SIG);
        host_disposition::clear_installed(SIG);
    }

    #[test]
    fn execve_reset_preserves_ignored_mask() {
        const SIG_KEEP: i32 = 10;
        const SIG_RESET: i32 = 12;
        host_disposition::clear_all();
        ensure_host_handler::<IdentityGlue>(SIG_KEEP);
        ensure_host_handler::<IdentityGlue>(SIG_RESET);
        assert!(host_disposition::is_installed(SIG_KEEP));
        assert!(host_disposition::is_installed(SIG_RESET));

        reset_routed_handlers_after_execve::<IdentityGlue>(
            carrick_abi::SigSet::EMPTY.with(SIG_KEEP),
        );
        assert!(
            host_disposition::is_installed(SIG_KEEP),
            "ignored-mask kept"
        );
        assert!(
            !host_disposition::is_installed(SIG_RESET),
            "non-ignored reset"
        );

        set_host_default::<IdentityGlue>(SIG_KEEP);
        host_disposition::clear_all();
    }

    /// The translation path: with a non-identity glue, the routable/claimed checks
    /// and the install mask all key on the LINUX signum, while the sigaction is
    /// installed on the HOST signum (linux+100). Proves both directions exercise
    /// the SAME generic code KVM uses.
    #[test]
    fn translated_glue_keys_mask_on_linux_signum() {
        const LIN: i32 = 12; // SIGUSR2 (linux); host would be 112.
        assert!(is_routable::<BsdLikeGlue>(LIN));
        assert!(!is_routable::<BsdLikeGlue>(15)); // SIGTERM claimed
        host_disposition::clear_installed(LIN);
        ensure_host_handler::<BsdLikeGlue>(LIN);
        assert!(
            host_disposition::is_installed(LIN),
            "mask keyed on the LINUX signum, not the host (112)"
        );
        assert!(!host_disposition::is_installed(112));
        set_host_default::<BsdLikeGlue>(LIN);
        host_disposition::clear_installed(LIN);
        assert_eq!(BsdLikeGlue::host_to_linux(112), 12);
        assert_eq!(BsdLikeGlue::linux_to_host(12), 112);
    }
}
