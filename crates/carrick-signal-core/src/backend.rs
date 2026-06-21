//! The per-backend host-signal SEAM (Review-P1 #6). Everything else about
//! cross-process guest-signal delivery — the MAP_SHARED xsignal ring
//! ([`crate::xsig`]), the disposition mirror + install mask
//! ([`crate::host_disposition`]), the routed/nudge sigaction handlers and the
//! `ensure`/`set_ignore`/`set_default`/`execve-reset` control flow
//! ([`crate::host_glue`]) — is platform-NEUTRAL and lives here in the leaf crate.
//!
//! A backend (KVM, bhyve, NVMM) supplies ONLY this ~15-line glue: its kick signal
//! number, its host↔linux signum translation, its extra claimed-signal set, and a
//! `poke` that wakes its pump. The irreducible "interrupt a running vCPU" kick is
//! abstracted ELSEWHERE (`carrick_hal::VcpuRegistry`), so it is not part of this
//! trait. HVF has a genuinely different (kqueue) pump and does NOT use this seam.
//!
//! Every method MUST be async-signal-safe (`const`-foldable arithmetic, a table
//! `match`, or a single atomic store / `write(2)`) — the routed/nudge/pump
//! handlers in [`crate::host_glue`] call `host_to_linux`, `is_claimed`,
//! `nudge_signum` and `poke` directly from a real signal handler.

/// The backend-specific glue the neutral host-signal driver calls into. All
/// methods are associated (no `self`): a `HostSignalGlue` is a zero-sized marker
/// type, instantiated as the generic parameter of the shared handlers/driver so
/// monomorphization produces, per backend, the exact code that lived in
/// `*_disposition.rs` / `*_xsig.rs` / `*_signal_pump.rs` before the consolidation.
pub trait HostSignalGlue: 'static {
    /// The host signal number carrick uses to KICK a vCPU out of its run loop
    /// (KVM: `libc::SIGRTMIN()`; bhyve: 65; NVMM: 33). The actual kick MECHANISM
    /// (what the handler does) lives behind `carrick_hal::VcpuKick`; this is only
    /// the number, needed to derive [`nudge_signum`](Self::nudge_signum) and to
    /// exclude the kick from disposition mirroring.
    fn kick_signal() -> i32;

    /// The host signal carrick uses to NUDGE a sibling process to drain its
    /// xsignal ring — a pure wakeup that NEVER injects itself as a guest signal.
    /// Default `kick_signal() + 1` (distinct from the kick, and from the pumped
    /// SIGHUP/INT/QUIT/TERM). Override only if a backend needs a different number.
    fn nudge_signum() -> i32 {
        Self::kick_signal() + 1
    }

    /// Translate a HOST signum to the LINUX (guest) signum. KVM is identity (Linux
    /// host); the BSD backends use the `carrick_host_bsd::signum` table. Called by
    /// the routed + pump handlers BEFORE recording pending, so the guest sees the
    /// Linux number it expects. MUST be a pure table/identity (signal-safe).
    fn host_to_linux(host_signum: i32) -> i32;

    /// Translate a LINUX (guest) signum to the HOST signum, for installing the
    /// `sigaction` on the right host number. Inverse of [`Self::host_to_linux`];
    /// KVM identity, BSD table. Pure (signal-safe).
    fn linux_to_host(linux_signum: i32) -> i32;

    /// Whether `linux_signum` is already CLAIMED by this backend for one of its own
    /// mechanisms (the pumped SIGHUP/INT/QUIT/TERM, SIGCHLD reaper, SIGPIPE, the
    /// kick/nudge) — so the disposition mirror must leave it alone. ANDed with the
    /// neutral `host_disposition::is_host_routable`. Pure (signal-safe).
    fn is_claimed(linux_signum: i32) -> bool;

    /// Wake this backend's signal pump after an async handler marked state pending
    /// — the ONE call the shared handlers make into per-backend pump state (each
    /// backend's `GenericSignalPump::poke::<Self>()`, a single `write(2)` to the
    /// pump self-pipe). MUST be async-signal-safe.
    fn poke();

    /// Install this backend's vCPU-KICK signal handler (idempotent). UNLIKE the
    /// other methods this is a SETUP call (the shared `GenericForkCoordinator`
    /// invokes it from normal context, never from a signal handler), so it may
    /// install a `sigaction`. The kick handler is the no-op whose only job is to
    /// EINTR the backend's run-loop ioctl (KVM_RUN / vm_run / nvmm_vcpu_run) — see
    /// each backend's `*_kicker::install_*_kick_handler`. A backend whose kick is
    /// NOT a signal (HVF: `hv_vcpus_exit`) makes this a no-op.
    fn install_kick_handler();

    /// Whether to SKIP installing a routed host handler for `linux_signum` — the
    /// gate `host_glue::ensure_host_handler` consults. Default = the neutral
    /// `!is_host_routable` (faults + uncatchable) OR `is_claimed`, i.e. exactly the
    /// pre-existing `!is_routable`. HVF overrides: it ROUTES the fault set (a
    /// sibling `kill -SEGV` must reach the guest, distinguished by
    /// [`is_synchronous_self_fault`](Self::is_synchronous_self_fault)), so it skips
    /// a SMALLER set. Pure (signal-safe).
    fn skip_install_routing(linux_signum: i32) -> bool {
        // Exactly the pre-existing `!is_routable`: !is_host_routable || is_claimed.
        !crate::host_disposition::is_host_routable(linux_signum) || Self::is_claimed(linux_signum)
    }

    /// Whether to SKIP mirroring a guest `SIG_IGN`/`SIG_DFL` onto the host — the
    /// gate `set_host_ignore`/`set_host_default` consult. Default =
    /// [`skip_install_routing`](Self::skip_install_routing). HVF overrides to ALSO
    /// skip the fault set + SIGINT: host-`SIG_IGN`ing a synchronous fault would let
    /// a real fault re-execute forever. Pure (signal-safe).
    fn skip_ignore_mirror(linux_signum: i32) -> bool {
        Self::skip_install_routing(linux_signum)
    }

    /// Whether to SKIP `linux_signum` in the execve disposition reset — the gate
    /// `reset_routed_handlers_after_execve` consults. Default = `is_claimed`.
    /// Pure (signal-safe).
    fn skip_execve_reset(linux_signum: i32) -> bool {
        Self::is_claimed(linux_signum)
    }

    /// Whether a host signal carrying `si_code` for guest `linux_signum` is a
    /// SYNCHRONOUS self-fault — a real CPU fault at the faulting PC, i.e. carrick's
    /// OWN bug, which must crash visibly — rather than an async cross-process
    /// `kill` (route to the guest). Default `false`: KVM/bhyve/NVMM guest faults
    /// are vmexits, never host signals. HVF overrides: a fault signum with
    /// `si_code > 0`. Consulted by `shared_routed_handler`. Pure (signal-safe).
    fn is_synchronous_self_fault(_linux_signum: i32, _si_code: i32) -> bool {
        false
    }
}
