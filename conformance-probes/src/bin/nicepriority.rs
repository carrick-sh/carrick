//! setpriority/getpriority nice-value model (LTP nice02/nice03). carrick had a
//! stateless model: setpriority returned 0 without storing and getpriority
//! always reported nice 0, and an out-of-range nice was rejected EINVAL instead
//! of clamped. Fixed: a persisted per-process nice, clamped to [-20,19], that
//! getpriority reflects. libc getpriority() returns the nice directly (the
//! kernel's `20 - nice` is converted back by the wrapper).
//!
//! The nice04 "non-root nice-lowering → EPERM" leg is NOT probed here: the
//! probe runs privileged (root in docker / guest-root under run-elf), so the
//! lowering succeeds on both sides. LTP nice04 (which drops to nobody) gates it.
//!
//! The last three lines cover the SCOPE of that persisted nice: it belongs to
//! one Linux process, not to the runtime. See the comment at the isolation leg
//! — under HVPatch every logical Linux process shares one host carrier, so a
//! runtime-global cell leaks a dead child's nice into a later unrelated one and
//! every single-process assertion above still passes.

use conformance_probes::errno;

fn main() {
    unsafe {
        // Every leg below only ever INCREASES nice (lowers priority), which is
        // allowed without CAP_SYS_NICE. That ordering is load-bearing: Docker's
        // default cap set drops CAP_SYS_NICE even for root, so any leg that
        // needed a nice DECREASE would fail EACCES on the ORACLE while
        // succeeding under carrick's full-cap guest root, and the probe would
        // read as a carrick DIFF (the under-privileged-oracle trap, AGENTS.md;
        // exactly what happened when the clamp leg ran before the isolation
        // legs and left the parent at 19 with 7 unreachable).

        // set nice 2 → getpriority reports 2.
        let s2 = libc::setpriority(libc::PRIO_PROCESS, 0, 2);
        println!("set_nice_2_ok={}", s2 == 0);
        *libc::__errno_location() = 0;
        println!(
            "get_nice_is_2={}",
            libc::getpriority(libc::PRIO_PROCESS, 0) == 2 && errno() == 0
        );

        // ---- nice is PER-PROCESS state, not one value shared by every guest
        // process in the runtime.
        //
        // Linux gives each process its own nice, inherited from its parent at
        // fork and independent thereafter. An emulator that keeps ONE nice cell
        // for the whole runtime passes every single-process check above and
        // still gets this wrong, because under HVPatch many logical Linux
        // processes share one host carrier — so a dead child's nice leaks into
        // an unrelated later child.
        //
        // The discriminator has to be a READ, not a privilege gate: this probe
        // cannot rely on EACCES arms (see the cap note above), so both values
        // below are PRINTED and the line-exact diff compares the numbers Linux
        // actually produces rather than a boolean a shared cell can satisfy by
        // accident. 7 (parent) versus 19 (child A) keeps the two models
        // distinguishable.
        libc::setpriority(libc::PRIO_PROCESS, 0, 7);
        let parent_nice = libc::getpriority(libc::PRIO_PROCESS, 0);
        println!("isolation_parent_nice={parent_nice}");

        // Child A raises itself to 19 (nice increase, unprivileged) and exits.
        // Under a per-process model that write dies with it.
        let pid_a = libc::fork();
        if pid_a == 0 {
            libc::setpriority(libc::PRIO_PROCESS, 0, 19);
            libc::_exit(0);
        }
        let mut status_a = -1;
        let reaped_a = pid_a > 0 && libc::waitpid(pid_a, &mut status_a, 0) == pid_a;
        println!(
            "isolation_child_a_exited_0={}",
            reaped_a && libc::WIFEXITED(status_a) && libc::WEXITSTATUS(status_a) == 0
        );

        // Child B only READS. It must see the parent's nice (7), inherited at
        // fork — never child A's 19. A runtime-global cell reports 19 here.
        // Encode nice ([-20,19]) as an exit status by biasing +20 (0..=39).
        let pid_b = libc::fork();
        if pid_b == 0 {
            let seen = libc::getpriority(libc::PRIO_PROCESS, 0);
            libc::_exit(seen + 20);
        }
        let mut status_b = -1;
        let reaped_b = pid_b > 0 && libc::waitpid(pid_b, &mut status_b, 0) == pid_b;
        if reaped_b && libc::WIFEXITED(status_b) {
            println!(
                "isolation_child_b_nice={}",
                libc::WEXITSTATUS(status_b) - 20
            );
        } else {
            // Never silently print a plausible number: a failed fork/reap is a
            // broken probe, not a passing one.
            println!("isolation_child_b_nice=unreaped");
        }

        // nice 50 is out of range → Linux CLAMPS to 19 and succeeds (no
        // EINVAL). 7 → 19 is still an increase, so this stays privilege-free —
        // which is why the clamp leg runs LAST.
        let s50 = libc::setpriority(libc::PRIO_PROCESS, 0, 50);
        println!("set_nice_50_ok={}", s50 == 0);
        *libc::__errno_location() = 0;
        println!(
            "get_nice_clamped_19={}",
            libc::getpriority(libc::PRIO_PROCESS, 0) == 19 && errno() == 0
        );

        // getpriority with an invalid `which` → EINVAL.
        *libc::__errno_location() = 0;
        let bad = libc::getpriority(99, 0);
        println!(
            "getpriority_bad_which_einval={}",
            bad == -1 && errno() == libc::EINVAL
        );

        let _ = errno;
    }
}
