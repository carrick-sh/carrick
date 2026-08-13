//! `WCOREDUMP` and the core file must agree: a kernel that sets the bit has
//! written a dump.
//!
//! Linux sets `WCOREDUMP(status)` only when it ACTUALLY produced a core.
//! carrick's `core_dumped_si_code` (`dispatch/proc.rs`) sets it whenever the
//! terminating signal is a core-dumping one and `RLIMIT_CORE` is nonzero, and
//! then writes no file — so a guest is told a core exists when none does. The
//! ELF core writer (`carrick-runtime/src/core_dump.rs`) and its validator
//! (`carrick debug core`) are both landed; only the crash-path wiring is
//! missing, and this probe is what will show when it arrives.
//!
//! The honest fix is to WRITE the dump, not to stop setting the bit: Docker
//! sets it, so clearing it would trade one divergence for another.
//!
//! The probe raises `RLIMIT_CORE` itself rather than assuming the ambient
//! limit — containers commonly ship `ulimit -c 0`, under which Linux correctly
//! reports no dump and the interesting case never runs. It also reports the
//! ambient `core_pattern`, because a pattern that pipes to a helper legitimately
//! leaves no file in the cwd; the file assertion is only meaningful when the
//! pattern is a plain relative name, so that condition is reported as its own
//! line and the comparison is made against it.
//!
//! Every line is a boolean, so the output is line-exact on any machine.

use conformance_probes::report;

/// Read `/proc/sys/kernel/core_pattern`, trimmed. Empty on failure.
fn core_pattern() -> String {
    std::fs::read_to_string("/proc/sys/kernel/core_pattern")
        .unwrap_or_default()
        .trim()
        .to_string()
}

/// A plain relative filename — no pipe, no directory, no format escapes that
/// would place the core somewhere other than the cwd.
fn pattern_is_plain_file(pattern: &str) -> bool {
    !pattern.is_empty()
        && !pattern.starts_with('|')
        && !pattern.starts_with('/')
        && !pattern.contains('%')
}

fn any_core_file_in(dir: &str, pattern: &str) -> bool {
    if std::path::Path::new(dir).join(pattern).exists() {
        return true;
    }
    // Some kernels append `.<pid>` even for a plain pattern.
    std::fs::read_dir(dir).is_ok_and(|entries| {
        entries.flatten().any(|entry| {
            entry
                .file_name()
                .to_string_lossy()
                .starts_with(&format!("{pattern}."))
        })
    })
}

fn main() {
    unsafe {
        let dir = "/tmp/coredumpfile";
        let _ = std::fs::remove_dir_all(dir);
        let made_dir = std::fs::create_dir_all(dir).is_ok();
        let chdir_ok = std::env::set_current_dir(dir).is_ok();

        // Raise RLIMIT_CORE: the ambient limit is 0 in most containers, and
        // under that Linux correctly writes nothing, so the divergence this
        // probe exists for would never be exercised.
        let limit = libc::rlimit {
            rlim_cur: 64 * 1024 * 1024,
            rlim_max: 64 * 1024 * 1024,
        };
        let raised = libc::setrlimit(libc::RLIMIT_CORE, &limit) == 0;

        let pattern = core_pattern();
        let plain = pattern_is_plain_file(&pattern);

        let child = libc::fork();
        if child == 0 {
            // Dereference null: SIGSEGV, a core-dumping signal on every Unix.
            let p: *mut u64 = std::ptr::null_mut();
            std::ptr::write_volatile(p, 1);
            libc::_exit(0);
        }
        let mut status: libc::c_int = 0;
        let reaped = child > 0 && libc::waitpid(child, &mut status, 0) == child;
        let signaled = libc::WIFSIGNALED(status);
        let by_sigsegv = signaled && libc::WTERMSIG(status) == libc::SIGSEGV;
        let core_bit = signaled && (status & 0x80) != 0;

        // Give a kernel that writes the dump asynchronously a moment to land it
        // before concluding it did not. Linux writes it before the parent's
        // `waitpid` returns, so this is belt-and-braces, not a race the result
        // depends on.
        let file_present = any_core_file_in(dir, if plain { &pattern } else { "core" });

        report!(
            made_dir = made_dir,
            chdir_ok = chdir_ok,
            raised_rlimit_core = raised,
            reaped = reaped,
            // Decomposed rather than folded into one line: a bare
            // `child_died_of_sigsegv=false` cannot distinguish "the store to
            // NULL did not fault at all" — which would be a far more serious
            // guest-memory bug than a missing core — from "it faulted with the
            // wrong signal". Each is its own observation.
            child_was_signaled = signaled,
            child_exited_normally = libc::WIFEXITED(status),
            child_exit_status_zero = libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0,
            child_died_of_sigsegv = by_sigsegv,
            // Linux: true — SIGSEGV with a nonzero RLIMIT_CORE dumps.
            wcoredump_set = core_bit,
            // Reported so the assertion below is interpretable rather than a
            // bare environment difference.
            core_pattern_is_plain_file = plain,
            // THE ASSERTION. When the pattern is a plain filename and the
            // kernel says it dumped, the file must be there. carrick sets the
            // bit and writes nothing, so this is false until the crash path is
            // wired to the ELF core writer.
            core_file_exists_when_bit_set = !(plain && core_bit) || file_present,
        );
    }
}
