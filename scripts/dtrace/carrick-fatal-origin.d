/*
 * carrick-fatal-origin.d — name the code path that aborted the runtime.
 *
 * WHAT IT MEASURES
 *   The user stack at the moment `carrick_fatal::fatal` is entered, plus the
 *   aborting thread's id. A `carrick fatal [domain]: message` line on stderr
 *   names WHAT invariant was violated but never WHO violated it, and the
 *   abort path takes no core on macOS: the shipped binary is codesigned with
 *   the hypervisor entitlement and a hardened runtime, so `ulimit -c
 *   unlimited` yields nothing in /cores. This script is the replacement for
 *   that missing core, and it needs nothing pre-armed on the tracee.
 *
 * PROVIDER ABI FACTS, qualified live on macOS 27 / Apple Silicon:
 *   - `carrick_fatal::fatal` is a real, non-inlined symbol in the release
 *     binary: `__ZN13carrick_fatal5fatal17h<hash>E`. The hash changes on
 *     every build, so the probe matches `carrick_fatal*fatal*` rather than an
 *     exact name. It is reached through the `carrick_fatal!` macro from every
 *     domain, so one probe covers them all.
 *   - `pid$target` needs the process to exist, so run this through
 *     `carrick trace`, which launches the guest under the probe, or with
 *     `-Z` against a run you start separately.
 *   - `ustack()` does NOT symbolicate the hardened, entitled carrick binary on
 *     this host: every frame comes back as a bare address. Symbolicate them
 *     offline instead, with the `__TEXT` base this script prints from
 *     `carrick*:::host-image-base(host_pid, runtime_TEXT_base, slide, path)`,
 *     which fires once per carrier before any guest instruction runs:
 *         atos -o target/release/carrick -l <text_base> <addr> ...
 *     Keep Apple `ld64` (AGENTS Rule 0) or the DOF section, and with it every
 *     `carrick*:::` probe including the image-base record, disappears.
 *   - The runtime holds a spin lock across a second fatal, so the same abort
 *     can print two stacks (the inner `format_fatal_parts` frame differs).
 *     Read the LAST record: it is the one that reached `abort()`.
 *
 * PERTURBATION
 *   None worth declaring: the probe fires exactly once, on a path that is
 *   already about to call `abort()`.
 *
 * USAGE
 *   carrick trace -s scripts/dtrace/carrick-fatal-origin.d -- \
 *       run <image> <cmd>
 */

#pragma D option quiet
#pragma D option ustackframes=60
#pragma D option destructive

carrick*:::host-image-base
/pid == $target || progenyof($target)/
{
    printf("CARRICKFATAL|image|host_pid=%d|text_base=0x%llx|slide=0x%llx\n",
        (int)arg0, (uint64_t)arg1, (uint64_t)arg2);
}

pid$target::*carrick_fatal*fatal*:entry
{
    printf("CARRICKFATAL|thread=%d|time=%llu\n", tid, (unsigned long long)timestamp);
    ustack();
    printf("CARRICKFATAL|end\n");
}

/*
 * A fatal is terminal, so the interesting window closes the moment the stack
 * above is printed. Bound the session so a trace can never outlive the run it
 * was capturing (`--require-script-exit` then gets its terminal receipt).
 */
tick-120s
{
    exit(0);
}
