#!/usr/sbin/dtrace -Zqs
/*
 * hvpatch-exit-attribution.d — where does a real HVPatch workload leave the
 * guest, how often, and how much host CPU does each kind of exit cost?
 *
 * (a) WHAT IT MEASURES
 * --------------------
 * For one traced `carrick run` (the CLI and its carrier descendants):
 *
 *   1. Host exits by class. Every `hv_vcpu_run` return fires `vcpu-run-exit`
 *      at the one site that also bumps the carrier's exhaustive
 *      `vcpu_run_exit_classes()` counters, with the same
 *      `carrick_el1_abi::HostExitClass` ordinal. The Rust reader folds the
 *      eight classes into the four buckets the EL1 ranking asks about:
 *      syscall (3), fault (6), kick/idle (0 canceled, 1 idle, 2 kick) and
 *      other (4 metadata, 5 maintenance, 7 other). Class 3 is every
 *      `hvc #2` return, and the EL1 vector also forwards EL0 aborts and
 *      sys64 traps through `hvc #2`; `vcpu-hvc-not-svc` names those, and the
 *      reader moves aborts (EC 0x20/0x21/0x24/0x25) into fault and the rest
 *      (sys64 MRS emulation, ...) into other.
 *   2. Guest-vs-host time on the executor threads. `vcpu-run-enter` /
 *      `vcpu-run-exit` bracket each `hv_vcpu_run` on the same host thread:
 *      `vtimestamp` inside the bracket is on-CPU guest time (EL0 plus any EL1
 *      service the guest kernel did without exiting), `timestamp` the wall
 *      time. The on-CPU time from one exit to the same thread's next enter is
 *      host service charged to the class of the exit that started it. Time a
 *      thread spends parked (blocked syscall, idle) is off-CPU and is not in
 *      either number. Carrier threads that never run a vCPU (reactor,
 *      supervisor) are NOT covered; `hvpatch-carrier-cpu-attribution` is the
 *      whole-carrier sampled split.
 *   3. Forwarded syscalls by Linux number. `hvpatch-syscall-service-begin`
 *      fires once per host-serviced syscall (EL1-served syscalls never reach
 *      it), so its histogram is exactly the host-forwarded population. The
 *      matching `hvpatch-syscall-service` adds its monotonic duration (wall,
 *      including blocking) and, when it closes on the same host thread, the
 *      on-CPU host time of the service.
 *
 * (b) PROVIDER ABI (carrick USDT, crates/carrick-observability/src/probes.rs)
 * --------------------
 *   vcpu-run-enter (u64 vcpu)                        — before hv_vcpu_run
 *   vcpu-run-exit  (u64 vcpu, u32 class, u64 esr)    — after each return
 *   vcpu-hvc-not-svc (u64 el1_esr)                   — the hvc #2 exit just
 *                       reported as class 3 carried a non-svc EL0 exception
 *   hvpatch-syscall-service-begin (i32 pid, i32 tid, u32 asid, u64 nr)
 *   hvpatch-syscall-service (i32 pid, i32 tid, u32 asid, u64 nr, u64 dur_ns)
 *   The two vcpu-run probes were added with this script (2026-10-01); a
 *   binary built before them matches zero probes under -Z and this program
 *   then reports saw_enter=0, which the reader refuses (zero events = the
 *   probe did not fire, never "no exits").
 *
 * TARGETING: `pid == $target || progenyof($target)` under `dtrace -Z`: the
 * carrier is a child of the traced CLI, and `carrick trace` arms probes of
 * processes not yet started.
 *
 * BOUND: ends on the target CLI's own exit. The capture bound (90 s shipped
 * default; `carrick trace --profile-bound-seconds` overrides it for go build)
 * is a safety net: a bounded capture reports bounded=1 and is refused.
 *
 * (c) PERTURBATION
 * --------------------
 * HIGH on exit-dense workloads: two USDT fires and three aggregation updates
 * per guest exit, plus two fires per forwarded syscall. Counts and class
 * shares are citable; absolute times under this script are inflated by the
 * probe cost charged to the host side of each exit (vtimestamp subtracts
 * DTrace's own probe time, the trampoline entry/exit is not). NEVER cite wall
 * or CPU time from an attribution run as a timing result: timing runs are the
 * uninstrumented arms in scripts/perf/el1_workload_ab.py.
 */

#pragma D option quiet
#pragma D option zdefs
#pragma D option bufsize=16m
#pragma D option aggsize=32m
#pragma D option dynvarsize=64m

self uint64_t run_vts;
self uint64_t run_ts;
self uint64_t exit_vts;
self uint32_t exit_class;
self uint64_t svc_vts;
self uint64_t svc_nr;

dtrace:::BEGIN
{
    /* Replaced by the Rust profile launcher with the immutable template hash. */
    printf("HVPEXIT1|header|version=1|program_sha256=/* CARRICK_HVPEXIT_PROGRAM_SHA256 */\n");
    root_exited = 0;
    bounded = 0;
    errors = 0;
    saw_enter = 0;
    saw_exit = 0;
    saw_service = 0;
    bound_elapsed_s = (uint64_t)0;
    bound_limit_s = (uint64_t)90;

    /*
     * The declared capture bound. Left as the shipped default when
     * unrendered so the bundled template stays a legal D program; the
     * summary reports whichever bound was in force.
     */
    /* CARRICK_HVPEXIT_BOUND */
}

/*
 * Host service since this thread's previous exit. Must precede the enter
 * clause below, which re-arms the thread-local state it reads.
 */
carrick*:::vcpu-run-enter
/(pid == $target || progenyof($target)) && self->exit_vts != 0/
{
    @host_vns[self->exit_class] = sum(vtimestamp - self->exit_vts);
    self->exit_vts = 0;
}

carrick*:::vcpu-run-enter
/pid == $target || progenyof($target)/
{
    saw_enter = 1;
    @enters = count();
    self->run_vts = vtimestamp;
    self->run_ts = timestamp;
}

/* An exit with no enter on this thread: tracing attached mid-run. */
carrick*:::vcpu-run-exit
/(pid == $target || progenyof($target)) && self->run_vts == 0/
{
    @unpaired = count();
}

carrick*:::vcpu-run-exit
/(pid == $target || progenyof($target)) && self->run_vts != 0/
{
    saw_exit = 1;
    @exits[(uint32_t)arg1] = count();
    @guest_vns[(uint32_t)arg1] = sum(vtimestamp - self->run_vts);
    @guest_wall_ns[(uint32_t)arg1] = sum(timestamp - self->run_ts);
    self->run_vts = 0;
    self->run_ts = 0;
    self->exit_vts = vtimestamp;
    self->exit_class = (uint32_t)arg1;
}

/*
 * The hvc #2 exit just counted as class 3 was an EL0 exception other than
 * svc. Count it by EL0 exception class and re-key this thread's pending host
 * time to 64 + EC, so the reader can move it out of the syscall bucket.
 */
carrick*:::vcpu-hvc-not-svc
/(pid == $target || progenyof($target)) && self->exit_vts != 0/
{
    @not_svc[(uint32_t)((arg0 >> 26) & 0x3f)] = count();
    self->exit_class = (uint32_t)(64 + ((arg0 >> 26) & 0x3f));
}

carrick*:::hvpatch-syscall-service-begin
/pid == $target || progenyof($target)/
{
    saw_service = 1;
    @fwd[(uint64_t)arg3] = count();
    self->svc_vts = vtimestamp;
    self->svc_nr = (uint64_t)arg3 + 1;
}

carrick*:::hvpatch-syscall-service
/(pid == $target || progenyof($target)) && self->svc_nr == (uint64_t)arg3 + 1/
{
    @fwd_paired[(uint64_t)arg3] = count();
    @fwd_oncpu_vns[(uint64_t)arg3] = sum(vtimestamp - self->svc_vts);
    self->svc_vts = 0;
    self->svc_nr = 0;
}

carrick*:::hvpatch-syscall-service
/pid == $target || progenyof($target)/
{
    @fwd_ended[(uint64_t)arg3] = count();
    @fwd_wall_ns[(uint64_t)arg3] = sum((uint64_t)arg4);
}

dtrace:::ERROR
{
    errors++;
    printf("HVPEXIT1|error|epid=%d|action=%d|offset=%d|fault=%d|value=%#x\n",
        arg1, arg2, arg3, arg4, arg5);
    exit(3);
}

proc:::exit
/pid == $target/
{
    root_exited = 1;
    exit(saw_enter && saw_exit && saw_service && errors == 0 ? 0 : 1);
}

tick-10s
{
    bound_elapsed_s += (uint64_t)10;
}

tick-10s
/bound_elapsed_s >= bound_limit_s/
{
    bounded = 1;
    exit(4);
}

dtrace:::END
{
    printf("HVPEXIT1|summary|status=%s|root_exited=%d|bounded=%d|errors=%d|saw_enter=%d|saw_exit=%d|saw_service=%d|bound_s=%d\n",
        root_exited && !bounded && errors == 0 && saw_enter && saw_exit && saw_service
            ? "ok" : "error",
        root_exited, bounded, errors, saw_enter, saw_exit, saw_service,
        bound_limit_s);
    printa("HVPEXIT1|enters|count=%@u\n", @enters);
    printa("HVPEXIT1|unpaired-exits|count=%@u\n", @unpaired);
    printa("HVPEXIT1|exit|class=%u|count=%@u|guest_vns=%@u|guest_wall_ns=%@u\n",
        @exits, @guest_vns, @guest_wall_ns);
    printa("HVPEXIT1|hvc-not-svc|ec=%u|count=%@u\n", @not_svc);
    printa("HVPEXIT1|host-after-exit|class=%u|vns=%@u\n", @host_vns);
    printa("HVPEXIT1|forwarded|nr=%u|count=%@u|ended=%@u|wall_ns=%@u|paired=%@u|oncpu_vns=%@u\n",
        @fwd, @fwd_ended, @fwd_wall_ns, @fwd_paired, @fwd_oncpu_vns);
    printf("HVPEXIT1|end\n");
}
