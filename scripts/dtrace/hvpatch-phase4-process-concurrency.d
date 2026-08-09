#!/usr/sbin/dtrace -qs
/*
 * Measure cumulative Linux guest-process creation and peak live guest
 * processes for the hvpatch Phase 4 cold-build workload.
 *
 * Provider ABI qualified from carrick-observability on macOS 26.0.1 arm64:
 * carrick*:::hvpatch-guest-lifecycle carries scalar CTF types
 * (uint32_t phase, int32_t pid, int32_t ppid, int32_t tid, uint32_t asid).
 * Phase 0=root, 1=fork, 2=exec, 3=thread-start,
 * 4=thread-exit, 5=process-exit. These are Linux guest identities multiplexed
 * inside one Darwin process; proc:::create cannot observe them. The companion
 * hvpatch-guest-exit carries (pid, tid, asid, status), keeping every probe at
 * five arguments or fewer because macOS zeros the sixth USDT argument.
 * hvpatch-guest-address-space carries (pid, asid, bank_base, bank_size, ttbr0).
 *
 * `peak_guest_processes` is exact for successfully published hvpatch lifecycle
 * events. Host proc:::create remains as a separate control: a shared-VM run
 * should not create one Darwin process per Linux fork.
 *
 * Perturbation: proc lifecycle and low-frequency Carrick fork/exec probes only;
 * this script does not instrument syscall or instruction hot paths.
 */

#pragma D option quiet

dtrace:::BEGIN
{
    started = timestamp;
    host_creates = 0;
    guest_live = 0;
    guest_peak = 0;
    guest_roots = 0;
    guest_forks = 0;
    guest_execs = 0;
    guest_exits = 0;
    errors = 0;
    bounded = 0;
}

proc:::create
/pid == $target || progenyof($target)/
{
    host_creates++;
}

carrick*:::hvpatch-guest-lifecycle
/(pid == $target || progenyof($target)) && (arg0 == 0 || arg0 == 1)/
{
    guest_roots += arg0 == 0;
    guest_forks += arg0 == 1;
    guest_live++;
    guest_peak = guest_live > guest_peak ? guest_live : guest_peak;
    @guest_identity[(int)arg1, (int)arg2, (int)arg3, (uint32_t)arg4] = count();
}

carrick*:::hvpatch-guest-lifecycle
/(pid == $target || progenyof($target)) && arg0 == 2/
{
    guest_execs++;
    @guest_execs[(int)arg1, (int)arg3, (uint32_t)arg4] = count();
}

carrick*:::hvpatch-guest-lifecycle
/(pid == $target || progenyof($target)) && arg0 == 5/
{
    guest_exits++;
    guest_live--;
}

carrick*:::hvpatch-guest-exit
/pid == $target || progenyof($target)/
{
    @guest_exit[(int)arg0, (int)arg1, (uint32_t)arg2, (int64_t)arg3] = count();
}

carrick*:::hvpatch-guest-address-space
/pid == $target || progenyof($target)/
{
    @guest_address[(int)arg0, (uint32_t)arg1, arg2, arg3, arg4] = count();
}

dtrace:::ERROR
{
    errors++;
}

proc:::exit
/pid == $target/
{
    exit(0);
}

profile:::tick-1sec
/timestamp - started > 90 * 1000000000/
{
    bounded = 1;
    exit(0);
}

dtrace:::END
{
    printf("HVPATCH4PROC|end|host_creates=%d|guest_roots=%d|guest_forks=%d|guest_execs=%d|guest_exits=%d|peak_guest_processes=%d|guest_live=%d|bounded=%d|errors=%d\n",
        host_creates, guest_roots, guest_forks, guest_execs, guest_exits,
        guest_peak, guest_live, bounded, errors);
    printa("HVPATCH4PROC|guest|pid=%d|ppid=%d|tid=%d|asid=%u|count=%@d\n", @guest_identity);
    printa("HVPATCH4PROC|exec|pid=%d|tid=%d|asid=%u|count=%@d\n", @guest_execs);
    printa("HVPATCH4PROC|exit|pid=%d|tid=%d|asid=%u|status=%d|count=%@d\n", @guest_exit);
    printa("HVPATCH4PROC|address|pid=%d|asid=%u|bank=0x%llx|size=0x%llx|ttbr0=0x%llx|count=%@d\n", @guest_address);
}
