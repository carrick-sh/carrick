#!/usr/sbin/dtrace -qs
/*
 * Capture hvpatch AArch64 faults with Linux guest PID/TID/ASID identity.
 *
 * Provider ABI qualified from carrick-observability on macOS 26.0.1 arm64:
 * carrick*:::hvpatch-guest-fault carries scalar CTF types
 * (uint64_t esr, uint64_t elr, uint64_t far, int32_t guest_pid,
 * int32_t guest_tid); hvpatch-guest-fault-asid carries
 * (int32_t guest_pid, int32_t guest_tid, uint32_t asid). The split keeps every
 * probe at five arguments or fewer because macOS zeros arg5. vcpu-fault-regs carries
 * (uint64_t esr, uint64_t elr, uint64_t far, uint64_t insn,
 * uint32_t base_reg, uint64_t base_value). The latter currently fires in the
 * runtime immediately before the process-aware companion; insn=UINT64_MAX and
 * base_reg=UINT32_MAX mean the active address space could not be decoded.
 *
 * Perturbation: fault-only probes. No syscall, VM-exit, or instruction hot path
 * is instrumented. Low-frequency lifecycle/exec markers associate the fault
 * with its image path. Every record carries DTrace's monotonic `timestamp`;
 * output from different CPU buffers is not chronological without it. Zero fault
 * records means the probes did not fire, not that the corresponding fault class
 * was absent.
 */

#pragma D option quiet

dtrace:::BEGIN
{
    started = timestamp;
    faults = 0;
    decoded = 0;
    identities = 0;
    errors = 0;
    bounded = 0;
}

carrick*:::execve-loaded
/pid == $target || progenyof($target)/
{
    self->exec_path = copyinstr(arg0);
}

carrick*:::hvpatch-guest-lifecycle
/(pid == $target || progenyof($target))/
{
    printf("HVPATCH4FAULT|lifecycle|ns=%llu|host_pid=%d|phase=%u|guest_pid=%d|guest_ppid=%d|guest_tid=%d|asid=%u\n",
        timestamp, pid, (uint32_t)arg0, (int)arg1, (int)arg2, (int)arg3,
        (uint32_t)arg4);
    if (arg0 == 2) {
        printf("HVPATCH4FAULT|exec|ns=%llu|host_pid=%d|guest_pid=%d|guest_tid=%d|asid=%u|path=%s\n",
            timestamp, pid, (int)arg1, (int)arg3, (uint32_t)arg4,
            self->exec_path == NULL ? "(unavailable)" : self->exec_path);
        self->exec_path = 0;
    }
}

carrick*:::hvpatch-guest-exit
/pid == $target || progenyof($target)/
{
    printf("HVPATCH4FAULT|exit|ns=%llu|host_pid=%d|guest_pid=%d|guest_tid=%d|asid=%u|status=%d\n",
        timestamp, pid, (int)arg0, (int)arg1, (uint32_t)arg2, (int)arg3);
}

carrick*:::hvpatch-guest-address-space
/pid == $target || progenyof($target)/
{
    printf("HVPATCH4FAULT|address|ns=%llu|host_pid=%d|guest_pid=%d|asid=%u|bank=0x%llx|size=0x%llx|ttbr0=0x%llx\n",
        timestamp, pid, (int)arg0, (uint32_t)arg1, arg2, arg3, arg4);
}

carrick*:::vcpu-fault-regs
/pid == $target || progenyof($target)/
{
    decoded++;
    printf("HVPATCH4FAULT|decode|ns=%llu|host_pid=%d|esr=0x%llx|elr=0x%llx|far=0x%llx|insn=0x%llx|rn=%u|xrn=0x%llx\n",
        timestamp, pid, arg0, arg1, arg2, arg3, (uint32_t)arg4, arg5);
}

carrick*:::hvpatch-guest-fault
/pid == $target || progenyof($target)/
{
    faults++;
    printf("HVPATCH4FAULT|guest|ns=%llu|host_pid=%d|guest_pid=%d|guest_tid=%d|esr=0x%llx|elr=0x%llx|far=0x%llx\n",
        timestamp, pid, (int)arg3, (int)arg4, arg0, arg1, arg2);
}

carrick*:::hvpatch-guest-fault-asid
/pid == $target || progenyof($target)/
{
    identities++;
    printf("HVPATCH4FAULT|identity|ns=%llu|host_pid=%d|guest_pid=%d|guest_tid=%d|asid=%u\n",
        timestamp, pid, (int)arg0, (int)arg1, (uint32_t)arg2);
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
    printf("HVPATCH4FAULT|end|faults=%d|identities=%d|decoded=%d|bounded=%d|errors=%d\n",
        faults, identities, decoded, bounded, errors);
}
