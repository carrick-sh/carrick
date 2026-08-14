#!/usr/sbin/dtrace -qs
/*
 * Attribute an HVPatch high-VA alias install and its first guest fault.
 *
 * Provider ABI qualified from carrick-observability on macOS 26.0.1 arm64:
 * carrick*:::hv-vm-map-alias carries (uint64_t va, uint64_t ipa,
 * uint64_t size, int32_t rc, int32_t forked); pt-alias-walk carries the VA,
 * four scalar long-descriptor values, and an int32_t flag (bit0 forked child,
 * bit1 walk failure, bit2 authoritative host backing); pt-fault-walk carries
 * (uint64_t far, uint64_t l0, uint64_t l1, uint64_t l2, uint64_t l3), and
 * pt-fault-ttbr carries (uint64_t far, uint64_t ttbr0). vcpu-fault-regs
 * carries (uint64_t esr, uint64_t elr, uint64_t far, uint64_t insn,
 * uint32_t base_reg, uint64_t base_value); hvpatch-guest-address-space carries
 * (int32_t guest_pid, uint32_t asid, uint64_t bank, uint64_t size,
 * uint64_t ttbr0). syscall-return arg0 is the canonical Linux syscall number,
 * arg2 the return value, and arg3 errno; AArch64 mmap/munmap/mprotect are
 * 222/215/226.
 *
 * Perturbation: alias-map, fault-only, process-lifecycle, and three selected
 * syscall-return probe. No instruction or VM-exit hot path is instrumented.
 * Zero alias-map or fault events is an error in a capture meant to reproduce
 * the first-write failure, never evidence that the operation did not happen.
 */

#pragma D option quiet

dtrace:::BEGIN
{
    started = timestamp;
    maps = 0;
    faults = 0;
    errors = 0;
    bounded = 0;
}

carrick*:::hvpatch-guest-address-space
/pid == $target || progenyof($target)/
{
    printf("HVPATCHALIAS|address|ns=%llu|host_pid=%d|guest_pid=%d|asid=%u|bank=0x%llx|size=0x%llx|ttbr0=0x%llx\n",
        timestamp, pid, (int)arg0, (uint32_t)arg1, arg2, arg3, arg4);
}

carrick*:::syscall-return
/(pid == $target || progenyof($target)) &&
    (arg0 == 222 || arg0 == 215 || arg0 == 226)/
{
    printf("HVPATCHALIAS|syscall|ns=%llu|host_pid=%d|nr=%llu|ret=%lld|errno=%d\n",
        timestamp, pid, (uint64_t)arg0, (int64_t)arg2, (int)arg3);
}

carrick*:::hv-vm-map-alias
/pid == $target || progenyof($target)/
{
    maps++;
    printf("HVPATCHALIAS|map|ns=%llu|host_pid=%d|va=0x%llx|ipa=0x%llx|size=0x%llx|rc=%d|forked=%d\n",
        timestamp, pid, arg0, arg1, arg2, (int)arg3, (int)arg4);
}

carrick*:::pt-alias-walk
/pid == $target || progenyof($target)/
{
    printf("HVPATCHALIAS|walk|ns=%llu|host_pid=%d|va=0x%llx|l0=0x%llx|l1=0x%llx|l2=0x%llx|l3=0x%llx|flag=%d\n",
        timestamp, pid, arg0, arg1, arg2, arg3, arg4, (int)arg5);
}

carrick*:::pt-fault-walk
/pid == $target || progenyof($target)/
{
    printf("HVPATCHALIAS|fault_walk|ns=%llu|host_pid=%d|far=0x%llx|l0=0x%llx|l1=0x%llx|l2=0x%llx|l3=0x%llx\n",
        timestamp, pid, arg0, arg1, arg2, arg3, arg4);
}

carrick*:::pt-fault-ttbr
/pid == $target || progenyof($target)/
{
    printf("HVPATCHALIAS|fault_ttbr|ns=%llu|host_pid=%d|far=0x%llx|ttbr0=0x%llx\n",
        timestamp, pid, arg0, arg1);
}

carrick*:::vcpu-fault-regs
/pid == $target || progenyof($target)/
{
    faults++;
    printf("HVPATCHALIAS|fault|ns=%llu|host_pid=%d|esr=0x%llx|elr=0x%llx|far=0x%llx|insn=0x%llx|rn=%u|xrn=0x%llx\n",
        timestamp, pid, arg0, arg1, arg2, arg3, (uint32_t)arg4, arg5);
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
    printf("HVPATCHALIAS|end|maps=%d|faults=%d|bounded=%d|errors=%d\n",
        maps, faults, bounded, errors);
}
