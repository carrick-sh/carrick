/*
 * Targeted native FreeBSD/x86 guest-PC observations.
 *
 * Set CARRICK_NATIVE_X86_TRACE_PC to one guest virtual address, or a
 * comma-separated list, before running carrick trace. The runtime fires only
 * when a gateway entry/resolution/xstate edge matches, avoiding a probe on
 * every block. For a controlled xstate bisect, CARRICK_NATIVE_X86_EDGE_BARRIER
 * accepts `all`, a source PC, or `source->target`; the selected edge remains
 * cold. CARRICK_NATIVE_X86_XSTATE_POLICY=unsafe-local-diagnostic deliberately
 * clobbers skipped local entries. neutral-domains is the guarded experimental
 * policy; unsafe-target-barrier-diagnostic is its compatibility spelling for
 * reproducing the rejected experiment.
 *
 * Usage:
 *   CARRICK_NATIVE_X86_TRACE_PC=0x60004b1d50 \
 *     carrick trace --script scripts/dtrace/native-x86-pc.d -- run ...
 */
#pragma D option quiet
#pragma D option bufsize=8m

dtrace:::BEGIN
{
    printf("native x86 targeted-PC trace started at %Y target=%d\n",
        walltimestamp, $target);
}

carrick*:::native-x86-pc
/pid == $target || progenyof($target)/
{
    printf("%Y [%d PC] hostpid=%d pc=%#x rsp=%#x rdi=%#x rbp=%#x stack0=%#x\n",
        walltimestamp, pid, (int)arg0, arg1, arg2, arg3, arg4, arg5);
}

carrick*:::native-x86-resolve
/pid == $target || progenyof($target)/
{
    printf("%Y [%d RESOLVE] hostpid=%d source=%#x target=%#x rsp=%#x rdi=%#x rbp=%#x\n",
        walltimestamp, pid, (int)arg0, arg1, arg2, arg3, arg4, arg5);
}

carrick*:::native-x86-xstate-edge
/pid == $target || progenyof($target)/
{
    printf("%Y [%d XEDGE] hostpid=%d source=%#x target=%#x event=%d flags=%#x src_fpu=%d dst_fpu=%d edges=%d save=%d hit=%d unsafe_local=%d target_barrier=%d xbv=%#x\n",
        walltimestamp, pid, (int)arg0, arg1, arg2, arg3, arg4,
        arg4 & 1, (arg4 >> 1) & 1, (arg4 >> 2) & 1,
        (arg4 >> 3) & 1, (arg4 >> 4) & 1, (arg4 >> 5) & 1,
        (arg4 >> 6) & 1, arg5);
}

carrick*:::native-x86-xstate-controls
/pid == $target || progenyof($target)/
{
    printf("%Y [%d XCTRL] hostpid=%d source=%#x fcw=%#x mxcsr=%#x pkru=%#x ext=%#x\n",
        walltimestamp, pid, (int)arg0, arg1, arg2, arg3, arg4, arg5);
}

carrick*:::native-x86-xstate-hashes
/pid == $target || progenyof($target)/
{
    printf("%Y [%d XHASH] hostpid=%d source=%#x legacy=%#x ymm=%#x opmask_zmm=%#x ext=%#x\n",
        walltimestamp, pid, (int)arg0, arg1, arg2, arg3, arg4, arg5);
}

carrick*:::native-x86-fault
/pid == $target || progenyof($target)/
{
    printf("%Y [%d FAULT] hostpid=%d pc=%#x addr=%#x rsp=%#x rcx=%#x rflags=%#x\n",
        walltimestamp, pid, (int)arg0, arg1, arg2, arg3, arg4, arg5);
}

carrick*:::native-x86-fault-regs
/pid == $target || progenyof($target)/
{
    printf("%Y [%d REGS ] hostpid=%d rax=%#x rdx=%#x rdi=%#x rsi=%#x r8=%#x\n",
        walltimestamp, pid, (int)arg0, arg1, arg2, arg3, arg4, arg5);
}

carrick*:::native-x86-fault-stack
/pid == $target || progenyof($target)/
{
    printf("%Y [%d STACK] hostpid=%d q3=%#x q4=%#x q6=%#x q7=%#x rbp=%#x\n",
        walltimestamp, pid, (int)arg0, arg1, arg2, arg3, arg4, arg5);
}

carrick*:::native-x86-fault-history
/pid == $target || progenyof($target)/
{
    printf("%Y [%d HIST ] hostpid=%d pcs=%#x,%#x,%#x,%#x,%#x\n",
        walltimestamp, pid, (int)arg0, arg1, arg2, arg3, arg4, arg5);
}

proc:::exit
/pid == $target/
{
    exit(0);
}

tick-1s
{
    seconds++;
}

tick-1s
/seconds >= 180/
{
    printf("native x86 targeted-PC trace reached 180-second bound\n");
    exit(0);
}
