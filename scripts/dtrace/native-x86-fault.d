/*
 * Native FreeBSD/x86 exec and fatal-fault state.
 *
 * Usage:
 *   carrick trace --script scripts/dtrace/native-x86-fault.d -- run ...
 *
 * Pair the two fault lines by host pid. Payloads are scalar so the record
 * survives a fork child exiting immediately after the probe fires.
 */
#pragma D option quiet
#pragma D option strsize=1024
#pragma D option bufsize=16m

dtrace:::BEGIN
{
    printf("native x86 exec/fault trace started at %Y target=%d\n",
        walltimestamp, $target);
}

carrick*:::execve-argv
/pid == $target || progenyof($target)/
{
    printf("%Y [%d exec] hostpid=%d path=%s argv=%s\n",
        walltimestamp, pid, (int)arg0, copyinstr(arg1), copyinstr(arg2));
}

carrick*:::execve-loaded
/pid == $target || progenyof($target)/
{
    printf("%Y [%d loaded] path=%s entry=%#x sp=%#x maps=%d\n",
        walltimestamp, pid, copyinstr(arg0), arg1, arg2, (int)arg3);
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
