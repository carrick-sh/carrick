#pragma D option quiet
#pragma D option strsize=256
#pragma D option bufsize=64m
#pragma D option switchrate=10ms

/*
 * Full-width guest memory syscall trace. Useful when 32-bit-looking sentinel
 * values such as 0xffffffff need to be distinguished from Linux's sign-extended
 * errno/MAP_FAILED values.
 */

carrick*:::syscall-entry
/(pid == $target || progenyof($target)) &&
    (arg0 == 222 || arg0 == 215 || arg0 == 216 || arg0 == 226 || arg0 == 233)/
{
    self->mm_args = (uint64_t *)copyin(arg2, 48);
    self->mm_nr = arg0;
    self->mm_a0 = self->mm_args[0];
    self->mm_a1 = self->mm_args[1];
    self->mm_a2 = self->mm_args[2];
    self->mm_a3 = self->mm_args[3];
    self->mm_a4 = self->mm_args[4];
    self->mm_a5 = self->mm_args[5];
    printf("[%d/%d entry] nr=%d args=[0x%llx,0x%llx,0x%llx,0x%llx,0x%llx,0x%llx]\n",
        pid, tid, (int)arg0,
        (unsigned long long)self->mm_args[0],
        (unsigned long long)self->mm_args[1],
        (unsigned long long)self->mm_args[2],
        (unsigned long long)self->mm_args[3],
        (unsigned long long)self->mm_args[4],
        (unsigned long long)self->mm_args[5]);
}

carrick*:::syscall-return
/(pid == $target || progenyof($target)) &&
    (arg0 == 222 || arg0 == 215 || arg0 == 216 || arg0 == 226 || arg0 == 233)/
{
    printf("[%d/%d ret  ] nr=%d ret=0x%llx errno=%d entry_nr=%d entry_args=[0x%llx,0x%llx,0x%llx,0x%llx,0x%llx,0x%llx]\n",
        pid, tid, (int)arg0, (unsigned long long)arg2, (int)arg3,
        (int)self->mm_nr,
        (unsigned long long)self->mm_a0,
        (unsigned long long)self->mm_a1,
        (unsigned long long)self->mm_a2,
        (unsigned long long)self->mm_a3,
        (unsigned long long)self->mm_a4,
        (unsigned long long)self->mm_a5);
}

carrick*:::unhandled-syscall
/pid == $target || progenyof($target)/
{
    printf("[%d/%d unhandled] nr=%d\n", pid, tid, (int)arg0);
}

carrick*:::guest-exit
/pid == $target || progenyof($target)/
{
    printf("[%d/%d guest-exit] code=%d\n", pid, tid, (int)arg0);
}

tick-1s { secs++; }
tick-1s /secs >= 25/ { exit(0); }
