#pragma D option quiet
#pragma D option strsize=256

/* aarch64 sysnos: 107=timer_create, 108=timer_gettime, 109=timer_getoverrun,
   110=timer_settime, 111=timer_delete. arg2 of carrick syscall-entry is the
   pointer to the 6-u64 arg array (host pointer, copyin OK). */

carrick*:::syscall-entry
/(pid == $target || progenyof($target)) && arg0 >= 107 && arg0 <= 111/
{
    self->args = (uint64_t *)copyin(arg2, 48);
    printf("[%d] sys ENTRY  nr=%d a0=%d a1=%d a2=0x%x a3=0x%x\n",
           pid, arg0,
           (int)self->args[0], (int)self->args[1],
           (uint64_t)self->args[2], (uint64_t)self->args[3]);
}

carrick*:::syscall-return
/(pid == $target || progenyof($target)) && arg0 >= 107 && arg0 <= 111/
{
    printf("[%d] sys RETURN nr=%d ret=%d errno=%d\n",
           pid, arg0, (int)arg2, (int)arg3);
}

tick-1s { secs++; }
tick-1s /secs >= 12/ { exit(0); }
