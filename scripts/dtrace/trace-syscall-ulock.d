#pragma D option quiet
#pragma D option strsize=256

/* Catch the underlying macOS __ulock_wait/__ulock_wake syscalls regardless
   of which library caused them. arg0 is op|flags, arg1 the address. */

syscall::ulock_wait:entry,syscall::ulock_wait2:entry
/pid == $target || progenyof($target)/
{
    self->op = arg0;
    self->addr = arg1;
}

syscall::ulock_wait:return,syscall::ulock_wait2:return
/(pid == $target || progenyof($target)) && self->addr/
{
    printf("[%d] ulock_wait op=0x%x addr=0x%llx ret=%d\n",
        pid, (uint32_t)self->op, (uint64_t)self->addr, (int)arg1);
    self->op = 0; self->addr = 0;
}

syscall::ulock_wake:entry
/pid == $target || progenyof($target)/
{
    self->wop = arg0;
    self->waddr = arg1;
}

syscall::ulock_wake:return
/(pid == $target || progenyof($target)) && self->waddr/
{
    printf("[%d] ulock_wake op=0x%x addr=0x%llx ret=%d\n",
        pid, (uint32_t)self->wop, (uint64_t)self->waddr, (int)arg1);
    self->wop = 0; self->waddr = 0;
}

tick-1s { secs++; }
tick-1s /secs >= 12/ { exit(0); }
