#pragma D option quiet
#pragma D option strsize=256

/* Pair every futex-route event with its syscall-return so we see how
   the dispatcher resolved each call (WAIT returned ret=0 → "woken",
   ret=-110 → ETIMEDOUT, ret=-11 → EAGAIN; WAKE returns the woken count). */

carrick*:::futex-route
/pid == $target || progenyof($target)/
{
    self->in_futex = 1;
    self->addr = (uint64_t)arg1;
    self->op = (int)arg2;
}

carrick*:::syscall-return
/(pid == $target || progenyof($target)) && self->in_futex && arg0 == 98/
{
    printf("[%d] %s addr=0x%llx ret=%d (errno=%d)\n",
        pid,
        self->op == 0 ? "WAIT " : (self->op == 1 ? "WAKE " : "OTHER"),
        self->addr, (int)arg2, (int)arg3);
    self->in_futex = 0;
}

tick-1s { secs++; }
tick-1s /secs >= 8/ { exit(0); }
