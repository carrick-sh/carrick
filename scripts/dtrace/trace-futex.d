#pragma D option quiet
#pragma D option strsize=256

carrick*:::syscall-entry
/(pid == $target || progenyof($target)) && arg0 == 98/
{
    self->args = (uint64_t *)copyin(arg2, 48);
    /* args: [0]=uaddr, [1]=op, [2]=val, [3]=timeout */
    printf("[%d] futex uaddr=0x%x op=%d val=%d timeout=0x%x\n",
        pid, (uint64_t)self->args[0],
        (int)self->args[1], (int)self->args[2],
        (uint64_t)self->args[3]);
}

carrick*:::syscall-return
/(pid == $target || progenyof($target)) && arg0 == 98/
{
    printf("[%d] futex return ret=%d errno=%d\n", pid, (int)arg2, (int)arg3);
}

carrick*:::fork-post
/pid == $target || progenyof($target)/
{
    printf("[%d] fork-post child=%d\n", pid, (int)arg1);
}

tick-1s { secs++; }
tick-1s /secs >= 13/ { exit(0); }
