#pragma D option quiet
#pragma D option strsize=256

carrick*:::syscall-entry
/(pid == $target || progenyof($target)) && (arg0 == 222 || arg0 == 56)/
{
    self->args = (uint64_t *)copyin(arg2, 48);
    /* mmap args: addr(0), len(1), prot(2), flags(3), fd(4), offset(5)
       open args: dirfd(0), pathname_ptr(1), flags(2) */
    printf("[%d] %s ENTRY a0=0x%x a1=0x%x a2=0x%x a3=0x%x a4=%d a5=%d\n",
        pid, arg0 == 222 ? "mmap" : "open",
        (uint64_t)self->args[0], (uint64_t)self->args[1],
        (uint64_t)self->args[2], (uint64_t)self->args[3],
        (int)self->args[4], (int)self->args[5]);
}

carrick*:::syscall-return
/(pid == $target || progenyof($target)) && (arg0 == 222 || arg0 == 56)/
{
    printf("[%d] %s RETURN ret=0x%x errno=%d\n",
        pid, arg0 == 222 ? "mmap" : "open",
        (uint64_t)arg2, (int)arg3);
}

tick-1s { secs++; }
tick-1s /secs >= 8/ { exit(0); }
