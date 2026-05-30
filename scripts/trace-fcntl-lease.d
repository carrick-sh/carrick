#pragma D option quiet
#pragma D option strsize=256

/* fcntl is Linux aarch64 syscall nr 25. The syscall-entry arg2 is a HOST
 * address of the 6-u64 arg array (copyin works); args[0]=fd, args[1]=cmd,
 * args[2]=lease/lock arg. self-> (thread-local) carries entry→return. */
carrick*:::syscall-entry
/(pid == $target || progenyof($target)) && arg0 == 25/
{
    this->a = (uint64_t *)copyin(arg2, 48);
    self->cmd = this->a[1];
    self->larg = this->a[2];
}

carrick*:::syscall-return
/(pid == $target || progenyof($target)) && arg0 == 25/
{
    printf("[%d] fcntl cmd=%d arg=%d -> ret=%d errno=%d\n",
        pid, (int)self->cmd, (int)self->larg, (int)arg2, (int)arg3);
    self->cmd = 0; self->larg = 0;
}

tick-1s { secs++; }
tick-1s /secs >= 20/ { exit(0); }
