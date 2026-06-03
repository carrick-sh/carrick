#pragma D option quiet
#pragma D option strsize=256

carrick*:::syscall-entry
/(pid == $target || progenyof($target)) && arg0 == 59/
{
    /* pipe2 args at copyin(arg2, 48): args[0]=pipefd_ptr, args[1]=flags */
    self->args = (uint64_t *)copyin(arg2, 48);
    printf("[%d] pipe2 ENTRY flags=0x%x\n", pid, (uint64_t)self->args[1]);
}

carrick*:::syscall-return
/(pid == $target || progenyof($target)) && arg0 == 59/
{
    printf("[%d] pipe2 RETURN ret=%d errno=%d\n", pid, (int)arg2, (int)arg3);
}

tick-1s { secs++; }
tick-1s /secs >= 8/ { exit(0); }
