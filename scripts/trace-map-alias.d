#pragma D option quiet
#pragma D option strsize=512

carrick*:::path-open
/pid == $target || progenyof($target)/
{
    printf("[%d open] path=%s size=%d errno=%d\n",
        (int)arg0, copyinstr(arg1), (int)arg2, (int)arg3);
}

carrick*:::syscall-entry
/(pid == $target || progenyof($target)) && arg0 == 222/
{
    this->sa = (uint64_t *)copyin(arg2, 48);
    printf("[%d mmap-entry] addr=%#llx len=%#llx prot=%#llx flags=%#llx fd=%lld off=%#llx\n",
        pid, this->sa[0], this->sa[1], this->sa[2], this->sa[3],
        (int64_t)this->sa[4], this->sa[5]);
}

carrick*:::syscall-return
/(pid == $target || progenyof($target)) && arg0 == 222/
{
    printf("[%d mmap-ret] ret=%lld errno=%d\n", pid, (int64_t)arg2, (int)arg3);
}

carrick*:::hv-vm-map-alias
/pid == $target || progenyof($target)/
{
    printf("[%d alias] va=%#llx ipa=%#llx size=%#llx rc=%d forked=%d\n",
        pid, arg0, arg1, arg2, (int)arg3, (int)arg4);
}

carrick*:::guest-exit
/pid == $target || progenyof($target)/
{
    printf("[%d guest-exit] code=%d\n", pid, (int)arg1);
}

tick-1s
{
    secs++;
}

tick-1s
/secs >= 10/
{
    exit(0);
}
