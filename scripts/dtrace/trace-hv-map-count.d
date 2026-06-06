#pragma D option quiet
#pragma D option strsize=256

/*
 * Count guest mmap/munmap syscalls and host Hypervisor.framework map/unmap
 * calls. The pid provider does not follow fork reliably, but perf_mmap_churn is
 * a single-process fixture, so pid$target is appropriate for the host function
 * calls here.
 */

carrick*:::syscall-return
/(pid == $target || progenyof($target)) && arg0 == 222/
{
    @guest["mmap"] = count();
}

carrick*:::syscall-return
/(pid == $target || progenyof($target)) && arg0 == 215/
{
    @guest["munmap"] = count();
}

pid$target::hv_vm_map:entry
{
    @hv["hv_vm_map"] = count();
}

pid$target::_hv_vm_map:entry
{
    @hv["hv_vm_map"] = count();
}

pid$target::hv_vm_unmap:entry
{
    @hv["hv_vm_unmap"] = count();
}

pid$target::_hv_vm_unmap:entry
{
    @hv["hv_vm_unmap"] = count();
}

carrick*:::guest-exit
/pid == $target || progenyof($target)/
{
    printf("guest-exit code=%d\n", (int)arg0);
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

END
{
    printa("guest %-16s %@d\n", @guest);
    printa("host  %-16s %@d\n", @hv);
}
