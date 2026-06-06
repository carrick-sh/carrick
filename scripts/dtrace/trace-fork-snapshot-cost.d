#pragma D option quiet

syscall:::entry
/(pid == $target || progenyof($target)) &&
    (probefunc == "fork" || probefunc == "wait4" ||
     probefunc == "mmap" || probefunc == "munmap" ||
     probefunc == "mincore")/
{
    @counts["sys_count", probefunc] = count();
}

syscall:::entry
/(pid == $target || progenyof($target)) &&
    (probefunc == "mmap" || probefunc == "munmap" || probefunc == "mincore")/
{
    @sums["sys_bytes", probefunc] = sum(arg1);
}

pid$target::hv_vm_map:entry
{
    @counts["hv_count", "hv_vm_map"] = count();
    @sums["hv_bytes", "hv_vm_map"] = sum(arg2);
}

pid$target::_hv_vm_map:entry
{
    @counts["hv_count", "hv_vm_map"] = count();
    @sums["hv_bytes", "hv_vm_map"] = sum(arg2);
}

tick-1s
{
    secs++;
}

tick-1s
/secs >= 20/
{
    exit(0);
}
