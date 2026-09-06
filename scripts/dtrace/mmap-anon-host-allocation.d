/*
 * Count host mmap calls during untouched anonymous guest mmap service.
 * macOS/arm64: syscall mmap arg1 is length; guest syscall args are nr,VA,
 * length,prot,flags. Enable service-begin to enable its args companion.
 * Select 255 guest pages (1044480 bytes), avoiding CPython's 1 MiB allocator
 * arenas. Fixture closes each view without touching it. Demand the exact
 * iteration count; nonzero host allocations disprove metadata-only mmap.
 * Kernel syscall instrumentation perturbs; this is a work-count receipt,
 * never a latency measurement. ERROR/empty output is unusable. Bound 25 s.
 */
#pragma D option quiet
dtrace:::BEGIN
{
    mmap_count = 0;
    errors = 0;
    host_maps = 0;
    host_bytes = (uint64_t)0;
    seconds = 0;
}
carrick*:::hvpatch-syscall-service-begin
/pid == $target || progenyof($target)/
{
    self->nr = arg3;
}
carrick*:::hvpatch-syscall-args
/(pid == $target || progenyof($target)) && arg0 == 222/
{
    self->selected = arg2 == 1044480 && arg4 == 34;
}
syscall::mmap:entry
/(pid == $target || progenyof($target)) && self->selected/
{
    host_maps++;
    host_bytes += arg1;
}
carrick*:::syscall-return
/(pid == $target || progenyof($target)) && arg0 == 222 && self->selected/
{
    mmap_count++;
    errors += arg3 != 0;
    self->selected = 0;
}
dtrace:::ERROR
{
    errors++;
    printf("UNUSABLE: DTrace error\n");
    exit(2);
}
tick-1s
{
    seconds++;
}
tick-1s
/seconds >= 25/
{
    exit(0);
}
END
{
    printf("ANON_HOST_ALLOCATION count=%d errors=%d host_maps=%d host_bytes=%llu\n", mmap_count, errors, host_maps, host_bytes);
    printf("%s\n", mmap_count == 0 || errors ? "UNUSABLE" : "CHECK EXPECTED ITERATION COUNT");
}
