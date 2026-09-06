/*
 * Internal write-copy contract for a whole libpython MAP_PRIVATE mapping.
 * The service-begin probe MUST be enabled: its wrapper only emits the args
 * companion after the identity-bearing begin has fired.
 * Qualified macOS/arm64 ABI: hvpatch-syscall-args is nr,addr,len,prot,flags;
 * syscall-return is nr,name,value,errno; guest-mem-copy is direction,VA,len,
 * stage1 IPA,mapping VA. Direction 1 is write_guest_bytes (not guest stores).
 * Select raw length 6611656 and flags exactly MAP_PRIVATE (2), excluding
 * loader mappings with additional flags. Driver must demand count=iterations,
 * zero errors, and a positive eager-control count on the identical fixture.
 * Per-copy instrumentation perturbs the eager control. Never cite timings.
 */
#pragma D option quiet
dtrace:::BEGIN
{
    copy_bytes = (uint64_t)0;
    copy_chunks = 0;
    mmap_count = 0;
    errors = 0;
    seconds = 0;
}
carrick*:::hvpatch-syscall-service-begin
/(pid == $target || progenyof($target))/
{
    self->nr = arg3;
}
carrick*:::hvpatch-syscall-args
/(pid == $target || progenyof($target)) && arg0 == 222/
{
    self->selected = arg2 == 6611656 && arg4 == 2;
}
carrick*:::guest-mem-copy
/(pid == $target || progenyof($target)) && self->selected && arg0 == 1/
{
    copy_bytes += arg2;
    copy_chunks++;
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
    printf("MMAP_COPY_CONTRACT count=%d errors=%d write_guest_bytes=%llu chunks=%d\n",
        mmap_count, errors, copy_bytes, copy_chunks);
    printf("%s\n", mmap_count == 0 || errors ? "UNUSABLE" : "CHECK EXPECTED ITERATION COUNT");
}
