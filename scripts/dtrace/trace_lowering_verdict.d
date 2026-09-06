/*
 * Diagnose private file-view lowering, including the exact fallback error.
 * Qualified on macOS/arm64, 2026-09-06: both probes fire in the VM carrier.
 * mmap-lowering-verdict: arg0 VA, arg1 length, arg2 file offset, arg3 outcome
 * (1 installed, 2 refused, 3 error, 5 host metadata unavailable).
 * mmap-lowering-error: arg0 VA, arg1 length, arg2 offset, arg3 C string.
 * Diagnostic only: error string formatting and per-event printing perturb
 * failing mappings. Never use this script's run for latency acceptance.
 * A zero event count is explicitly unusable evidence.
 */
#pragma D option quiet
carrick*:::mmap-lowering-verdict
/pid == $target || progenyof($target)/
{
    seen++;
    printf("lowering va=0x%llx len=0x%llx offset=0x%llx outcome=%u\n",
        arg0, arg1, arg2, arg3);
    @outcomes[arg3] = count();
}
carrick*:::mmap-lowering-error
/pid == $target || progenyof($target)/
{
    printf("lowering-error va=0x%llx len=0x%llx offset=0x%llx reason=%s\n",
        arg0, arg1, arg2, copyinstr(arg3));
}
dtrace:::ERROR
{
    failed = 1;
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
    printf("lowering-events=%d trace-errors=%d\n", seen, failed);
    printf("%s\n", seen == 0 || failed ? "UNUSABLE" : "DIAGNOSTIC CAPTURE");
    printa("outcome=%u count=%@d\n", @outcomes);
}
