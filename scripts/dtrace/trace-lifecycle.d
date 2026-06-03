#pragma D option quiet
#pragma D option strsize=128

/* Measure carrick's per-run lifecycle: anchor at the first host syscall
 * (~process start), then time to (a) the FIRST guest Linux syscall = boot/setup
 * done, and (b) guest-exit. Accumulate mmap bytes (the suspected eager-alloc).
 * boot = st->first-guest-syscall, guest-run = that->guest-exit. */
BEGIN { st = 0; firstgs = 0; }

syscall:::entry
/(pid == $target || progenyof($target)) && st == 0/
{ st = timestamp; }

carrick*:::syscall-entry
/(pid == $target || progenyof($target)) && firstgs == 0/
{
    firstgs = 1;
    printf("[+%6d us] BOOT DONE (first guest syscall nr=%d)\n",
        (timestamp - st) / 1000, (int)arg0);
}

carrick*:::guest-exit
/(pid == $target || progenyof($target))/
{ printf("[+%6d us] guest-exit\n", (timestamp - st) / 1000); }

syscall::mmap:entry
/(pid == $target || progenyof($target))/
{ @mmap_bytes = sum(arg1); @mmap_calls = count(); @biggest = max(arg1); }

tick-1s { secs++; }
tick-1s /secs >= 10/ { exit(0); }

END {
    printa("total mmap: %@d bytes in %@d calls; biggest single mmap %@d bytes\n",
        @mmap_bytes, @mmap_calls, @biggest);
}
