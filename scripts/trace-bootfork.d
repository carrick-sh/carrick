#pragma D option quiet
#pragma D option strsize=64

/* Measure first-boot vs fork. Anchor at the first host syscall. lifecycle
 * phase=4 (FIRST_VCPU_RUN) = INITIAL boot done. fork-pre→fork-post = the fork
 * path (HVF rebuild + snapshot restore in the child, NO image reload).
 * guest-exit→PROCESS EXIT = teardown. Workload: sh boots, then forks+execs. */
BEGIN { st = 0; fp = 0; }

syscall:::entry
/(pid == $target || progenyof($target)) && st == 0/
{ st = timestamp; }

carrick*:::lifecycle
/(pid == $target || progenyof($target))/
{ printf("[+%6d us] lifecycle phase=%d (4=first-vcpu-run / boot done)\n",
    (timestamp - st) / 1000, (int)arg0); }

carrick*:::fork-pre
/(pid == $target || progenyof($target))/
{ fp = timestamp; printf("[+%6d us] fork-pre\n", (fp - st) / 1000); }

carrick*:::fork-post
/(pid == $target || progenyof($target))/
{ printf("[+%6d us] fork-post pid=%d  (fork cost ~%d us)\n",
    (timestamp - st) / 1000, (int)arg0, fp ? (timestamp - fp) / 1000 : -1); }

carrick*:::guest-exit
/(pid == $target || progenyof($target))/
{ printf("[+%6d us] guest-exit code=%d\n", (timestamp - st) / 1000, (int)arg1); }

proc:::exit
/(pid == $target || progenyof($target))/
{ printf("[+%6d us] PROCESS EXIT\n", (timestamp - st) / 1000); }

tick-1s { secs++; }
tick-1s /secs >= 12/ { exit(0); }
