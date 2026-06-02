#pragma D option quiet
#pragma D option strsize=512

/*
 * Focused Rosetta event-shape trace.
 *
 * Covers the syscall families that can affect translated-code memory semantics
 * around the reduced gpgv output corruption:
 *   futex=98, prctl=167, munmap=215, mremap=216, clone=220, mmap=222,
 *   mprotect=226, getrandom=278, membarrier=283, clone3=435,
 *   exit/exit_group/wait.
 *
 * Example:
 *   carrick trace --script scripts/trace-rosetta-events.d --trace-out /tmp/events.out -- run ...
 */

dtrace:::BEGIN
{
    printf("rosetta event trace started at %Y\n", walltimestamp);
}

carrick*:::execve-argv
/pid == $target || progenyof($target)/
{
    printf("[%d exec-argv] path=%s argv=%s\n", pid, copyinstr(arg1), copyinstr(arg2));
}

carrick*:::execve-loaded
/pid == $target || progenyof($target)/
{
    printf("[%d exec-load] path=%s entry=%#llx sp=%#llx maps=%lld\n",
        pid, copyinstr(arg0), arg1, arg2, (int64_t)arg3);
}

carrick*:::path-open
/(pid == $target || progenyof($target)) &&
 (strstr(copyinstr(arg1), "InRelease") != NULL ||
  strstr(copyinstr(arg1), "ubuntu-archive-keyring.gpg") != NULL ||
  strstr(copyinstr(arg1), "/usr/bin/gpgv") != NULL)/
{
    printf("[%d open] path=%s size=%lld errno=%d\n",
        pid, copyinstr(arg1), (int64_t)arg2, (int)arg3);
}

carrick*:::syscall-entry
/(pid == $target || progenyof($target)) &&
 (arg0 == 98 || arg0 == 167 || arg0 == 215 || arg0 == 216 ||
  arg0 == 220 || arg0 == 222 || arg0 == 226 || arg0 == 260 ||
  arg0 == 261 || arg0 == 278 || arg0 == 283 || arg0 == 435 || arg0 == 93 ||
  arg0 == 94)/
{
    this->sa = (uint64_t *)copyin(arg2, 48);
    printf("[%d sys-entry] %s(%d) a0=%#llx a1=%#llx a2=%#llx a3=%#llx a4=%#llx a5=%#llx\n",
        pid, copyinstr(arg1), arg0,
        this->sa[0], this->sa[1], this->sa[2],
        this->sa[3], this->sa[4], this->sa[5]);
}

carrick*:::syscall-return
/(pid == $target || progenyof($target)) &&
 (arg0 == 98 || arg0 == 167 || arg0 == 215 || arg0 == 216 ||
  arg0 == 220 || arg0 == 222 || arg0 == 226 || arg0 == 260 ||
  arg0 == 261 || arg0 == 278 || arg0 == 283 || arg0 == 435 || arg0 == 93 ||
  arg0 == 94)/
{
    printf("[%d sys-ret  ] %s(%d) ret=%lld errno=%d\n",
        pid, copyinstr(arg1), arg0, (int64_t)arg2, (int)arg3);
}

carrick*:::futex-route
/pid == $target || progenyof($target)/
{
    printf("[%d futex-route] addr=%#llx op=%d shared=%d host=%#llx\n",
        pid, arg1, (int)arg2, (int)arg3, arg4);
}

carrick*:::hv-vm-map-alias
/pid == $target || progenyof($target)/
{
    printf("[%d alias-map] va=%#llx ipa=%#llx size=%#llx rc=%d forked=%d\n",
        pid, arg0, arg1, arg2, (int)arg3, (int)arg4);
}

carrick*:::pt-alias-walk
/pid == $target || progenyof($target)/
{
    printf("[%d pt-alias] va=%#llx l0=%#llx l1=%#llx l2=%#llx l3=%#llx rc=%d\n",
        pid, arg0, arg1, arg2, arg3, arg4, (int)arg5);
}

carrick*:::pt-pause-begin
/pid == $target || progenyof($target)/
{
    printf("[%d pt-pause-begin] tid=%d others=%d count=%d\n",
        pid, (int)arg0, (int)arg1, (int)arg2);
}

carrick*:::pt-pause-ready
/pid == $target || progenyof($target)/
{
    printf("[%d pt-pause-ready] tid=%d spins=%d wait_us=%lld\n",
        pid, (int)arg0, (int)arg1, (int64_t)arg2);
}

carrick*:::pt-pause-timeout
/pid == $target || progenyof($target)/
{
    printf("[%d pt-pause-timeout] tid=%d wait_us=%lld\n",
        pid, (int)arg0, (int64_t)arg1);
}

carrick*:::pt-pause-end
/pid == $target || progenyof($target)/
{
    printf("[%d pt-pause-end] tid=%d\n", pid, (int)arg0);
}

carrick*:::pt-pool
/pid == $target || progenyof($target)/
{
    printf("[%d pt-pool] in_use=%u free=%u cap=%u changed=%d\n",
        pid, (uint32_t)arg0, (uint32_t)arg1, (uint32_t)arg2, (int)arg3);
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
/secs >= 30/
{
    printf("rosetta event trace timeout at %Y\n", walltimestamp);
    exit(0);
}
