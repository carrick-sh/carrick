#pragma D option quiet
#pragma D option strsize=256

/* arg0 of carrick USDT probes is libc::getpid()-as-u32; real args start at arg1. */

carrick*:::syscall-entry
/(pid == $target || progenyof($target)) && (arg0 == 73 || arg0 == 103 || arg0 == 133)/
{ printf("[%d] sys ENTRY  nr=%d\n", pid, arg0); }

carrick*:::syscall-return
/(pid == $target || progenyof($target)) && (arg0 == 73 || arg0 == 103 || arg0 == 133)/
{ printf("[%d] sys RETURN nr=%d ret=%d\n", pid, arg0, (int)arg2); }

carrick*:::itimer-fire
/pid == $target || progenyof($target)/
{ printf("[%d] itimer-fire signum=%d gen=%d\n", pid, (int)arg1, (int)arg2); }

carrick*:::signal-publish
/pid == $target || progenyof($target)/
{ printf("[%d] signal-publish tid=%d signum=%d code=%d\n", pid, (int)arg1, (int)arg2, (int)arg3); }

carrick*:::io-wait-begin
/pid == $target || progenyof($target)/
{ printf("[%d] io-wait-begin tid=%d nfds=%d timeout_ms=%d\n", pid, (int)arg1, (int)arg2, (int)arg3); }

carrick*:::io-wait-end
/pid == $target || progenyof($target)/
{ printf("[%d] io-wait-end tid=%d code=%d nfds=%d\n", pid, (int)arg1, (int)arg2, (int)arg3); }

tick-1s { secs++; }
tick-1s /secs >= 10/ { exit(0); }
