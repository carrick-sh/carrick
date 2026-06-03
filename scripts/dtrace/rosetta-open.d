#pragma D option quiet
#pragma D option strsize=512
carrick*:::path-open
/pid == $target || progenyof($target)/
{ printf("OPEN [%d] %s size=%d errno=%d\n", pid, copyinstr(arg1), (int)arg2, (int)arg3); }
carrick*:::syscall-return
/(pid == $target || progenyof($target)) && (arg0 == 80 || arg0 == 222)/
{ printf("SYS  [%d] nr=%d ret=%d errno=%d\n", pid, (int)arg0, (int)arg2, (int)arg3); }
tick-1s { secs++; }
tick-1s /secs >= 15/ { exit(0); }
