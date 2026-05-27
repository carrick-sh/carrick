#pragma D option quiet
#pragma D option strsize=200
carrick*:::syscall-return
/pid==$target||progenyof($target)/
{ printf("[%d] nr=%d %s ret=%d errno=%d\n", pid, (int)arg0, copyinstr(arg1), (int)arg2, (int)arg3); }
tick-1s{secs++} tick-1s/secs>=15/{exit(0)}
