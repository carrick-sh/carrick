#pragma D option quiet
carrick*:::signal-inject /pid==$target||progenyof($target)/ { @i[pid,(int)arg0]=count(); printf("INJECT[%d] sig=%d\n", pid, (int)arg0); }
carrick*:::syscall-entry /(pid==$target||progenyof($target)) && arg0==103/ { this->a=(uint64_t*)copyin(arg2,48); printf("SETITIMER[%d] which=%d newval_ptr=0x%x\n", pid, (int)this->a[0], this->a[1]); }
tick-1s{secs++} tick-1s/secs>=15/{exit(0)}
END{ printa("count sig: pid=%d sig=%d n=%@d\n",@i); }
