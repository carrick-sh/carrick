#pragma D option quiet
carrick*:::syscall-entry /(pid==$target||progenyof($target)) && arg0==222/ { this->a=(uint64_t*)copyin(arg2,48); self->len=this->a[1]; self->prot=this->a[2]; self->flags=this->a[3]; self->fd=(int)this->a[4]; }
carrick*:::syscall-return /(pid==$target||progenyof($target)) && arg0==222/ { printf("MMAP[%d] len=%d prot=0x%x flags=0x%x fd=%d -> ret=0x%x errno=%d\n", pid, self->len, self->prot, self->flags, self->fd, arg2, (int)arg3); }
tick-1s{secs++} tick-1s/secs>=15/{exit(0)}
