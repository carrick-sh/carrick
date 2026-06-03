/* Wall-time per guest syscall (entry->return) across a glob workload + children,
 * to find the real time sink (counts != time). Bounded so it can't run away.
 * aarch64 nrs: 8=getxattr 9=lgetxattr 10=fgetxattr 25=fcntl 56=openat 57=close
 * 61=getdents64 62=lseek 63=read 79=newfstatat 80=fstat 17=getcwd 48=faccessat. */
#pragma D option quiet

carrick*:::syscall-entry
/pid == $target || progenyof($target)/
{ self->t = timestamp; }

carrick*:::syscall-return
/(pid == $target || progenyof($target)) && self->t != 0/
{
    @ns[arg0] = sum(timestamp - self->t);
    @c[arg0] = count();
    self->t = 0;
}

tick-1s { secs++; }
tick-1s /secs >= 80/ { exit(0); }

END { printa("nr=%-5d total_ns=%@d calls=%@d\n", @ns, @c); }
