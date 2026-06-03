#pragma D option quiet
#pragma D option strsize=256

/*
 * Trace a CARRICK_WATCH_ADDR watchpoint with enough write(2) context to locate
 * when a guest output buffer changes relative to the host syscall boundary.
 */

dtrace:::BEGIN
{
    fd_pos[0, 0] = 0;
    seen[0, 0] = 0;
    last_value[0, 0] = 0;
    printf("mem watch trace started at %Y\n", walltimestamp);
}

carrick*:::path-open
/(pid == $target || progenyof($target)) &&
 (strstr(copyinstr(arg1), "InRelease") != NULL ||
  strstr(copyinstr(arg1), "ubuntu-archive-keyring.gpg") != NULL ||
  strstr(copyinstr(arg1), "/work/plain") != NULL ||
  strstr(copyinstr(arg1), "/tmp/plain") != NULL)/
{
    printf("[%d open] path=%s size=%lld errno=%d\n",
        pid, copyinstr(arg1), (int64_t)arg2, (int)arg3);
}

carrick*:::syscall-entry
/(pid == $target || progenyof($target)) &&
 (arg0 == 63 || arg0 == 64 || arg0 == 66 || arg0 == 68 || arg0 == 70 ||
  arg0 == 98 || arg0 == 167 || arg0 == 215 || arg0 == 222 || arg0 == 226 ||
  arg0 == 278)/
{
    this->sa = (uint64_t *)copyin(arg2, 48);
    self->nr = arg0;
    self->fd = this->sa[0];
    self->addr = this->sa[1];
    self->len = this->sa[2];
    self->pos = (arg0 == 64 || arg0 == 66 || arg0 == 68 || arg0 == 70) ?
        fd_pos[pid, self->fd] : 0;

    printf("[%d sys-entry] %s(%d) a0=%#llx a1=%#llx a2=%#llx a3=%#llx pos=%lld\n",
        pid, copyinstr(arg1), arg0,
        this->sa[0], this->sa[1], this->sa[2], this->sa[3],
        (int64_t)self->pos);
}

carrick*:::mem-watch
/pid == $target || progenyof($target)/
{
    this->changed = !seen[pid, arg1] || last_value[pid, arg1] != arg2;
    printf("[%d watch] nr=%d addr=%#llx value=%#llx changed=%d write_fd=%d write_pos=%lld write_addr=%#llx write_len=%lld\n",
        pid, (int)arg0, arg1, arg2, (int)this->changed,
        (int)self->fd, (int64_t)self->pos, self->addr, (int64_t)self->len);
    seen[pid, arg1] = 1;
    last_value[pid, arg1] = arg2;
}

carrick*:::syscall-return
/(pid == $target || progenyof($target)) && self->nr != 0/
{
    printf("[%d sys-ret  ] %s(%d) ret=%lld errno=%d pos=%lld\n",
        pid, copyinstr(arg1), (int)arg0, (int64_t)arg2, (int)arg3,
        (int64_t)self->pos);
    fd_pos[pid, self->fd] = ((self->nr == 64 || self->nr == 66 ||
        self->nr == 68 || self->nr == 70) && (int64_t)arg2 > 0) ?
        fd_pos[pid, self->fd] + arg2 : fd_pos[pid, self->fd];
    self->nr = 0;
    self->fd = 0;
    self->addr = 0;
    self->len = 0;
    self->pos = 0;
}

tick-1s
{
    secs++;
}

tick-1s
/secs >= 20/
{
    printf("mem watch trace timeout at %Y\n", walltimestamp);
    exit(0);
}
