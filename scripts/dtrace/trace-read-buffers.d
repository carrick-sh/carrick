#pragma D option quiet
#pragma D option strsize=256

/*
 * Trace guest read(2) destination buffers with optional subrange fingerprints.
 *
 * Pair with:
 *   CARRICK_GUEST_MEM_SUB_OFFSET=<offset>
 *   CARRICK_GUEST_MEM_SUB_LEN=<length>
 */

dtrace:::BEGIN
{
    printf("read buffer trace started at %Y\n", walltimestamp);
}

carrick*:::path-open
/(pid == $target || progenyof($target)) &&
 (strstr(copyinstr(arg1), "InRelease") != NULL ||
  strstr(copyinstr(arg1), "ubuntu-archive-keyring.gpg") != NULL ||
  strstr(copyinstr(arg1), ".asc") != NULL)/
{
    printf("[%d open] path=%s size=%lld errno=%d\n",
        pid, copyinstr(arg1), (int64_t)arg2, (int)arg3);
}

carrick*:::syscall-entry
/(pid == $target || progenyof($target)) && arg0 == 63/
{
    this->sa = (uint64_t *)copyin(arg2, 48);
    self->nr = arg0;
    self->fd = this->sa[0];
    self->addr = this->sa[1];
    self->len = this->sa[2];
    printf("[%d read-entry] fd=%d addr=%#llx len=%lld\n",
        pid, (int)self->fd, (uint64_t)self->addr, (int64_t)self->len);
}

carrick*:::guest-mem-copy
/(pid == $target || progenyof($target)) && self->nr == 63/
{
    copy_stage1[pid, arg1] = arg3;
    printf("[%d read-copy ] dir=%d fd=%d addr=%#llx len=%lld stage1=%#llx map_start=%#llx\n",
        pid, (int)arg0, (int)self->fd, (uint64_t)arg1, (int64_t)arg2,
        (uint64_t)arg3, (uint64_t)arg4);
}

carrick*:::guest-mem-region
/(pid == $target || progenyof($target)) && self->nr == 63/
{
    this->addr = arg1;
    this->map_start = arg2;
    this->map_ipa = arg4;
    this->stage1 = copy_stage1[pid, this->addr];
    this->va_off = this->addr - this->map_start;
    this->ipa_off = this->stage1 == 0xffffffffffffffff ? 0xffffffffffffffff : this->stage1 - this->map_ipa;
    this->status = this->stage1 == 0xffffffffffffffff ? "NOSTAGE" :
        (this->va_off == this->ipa_off ? "MATCH" : "MISMATCH");
    printf("[%d read-reg  ] dir=%d fd=%d addr=%#llx map_start=%#llx map_end=%#llx map_ipa=%#llx va_off=%#llx ipa_off=%#llx %s\n",
        pid, (int)arg0, (int)self->fd, (uint64_t)this->addr,
        (uint64_t)this->map_start, (uint64_t)arg3, (uint64_t)this->map_ipa,
        (uint64_t)this->va_off, (uint64_t)this->ipa_off, this->status);
}

carrick*:::guest-mem-point
/(pid == $target || progenyof($target)) && self->nr == 63/
{
    this->status = arg3 == 0xffffffffffffffff ? "NOSTAGE" :
        (arg2 == arg3 ? "MATCH" : "MISMATCH");
    printf("[%d read-point] dir=%d fd=%d addr=%#llx va_off=%#llx ipa_off=%#llx stage1=%#llx %s\n",
        pid, (int)arg0, (int)self->fd, (uint64_t)arg1, (uint64_t)arg2,
        (uint64_t)arg3, (uint64_t)arg4, this->status);
}

carrick*:::guest-mem-bytes
/(pid == $target || progenyof($target)) && self->nr == 63/
{
    printf("[%d read-byte ] dir=%d fd=%d addr=%#llx len=%lld sum=%#llx head=%#llx\n",
        pid, (int)arg0, (int)self->fd, (uint64_t)arg1, (int64_t)arg2,
        (uint64_t)arg3, (uint64_t)arg4);
}

carrick*:::guest-mem-tail
/(pid == $target || progenyof($target)) && self->nr == 63/
{
    printf("[%d read-tail ] dir=%d fd=%d addr=%#llx len=%lld tail=%#llx\n",
        pid, (int)arg0, (int)self->fd, (uint64_t)arg1, (int64_t)arg2,
        (uint64_t)arg3);
}

carrick*:::guest-mem-subrange
/(pid == $target || progenyof($target)) && self->nr == 63/
{
    printf("[%d read-sub  ] dir=%d fd=%d addr=%#llx off=%#llx len=%lld sum=%#llx\n",
        pid, (int)arg0, (int)self->fd, (uint64_t)arg1, (uint64_t)arg2,
        (int64_t)arg3, (uint64_t)arg4);
}

carrick*:::guest-mem-subedge
/(pid == $target || progenyof($target)) && self->nr == 63/
{
    printf("[%d read-sedge] dir=%d fd=%d addr=%#llx off=%#llx head=%#llx tail=%#llx\n",
        pid, (int)arg0, (int)self->fd, (uint64_t)arg1, (uint64_t)arg2,
        (uint64_t)arg3, (uint64_t)arg4);
}

carrick*:::guest-mem-subcount
/(pid == $target || progenyof($target)) && self->nr == 63/
{
    printf("[%d read-scnt ] dir=%d fd=%d addr=%#llx off=%#llx nonzero=%lld\n",
        pid, (int)arg0, (int)self->fd, (uint64_t)arg1, (uint64_t)arg2,
        (int64_t)arg3);
}

carrick*:::syscall-return
/(pid == $target || progenyof($target)) && self->nr == 63/
{
    printf("[%d read-ret  ] fd=%d addr=%#llx len=%lld ret=%lld errno=%d\n",
        pid, (int)self->fd, (uint64_t)self->addr, (int64_t)self->len,
        (int64_t)arg2, (int)arg3);
    self->nr = 0;
    self->fd = 0;
    self->addr = 0;
    self->len = 0;
}

tick-1s { secs++; }
tick-1s /secs >= 20/ { exit(0); }
