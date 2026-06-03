#pragma D option quiet
#pragma D option strsize=256

/*
 * Trace guest write buffers with per-fd logical offsets.
 *
 * This pairs carrick syscall-entry/syscall-return with guest-mem-* probes.
 * The guest-mem probes carry content fingerprints from Carrick's copied guest
 * buffer; the offset counter lets us identify the write covering a target file
 * offset without DTrace reading guest VAs.
 */

dtrace:::BEGIN
{
    fd_pos[0, 0] = 0;
    copy_stage1[0, 0] = 0;
    printf("write buffer trace started at %Y\n", walltimestamp);
}

carrick*:::path-open
/pid == $target || progenyof($target)/
{
    printf("[%d open] path=%s size=%d errno=%d\n",
        pid, copyinstr(arg1), (int)arg2, (int)arg3);
}

carrick*:::syscall-entry
/(pid == $target || progenyof($target)) && (arg0 == 64 || arg0 == 66 || arg0 == 68 || arg0 == 70)/
{
    this->sa = (uint64_t *)copyin(arg2, 48);
    self->nr = arg0;
    self->fd = this->sa[0];
    self->addr = this->sa[1];
    self->len = this->sa[2];
    self->pos = fd_pos[pid, self->fd];
    printf("[%d write-entry] nr=%d fd=%d pos=%d addr=%#x len=%d\n",
        pid, (int)arg0, (int)self->fd, self->pos, self->addr, self->len);
}

carrick*:::guest-mem-bytes
/(pid == $target || progenyof($target)) && arg0 == 0 && self->nr != 0/
{
    printf("[%d write-byte ] nr=%d fd=%d pos=%d addr=%#x len=%d sum=%#x head=%#x\n",
        pid, (int)self->nr, (int)self->fd, self->pos, arg1, arg2, arg3, arg4);
}

carrick*:::guest-mem-copy
/(pid == $target || progenyof($target)) && arg0 == 0 && self->nr != 0/
{
    copy_stage1[pid, arg1] = arg3;
    printf("[%d write-copy ] nr=%d fd=%d pos=%d addr=%#x len=%d stage1=%#x map_start=%#x\n",
        pid, (int)self->nr, (int)self->fd, self->pos, arg1, arg2, arg3, arg4);
}

carrick*:::guest-mem-region
/(pid == $target || progenyof($target)) && arg0 == 0 && self->nr != 0/
{
    this->addr = arg1;
    this->map_start = arg2;
    this->map_ipa = arg4;
    this->stage1 = copy_stage1[pid, this->addr];
    this->va_off = this->addr - this->map_start;
    this->ipa_off = this->stage1 == 0xffffffffffffffff ? 0xffffffffffffffff : this->stage1 - this->map_ipa;
    this->status = this->stage1 == 0xffffffffffffffff ? "NOSTAGE" :
        (this->va_off == this->ipa_off ? "MATCH" : "MISMATCH");
    printf("[%d write-reg  ] nr=%d fd=%d pos=%d addr=%#x map_start=%#x map_end=%#x map_ipa=%#x va_off=%#x ipa_off=%#x %s\n",
        pid, (int)self->nr, (int)self->fd, self->pos, this->addr, this->map_start,
        arg3, this->map_ipa, this->va_off, this->ipa_off, this->status);
}

carrick*:::guest-mem-point
/(pid == $target || progenyof($target)) && arg0 == 0 && self->nr != 0/
{
    this->addr = arg1;
    this->va_off = arg2;
    this->ipa_off = arg3;
    this->stage1 = arg4;
    this->status = this->ipa_off == 0xffffffffffffffff ? "NOSTAGE" :
        (this->va_off == this->ipa_off ? "MATCH" : "MISMATCH");
    printf("[%d write-point] nr=%d fd=%d pos=%d addr=%#x va_off=%#x ipa_off=%#x stage1=%#x %s\n",
        pid, (int)self->nr, (int)self->fd, self->pos, this->addr, this->va_off,
        this->ipa_off, this->stage1, this->status);
}

carrick*:::guest-mem-tail
/(pid == $target || progenyof($target)) && arg0 == 0 && self->nr != 0/
{
    printf("[%d write-tail ] nr=%d fd=%d pos=%d addr=%#x len=%d tail=%#x\n",
        pid, (int)self->nr, (int)self->fd, self->pos, arg1, arg2, arg3);
}

carrick*:::guest-mem-subrange
/(pid == $target || progenyof($target)) && arg0 == 0 && self->nr != 0/
{
    printf("[%d write-sub  ] nr=%d fd=%d pos=%d addr=%#x off=%#x len=%d sum=%#x\n",
        pid, (int)self->nr, (int)self->fd, self->pos, arg1, arg2, arg3, arg4);
}

carrick*:::guest-mem-subedge
/(pid == $target || progenyof($target)) && arg0 == 0 && self->nr != 0/
{
    printf("[%d write-sedge] nr=%d fd=%d pos=%d addr=%#x off=%#x head=%#x tail=%#x\n",
        pid, (int)self->nr, (int)self->fd, self->pos, arg1, arg2, arg3, arg4);
}

carrick*:::guest-mem-subcount
/(pid == $target || progenyof($target)) && arg0 == 0 && self->nr != 0/
{
    printf("[%d write-scnt ] nr=%d fd=%d pos=%d addr=%#x off=%#x nonzero=%d\n",
        pid, (int)self->nr, (int)self->fd, self->pos, arg1, arg2, arg3);
}

carrick*:::syscall-return
/(pid == $target || progenyof($target)) && self->nr != 0/
{
    printf("[%d write-ret  ] nr=%d fd=%d pos=%d ret=%d errno=%d\n",
        pid, (int)self->nr, (int)self->fd, self->pos, (int)arg2, (int)arg3);
    fd_pos[pid, self->fd] = (int)arg2 > 0 ? fd_pos[pid, self->fd] + arg2 : fd_pos[pid, self->fd];
    self->nr = 0;
    self->fd = 0;
    self->addr = 0;
    self->len = 0;
    self->pos = 0;
}

tick-1s { secs++; }
tick-1s /secs >= 20/ { exit(0); }
