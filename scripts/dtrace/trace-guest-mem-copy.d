#pragma D option quiet
#pragma D option strsize=256

/*
 * Trace Carrick syscall-path guest-memory copies.
 *
 * Use with a focused workload, e.g.:
 *   carrick trace --script scripts/trace-guest-mem-copy.d --trace-out /tmp/mem.out -- run ...
 *
 * dir: 0=guest->host read, 1=host->guest internal write,
 *      2=host->guest syscall checked write.
 *
 * For high-VA Rosetta aliases, compare:
 *   va_off = addr - mapping_start
 *   ipa_off = stage1_ipa - mapping_ipa
 *
 * A mismatch means Carrick copied through a different backing than the guest's
 * live stage-1 walk will use.
 */

dtrace:::BEGIN
{
    printf("guest memory copy trace started at %Y\n", walltimestamp);
}

carrick*:::guest-mem-copy
/pid == $target || progenyof($target)/
{
    copy_dir[pid, arg1] = (int)arg0;
    copy_len[pid, arg1] = arg2;
    copy_stage1[pid, arg1] = arg3;
    copy_start[pid, arg1] = arg4;
    printf("[%d mem-copy] dir=%d addr=%#x len=%d stage1=%#x map_start=%#x\n",
        pid, (int)arg0, arg1, arg2, arg3, arg4);
}

carrick*:::guest-mem-region
/pid == $target || progenyof($target)/
{
    this->addr = arg1;
    this->map_start = arg2;
    this->map_end = arg3;
    this->map_ipa = arg4;
    this->stage1 = copy_stage1[pid, this->addr];
    this->va_off = this->addr - this->map_start;
    this->ipa_off = this->stage1 == 0xffffffffffffffff ? 0xffffffffffffffff : this->stage1 - this->map_ipa;
    this->status = this->stage1 == 0xffffffffffffffff ? "NOSTAGE" :
        (this->va_off == this->ipa_off ? "MATCH" : "MISMATCH");
    printf("[%d mem-reg ] dir=%d addr=%#x len=%d map_start=%#x map_end=%#x map_ipa=%#x va_off=%#x ipa_off=%#x %s\n",
        pid, copy_dir[pid, this->addr], this->addr, copy_len[pid, this->addr],
        this->map_start, this->map_end, this->map_ipa, this->va_off, this->ipa_off,
        this->status);
}

carrick*:::guest-mem-bytes
/pid == $target || progenyof($target)/
{
    printf("[%d mem-byte ] dir=%d addr=%#x len=%d sum=%#x head=%#x\n",
        pid, (int)arg0, arg1, arg2, arg3, arg4);
}

carrick*:::guest-mem-tail
/pid == $target || progenyof($target)/
{
    printf("[%d mem-tail ] dir=%d addr=%#x len=%d tail=%#x\n",
        pid, (int)arg0, arg1, arg2, arg3);
}

tick-1s { secs++; }
tick-1s /secs >= 20/ { exit(0); }
