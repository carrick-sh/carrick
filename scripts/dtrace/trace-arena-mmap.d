#pragma D option quiet
#pragma D option strsize=256

/* Linux aarch64 syscall numbers: mmap=222 munmap=215 mremap=216 madvise=233 */

/* Capture mmap args at entry (arg2 = ptr to 6 u64 args). Pair to return via self->. */
carrick*:::syscall-entry
/(pid == $target || progenyof($target)) && arg0 == 222/
{
    this->a = (uint64_t *)copyin(arg2, 48);
    self->maddr  = this->a[0];
    self->mlen   = this->a[1];
    self->mprot  = this->a[2];
    self->mflags = this->a[3];
}

/* Report only the large maps (>= 8 MiB = arena chunk territory). */
carrick*:::syscall-return
/(pid == $target || progenyof($target)) && arg0 == 222 && self->mlen >= 0x800000/
{
    printf("[%d] mmap addr=0x%llx len=0x%llx prot=0x%llx flags=0x%llx -> 0x%llx errno=%d\n",
        pid,
        (unsigned long long)self->maddr, (unsigned long long)self->mlen,
        (unsigned long long)self->mprot, (unsigned long long)self->mflags,
        (unsigned long long)arg2, (int)arg3);
    self->mlen = 0;
}

/* munmap / mremap / madvise returns (catch arena release + hint calls). */
carrick*:::syscall-entry
/(pid == $target || progenyof($target)) && (arg0 == 215 || arg0 == 216 || arg0 == 233)/
{
    this->b = (uint64_t *)copyin(arg2, 48);
    self->oaddr = this->b[0];
    self->olen  = this->b[1];
    self->oadv  = this->b[2];
}
carrick*:::syscall-return
/(pid == $target || progenyof($target)) && (arg0 == 215 || arg0 == 216 || arg0 == 233) && self->olen >= 0x800000/
{
    printf("[%d] nr=%d addr=0x%llx len=0x%llx adv=%d -> 0x%llx errno=%d\n",
        pid, (int)arg0,
        (unsigned long long)self->oaddr, (unsigned long long)self->olen,
        (int)self->oadv, (unsigned long long)arg2, (int)arg3);
    self->olen = 0;
}

/* mprotect (226): Go commits PROT_NONE-reserved heap/arena memory by
   mprotect'ing it RW. If carrick doesn't back the page on this transition,
   writes land nowhere and reads see the pre-commit scribble (0x7b). */
carrick*:::syscall-entry
/(pid == $target || progenyof($target)) && arg0 == 226/
{
    this->c = (uint64_t *)copyin(arg2, 48);
    self->paddr = this->c[0];
    self->plen  = this->c[1];
    self->pprot = this->c[2];
}
carrick*:::syscall-return
/(pid == $target || progenyof($target)) && arg0 == 226 && self->plen >= 0x800000/
{
    printf("[%d] mprotect addr=0x%llx len=0x%llx prot=0x%llx -> 0x%llx errno=%d\n",
        pid, (unsigned long long)self->paddr, (unsigned long long)self->plen,
        (unsigned long long)self->pprot, (unsigned long long)arg2, (int)arg3);
    self->plen = 0;
}

/* Any syscall carrick couldn't handle — an unhandled mm call would explain it. */
carrick*:::unhandled-syscall
/pid == $target || progenyof($target)/
{ printf("[%d] UNHANDLED nr=%d\n", pid, (int)arg0); }

/* Sanity: confirm the guest actually ran + exited under the trace. */
carrick*:::guest-exit
/pid == $target || progenyof($target)/
{ printf("[%d] GUEST-EXIT code=%d\n", pid, (int)arg0); }

tick-1s { secs++; }
tick-1s /secs >= 25/ { exit(0); }
