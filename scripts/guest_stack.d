/*
 * guest_stack.d — walk the GUEST's aarch64 call stack at each syscall
 * trap, from the host side, using carrick's USDT probes.
 *
 * macOS DTrace has no `ustack()` helper for the guest (the guest isn't
 * a host process — it's code running inside an HVF vCPU whose memory
 * carrick maps into its own address space). So we reconstruct the
 * guest call chain ourselves from the `carrick*:::vcpu-trap` probe.
 *
 * The probe carries a `GuestRegs` JSON snapshot:
 *   {"pc":..,"sp":..,"fp":..,"lr":..,"x8":..,"x0":..,"stack_xlate":..}
 *
 * `fp` (x29) is the head of the AAPCS64 frame-pointer chain: at [fp]
 * sits the caller's saved fp, at [fp+8] the saved lr (return address).
 * `stack_xlate` is the wrapping guest->host offset for the stack's
 * mapping, so `host_va = guest_va + stack_xlate` lets us `copyin` each
 * frame directly — no separate mapping table needed (carrick computes
 * the offset per-trap from the region containing sp).
 *
 * REQUIREMENTS:
 *   - Guest binaries built WITH frame pointers. THIS MATTERS for the
 *     distro you trace:
 *       * Ubuntu 24.04 LTS and later: frame pointers ON by default
 *         (64-bit) — this walker works out of the box.
 *       * Fedora 38+: ON by default — works.
 *       * Debian (incl. 13/trixie): frame pointers OFF by default.
 *         dpkg-buildflags has opt-in `qa=+framepointer`, but stock
 *         Debian binaries (glibc, coreutils, apt, sqv...) are built
 *         `-fomit-frame-pointer`, so x29 is NOT the AAPCS frame
 *         pointer and this walk yields garbage / `copyin` errors.
 *     To trace a Debian guest meaningfully, either use an Ubuntu
 *     image, or rebuild the target with frame pointers, or fall back
 *     to PC-only single-frame tracing (the `pc` field alone is always
 *     valid; only the unwound chain needs frame pointers).
 *   - Run as root (libdtrace needs /dev/dtrace).
 *
 * USAGE:
 *   sudo dtrace -s scripts/guest_stack.d -c \
 *       '/path/to/carrick run <image> --raw /usr/bin/whatever'
 *
 * Output is one block per syscall trap: guest PC + syscall number,
 * then the unwound return addresses (guest VAs). Feed those to
 * addr2line/llvm-symbolizer against the guest binary for names.
 */

#pragma D option quiet
#pragma D option strsize=256
#pragma D option dynvarsize=4m

dtrace:::BEGIN
{
	printf("guest_stack.d: walking guest frame-pointer chains\n");
}

carrick*:::vcpu-trap
{
	this->j = copyinstr(arg0);
	this->fp = (uint64_t) strtoll(json(this->j, "fp"));
	this->pc = (uint64_t) strtoll(json(this->j, "pc"));
	this->x8 = (uint64_t) strtoll(json(this->j, "x8"));
	this->xl = (uint64_t) strtoll(json(this->j, "stack_xlate"));

	printf("\n== trap pc=0x%x syscall=%d fp=0x%x ==\n",
	    this->pc, this->x8, this->fp);
}

/* Frame 0: return address at [fp+8], next fp at [fp]. */
carrick*:::vcpu-trap
/this->fp != 0 && this->xl != 0/
{
	this->lr0 = *(uint64_t *) copyin(this->fp + this->xl + 8, 8);
	this->nextfp = *(uint64_t *) copyin(this->fp + this->xl, 8);
	printf("  #0  0x%x\n", this->lr0);
}

/* Frame 1. */
carrick*:::vcpu-trap
/this->nextfp != 0 && this->xl != 0/
{
	this->lr1 = *(uint64_t *) copyin(this->nextfp + this->xl + 8, 8);
	this->nextfp = *(uint64_t *) copyin(this->nextfp + this->xl, 8);
	printf("  #1  0x%x\n", this->lr1);
}

/* Frame 2. */
carrick*:::vcpu-trap
/this->nextfp != 0 && this->xl != 0/
{
	this->lr2 = *(uint64_t *) copyin(this->nextfp + this->xl + 8, 8);
	this->nextfp = *(uint64_t *) copyin(this->nextfp + this->xl, 8);
	printf("  #2  0x%x\n", this->lr2);
}

/* Frame 3. */
carrick*:::vcpu-trap
/this->nextfp != 0 && this->xl != 0/
{
	this->lr3 = *(uint64_t *) copyin(this->nextfp + this->xl + 8, 8);
	this->nextfp = *(uint64_t *) copyin(this->nextfp + this->xl, 8);
	printf("  #3  0x%x\n", this->lr3);
}

/* Frame 4. */
carrick*:::vcpu-trap
/this->nextfp != 0 && this->xl != 0/
{
	this->lr4 = *(uint64_t *) copyin(this->nextfp + this->xl + 8, 8);
	printf("  #4  0x%x\n", this->lr4);
}

dtrace:::END
{
	printf("\nguest_stack.d: done\n");
}
