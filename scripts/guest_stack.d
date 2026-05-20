/*
 * guest_stack.d — walk the GUEST's aarch64 call stack at each syscall
 * trap, entirely from DTrace, via carrick's `vcpu-trap` USDT probe.
 *
 * macOS DTrace has no `ustack()` for the guest (it runs inside an HVF
 * vCPU, not as a host process). But carrick maps the guest's RAM into
 * its own address space, so DTrace `copyin` CAN read it — provided we
 * hand it the correct host address.
 *
 * The `vcpu-trap` probe passes `arg0` = the address of a
 * `compat::GuestRegs` (`#[repr(C)]`, all u64 fields). We copyin that
 * struct, then follow the AAPCS64 frame-pointer chain: at [fp] sits
 * the caller's saved fp, at [fp+8] the saved lr (return address).
 *
 * ADDRESS TRANSLATION (the part that's easy to get wrong): a guest
 * stack VA is translated to its host address with
 *   host = stack_host_base + (guest_va - stack_guest_base)
 * We pass the two BASES separately (not a single offset) because the
 * stack lives high (0xffffff..) and the host mapping low (0x60..), so
 * a single `host_base - guest_base` offset wraps past i63 and DTrace's
 * signed arithmetic mangles it. With separate bases every intermediate
 * value stays in range.
 *
 * REQUIREMENTS:
 *   - Frame-pointer-built guest binaries. Ubuntu 24.04+/Fedora 38+
 *     enable FP by default; stock Debian (incl. 13/trixie) does NOT
 *     (opt-in via dpkg-buildflags qa=+framepointer), so Debian guests
 *     yield short/garbage chains. Use an Ubuntu image.
 *   - Run as root (libdtrace needs /dev/dtrace).
 *
 * USAGE:
 *   sudo dtrace -s scripts/guest_stack.d -c \
 *     '/path/to/carrick run docker.io/library/ubuntu:24.04 --raw /usr/bin/true'
 *
 * Output: one block per trap — guest PC + syscall number, then the
 * unwound return addresses (guest VAs). Feed those to
 * addr2line/llvm-symbolizer against the guest binary for names.
 */

#pragma D option quiet
#pragma D option dynvarsize=8m

typedef struct {
	uint64_t pc;
	uint64_t sp;
	uint64_t fp;
	uint64_t lr;
	uint64_t x8;
	uint64_t x0;
	uint64_t sgb;	/* stack_guest_base */
	uint64_t shb;	/* stack_host_base  */
	uint64_t sge;	/* stack_guest_end (exclusive) */
} gregs_t;

/* guest stack VA -> host VA, using the two bases (no wrapping). */
#define XL(gva)  (this->shb + ((gva) - this->sgb))
/* true iff [gva, gva+16) is inside the stack region (so the frame's
 * saved fp at [gva] and saved lr at [gva+8] are both safe to copyin). */
#define INREG(gva)  ((this->sgb != 0) && (gva) >= this->sgb && (gva) + 16 <= this->sge)

dtrace:::BEGIN
{
	printf("guest_stack.d: copyin-walking guest frame pointers\n");
}

carrick*:::vcpu-trap
{
	this->r   = (gregs_t *) copyin(arg0, sizeof(gregs_t));
	this->pc  = this->r->pc;
	this->x8  = this->r->x8;
	this->fp  = this->r->fp;
	this->sgb = this->r->sgb;
	this->shb = this->r->shb;
	this->sge = this->r->sge;

	printf("\n== trap pc=0x%x syscall=%d fp=0x%x ==\n",
	    this->pc, this->x8, this->fp);
}

/* Frame 0: ra at [fp+8], next fp at [fp]. */
carrick*:::vcpu-trap
/INREG(this->fp)/
{
	this->ra = *(uint64_t *) copyin(XL(this->fp + 8), 8);
	this->nf = *(uint64_t *) copyin(XL(this->fp), 8);
	printf("  #0  0x%x\n", this->ra);
}

/* Frame 1. */
carrick*:::vcpu-trap
/INREG(this->nf)/
{
	this->ra = *(uint64_t *) copyin(XL(this->nf + 8), 8);
	this->nf = *(uint64_t *) copyin(XL(this->nf), 8);
	printf("  #1  0x%x\n", this->ra);
}

/* Frame 2. */
carrick*:::vcpu-trap
/INREG(this->nf)/
{
	this->ra = *(uint64_t *) copyin(XL(this->nf + 8), 8);
	this->nf = *(uint64_t *) copyin(XL(this->nf), 8);
	printf("  #2  0x%x\n", this->ra);
}

/* Frame 3. */
carrick*:::vcpu-trap
/INREG(this->nf)/
{
	this->ra = *(uint64_t *) copyin(XL(this->nf + 8), 8);
	this->nf = *(uint64_t *) copyin(XL(this->nf), 8);
	printf("  #3  0x%x\n", this->ra);
}

/* Frame 4. */
carrick*:::vcpu-trap
/INREG(this->nf)/
{
	this->ra = *(uint64_t *) copyin(XL(this->nf + 8), 8);
	printf("  #4  0x%x\n", this->ra);
}

dtrace:::END
{
	printf("\nguest_stack.d: done\n");
}
