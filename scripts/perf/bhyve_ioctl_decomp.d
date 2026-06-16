/*
 * Decompose carrick-bhyve's per-guest-syscall HOST cost on FreeBSD (native dtrace).
 *
 * carrick's x86 backends service each guest syscall via an OUT-port doorbell
 * (a VM exit) plus a handful of register get/set ioctls. This script counts and
 * times every ioctl on the vmm device so we can split:
 *   - carrick overhead   = many VM_GET/SET_REGISTER ioctls per guest syscall
 *   - vm-entry/QEMU tax   = wall time concentrated in the VM_RUN ioctl
 *
 * Pair with a probe of known syscall count (perf_trap_floor = 22000 getpid
 * doorbells: 2000 warmup + 20000 timed) to get per-syscall ioctl counts.
 *
 * Usage (from /path/to/carrick):
 *   dtrace -s scripts/perf/bhyve_ioctl_decomp.d \
 *          -c "/bin/sh scripts/perf/freebsd-bhyve-probe.sh"
 */
#pragma D option quiet
#pragma D option dynvarsize=32m

BEGIN { wall0 = timestamp; }

syscall::ioctl:entry
/pid == $target || progenyof($target)/
{ self->ts = timestamp; self->req = arg1; }

syscall::ioctl:return
/self->ts/
{
	@cnt[self->req]  = count();
	@tot[self->req]  = sum(timestamp - self->ts);
	@lat[self->req]  = quantize(timestamp - self->ts);
	@all_ns  = sum(timestamp - self->ts);
	@all_cnt = count();
	self->ts = 0;
}

/* every host syscall the carrick process issues, by name (where else time goes) */
syscall:::entry
/pid == $target || progenyof($target)/
{ @sysc[probefunc] = count(); @sysall = count(); }

tick-1s { secs++; }
tick-1s /secs >= 60/ { exit(0); }

END {
	printf("wall_ns = %d\n", timestamp - wall0);
	printf("\n=== host ioctl COUNT by request code ===\n");
	printa("  req=0x%08x  cnt=%@d\n", @cnt);
	printf("\n=== host ioctl TOTAL-ns by request code ===\n");
	printa("  req=0x%08x  ns=%@d\n", @tot);
	printf("\n=== grand totals ===\n");
	printa("  total_ioctls    = %@d\n", @all_cnt);
	printa("  total_ioctl_ns  = %@d\n", @all_ns);
	printa("  total_syscalls  = %@d\n", @sysall);
	printf("\n=== host syscalls by name (top) ===\n");
	trunc(@sysc, 14);
	printa("  %-18s %@d\n", @sysc);
	printf("\n=== per-request ioctl latency (ns) ===\n");
	printa(@lat);
}
