#!/usr/sbin/dtrace -Zqs
/*
 * hvpatch-mmap-shape-census.d — WHAT SHAPE are the guest `mmap` calls whose
 * service windows take all the zero-fill faults, on the kernel (hvpatch) lane?
 *
 * (a) WHAT IT MEASURES
 * -------------------
 * Every guest `mmap`, bucketed by (anonymous?, sharing, PROT_EXEC?) and by
 * length class, together with the zero-fill faults each bucket's service
 * window takes. Its sibling `hvpatch-mmap-fault-source.d` says WHICH CARRICK
 * CODE faults the pages (`__bzero` from the eager snapshot buffer at
 * `dispatch/mem.rs:2792`); this says WHICH GUEST REQUESTS reach that code, so
 * a lowering can be aimed at the population that actually exists rather than
 * at the one the code's guards imply.
 *
 * The question it was written for: the file-backed mmap lowering
 * (`mmap_file_backed_lowering_enabled`, default ON) refuses a mapping that
 * carries `PROT_EXEC`, on the grounds that executable content must flow
 * through the write path's W^X / translation-invalidation metadata. If the
 * fault-heavy population is mostly PROT_EXEC, that guard is the blocker and
 * relaxing it is a correctness argument to be made explicitly. If it is NOT,
 * the guard is a red herring and some other refusal is doing the work.
 *
 * (b) PROVIDER ABI FACTS, qualified rather than assumed
 * ----------------------------------------------------
 *   1. `carrick*:::hvpatch-syscall-args` publishes
 *      (number, args[0], args[1], args[2], args[3])
 *      (`crates/carrick-observability/src/probes.rs:4635`), so for `mmap`:
 *      **arg0=number, arg1=addr, arg2=length, arg3=prot, arg4=flags**.
 *      It is published ONLY when the identity-bearing
 *      `hvpatch-syscall-service-begin` fired, so a consumer can join the two
 *      on the same host thread and never sees an identity-free args record.
 *   2. `hvpatch-syscall-service-begin`/`-clear` carry the canonical syscall
 *      number in **arg3** (arg0 is the guest pid). 222 is `mmap` on the
 *      canonical AArch64 table.
 *   3. Linux flag/prot bits used here, from `carrick-abi`:
 *      `MAP_SHARED`=0x01, `MAP_PRIVATE`=0x02, `MAP_ANONYMOUS`=0x20
 *      (`lib.rs:2990`); `PROT_READ`=0x1, `PROT_WRITE`=0x2, `PROT_EXEC`=0x4.
 *   4. `dtrace -Z` is REQUIRED — the probes live in a process that has not
 *      started when this compiles.
 *
 * (c) READING IT
 * -------------
 * `MMAP_SHAPE` rows are counts of guest calls; `ZFOD_BY_SHAPE` rows are the
 * zero-fill faults taken inside those calls' service windows. Compare the two:
 * a shape with many calls and few faults is already lowered well, and a shape
 * with few calls and most of the faults is the whole target.
 *
 * Symbolication is not used here, so unlike the fault-source script this one
 * may print at `dtrace:::END`. It still snapshots on a tick so a run that is
 * interrupted still yields data.
 *
 * (d) PERTURBATION
 * ---------------
 * MODERATE — one clause per guest mmap plus the fault probes. COUNTS are the
 * claim; wall time under this script is never performance authority.
 *
 * (e) RUNNING IT
 * -------------
 * `-c` cannot exec the codesigned carrick binary. Arm first, then run the
 * workload separately:
 *
 *   sudo dtrace -Zqs scripts/dtrace/hvpatch-mmap-shape-census.d > out.txt &
 *   until grep -q ARMED out.txt; do sleep 2; done
 *   target/release/carrick run --exec-backend hvpatch <image> <workload>
 */
#pragma D option quiet
#pragma D option aggsize=64m
#pragma D option dynvarsize=64m
#pragma D option bufsize=64m

dtrace:::BEGIN
{
	printf("ARMED hvpatch-mmap-shape-census: start the workload now\n");
}

/*
 * The args probe fires immediately after `-begin` on the same thread, so the
 * shape is recorded before the window's faults can be attributed to it.
 */
carrick*:::hvpatch-syscall-args
/arg0 == 222/
{
	self->anon  = (arg4 & 0x20) ? "anon" : "file";
	self->share = (arg4 & 0x01) ? "shared" : ((arg4 & 0x02) ? "private" : "share?");
	self->exec  = (arg3 & 0x4) ? "X" : "-";
	self->write = (arg3 & 0x2) ? "W" : "-";
	self->read  = (arg3 & 0x1) ? "R" : "-";
	self->shape = strjoin(strjoin(strjoin(strjoin(strjoin(
	    self->anon, "/"), self->share), "/"),
	    strjoin(strjoin(self->read, self->write), self->exec)), "");
	self->len = arg2;
	@shape[self->shape] = count();
	@bytes[self->shape] = sum(arg2);
	@len_by_shape[self->shape] = quantize(arg2);
	@calls = count();
}

carrick*:::hvpatch-syscall-service-begin
/arg3 == 222/
{
	self->in_mmap = 1;
}

carrick*:::hvpatch-syscall-service-clear
{
	self->in_mmap = 0;
	self->shape = 0;
}

vminfo:::zfod
/self->in_mmap && self->shape != NULL/
{
	@zfod_by_shape[self->shape] = count();
	@zfod_total = count();
}

vminfo:::zfod
/self->in_mmap && self->shape == NULL/
{
	@zfod_by_shape["<no-args-record>"] = count();
	@zfod_total = count();
}

tick-5s
{
	printf("=== SNAPSHOT ===\n");
	printa("MMAP_SHAPE      %-24s %@8d\n", @shape);
	printa("MMAP_BYTES      %-24s %@12d\n", @bytes);
	printa("ZFOD_BY_SHAPE   %-24s %@8d\n", @zfod_by_shape);
	printa("MMAP_CALLS %@d\n", @calls);
	printa("INWINDOW_ZFOD %@d\n", @zfod_total);
}

dtrace:::END
{
	printf("=== FINAL ===\n");
	printa("MMAP_SHAPE      %-24s %@8d\n", @shape);
	printa("MMAP_BYTES      %-24s %@12d\n", @bytes);
	printa("ZFOD_BY_SHAPE   %-24s %@8d\n", @zfod_by_shape);
	printa("LEN_BY_SHAPE    %-24s %@d\n", @len_by_shape);
	printa("MMAP_CALLS %@d\n", @calls);
	printa("INWINDOW_ZFOD %@d\n", @zfod_total);
}
