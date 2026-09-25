#!/usr/sbin/dtrace -Zs
/*
 * hvpatch-pt-pause-drain-stall.d — why does a stage-1 page-table pause drain
 * wait, whom does it wait for, and does every kick it sends get served?
 *
 * (a) What it measures
 *       - A power-of-two histogram of every drain's wait (us, `pt-pause-ready`
 *         arg2) and of its wait rounds (arg1), so a stall is read against the
 *         population, not in isolation.
 *       - One SLOW-DRAIN row per drain >= 20 ms: coordinator tid, exact-MM
 *         census, first sibling in guest at begin, the kicks the coordinator
 *         itself issued (dead = LiveVcpuSlot named no vCPU; err = nonzero
 *         hv_vcpus_exit rc), and the coordinator's own off-CPU time inside the
 *         drain (a drain can be long because its COORDINATOR was descheduled).
 *       - DRAIN-WAIT rows naming each sibling still in guest on the first wait
 *         round (`pt-pause-drain-wait`).
 *       - A stall window: once a drain has been open >= 100 ms, host stacks of
 *         every other carrier thread on CPU (profile) and going off CPU
 *         (sched), printed from the probe clause so they symbolize while the
 *         carrier lives. A sibling on CPU inside `Hv::Vcpu::run` for the whole
 *         window is executing guest code and never saw its kick.
 *       - The kick ledger: KICK (coordinator only), CANCELED (`vcpu-canceled`,
 *         by HVF vCPU id and EL), REARM-IRQ (`kick-rearm-irq`: a kick absorbed
 *         in Carrick's EL1 code and owed to EL0, with the EL0 PSTATE it will
 *         return into), and how each owed kick ended: `irq-kick-taken`,
 *         `rearm-served` (IRQ or a second cancel), or
 *         `rearm-superseded-by-syscall-exit`. `owed-kick-settle` splits the
 *         settles by where the vCPU stopped and whether EL0 ran IRQ-unmasked.
 *
 * (b) Provider ABI facts qualified live on this host (macOS 27.2, M4, carrick
 *     release build with `__DATA,__dof_carrick`):
 *       * USDT names lower `__` to `-` (`pt-pause-begin`) but keep a single
 *         `_`: `kick__in_kernel` is `kick-in_kernel`. A misspelled name lists
 *         nothing and silently counts zero. `-Z` is required because the
 *         carrier is spawned after arming.
 *       * Every clause screens `pid == $target || progenyof($target)`: other
 *         agents' guests share `carrick*:::`.
 *       * `pt-pause-begin` = (coordinator_tid, any_in_guest, first_in_guest_tid,
 *         census) as i32; `pt-pause-ready` = (tid, wait_rounds, wait_us);
 *         `pt-pause-drain-wait` = (coordinator, sibling, wait_us);
 *         `vcpu-kick` = (id u64, valid, rc); `vcpu-canceled` = (id, pc, el,
 *         resumed_mid_el1); `kick-rearm-irq` = (pc, site 1 vector / 2 EL1
 *         image / 3 clock stub, el0_pstate, elr_el1); `owed-kick-settle` =
 *         (pc, pstate, el0_state).
 *       * Carrick's ustack frames do not symbolize after the carrier exits;
 *         the stall clause prints from the probe so they do while it lives.
 *       * The page-table barrier is per MM: g_drain tracks one open drain, which
 *         is exact for the single-process Go suites this was written for and
 *         approximate when two traced processes pause at once.
 *       * `pt-pause-timeout` no longer fires (the drain has no deadline); the
 *         clauses stay so an older binary still reports its timeouts.
 *
 * (c) Perturbation
 *     Low on the pause path (probes fire per pause and per kick). The stall
 *     window adds profile-997 and sched sampling of one carrier only while a
 *     drain is >= 100 ms old. Histograms are same-instrument only.
 *
 * Usage:
 *   carrick trace -s scripts/dtrace/hvpatch-pt-pause-drain-stall.d -o out -- \
 *     run -w /usr/local/go/src/time \
 *     localhost:5005/carrick-go-conformance:1.24 /conformance/time.test -test.short
 */

#pragma D option quiet
#pragma D option bufsize=16m
#pragma D option switchrate=20hz

/*
 * The open drain in this carrier (see the per-MM caveat above). Globals are
 * defined in BEGIN, not by C-style declarations: `carrick trace`'s compile
 * rejects a top-level `uint64_t g_drain;` with "syntax error near ;" even
 * though `dtrace -e` accepts it, and a predicate naming a global before any
 * clause assigns it fails with "Unknown variable name".
 */
dtrace:::BEGIN
{
	g_drain = (uint64_t)0;
	g_pid = 0;
	g_coord = 0;
	g_stall = 0;
	secs = 0;
	settle_samples = 0;
}

carrick*:::pt-pause-begin
/pid == $target || progenyof($target)/
{
	self->drain = timestamp;
	self->census = arg3;
	self->first = arg2;
	self->kicks = 0;
	self->deadkicks = 0;
	self->errkicks = 0;
	self->offtotal = 0;
	self->offmax = 0;
	self->off = 0;
}

carrick*:::vcpu-kick
/(pid == $target || progenyof($target)) && self->drain/
{
	self->kicks++;
	self->deadkicks += arg1 == 0 ? 1 : 0;
	self->errkicks += (arg1 != 0 && arg2 != 0) ? 1 : 0;
}

/*
 * Kick delivery ledger while a drain is open: every kick the coordinator
 * issued, every CANCELED run return (by HVF vCPU id, so a kick id with no
 * matching cancel never stopped a running vCPU), every kick the engine owed to
 * EL0. Each row carries `open_us` relative to the open drain; read the rows of
 * a stalled drain by its STALL-OPEN time and pid (per-CPU buffers interleave,
 * so sort by the leading wall-clock ms).
 */
carrick*:::vcpu-kick
/(pid == $target || progenyof($target)) && g_drain && tid == g_coord/
{
	printf("%d KICK pid=%d thread=%d vcpu=%d valid=%d rc=%d open_us=%d\n",
	    walltimestamp / 1000000, pid, tid, arg0, arg1, arg2, (timestamp - g_drain) / 1000);
}

carrick*:::vcpu-canceled
/(pid == $target || progenyof($target)) && g_drain/
{
	printf("%d CANCELED pid=%d thread=%d vcpu=%d pc=0x%x el=%d resumed=%d open_us=%d\n",
	    walltimestamp / 1000000, pid, tid, arg0, arg1, arg2, arg3, (timestamp - g_drain) / 1000);
}

/*
 * How each owed kick (a kick the engine absorbed inside Carrick's EL1 code and
 * owes to the next EL0 boundary) ends: served by the virtual IRQ at EL0
 * (`vcpu-irq-kick`), by a second CANCELED, or superseded by a surfaced
 * syscall exit (a kick absorbed on the vector's way INTO the host). An owed
 * kick with none of these outcomes is a lost kick.
 */
carrick*:::kick-rearm-irq
/pid == $target || progenyof($target)/
{
	self->rearm = timestamp;
}

carrick*:::vcpu-irq-kick
/self->rearm && g_drain/
{
	printf("%d IRQ-KICK-TAKEN pid=%d thread=%d el0_pc=0x%x after_us=%d\n",
	    walltimestamp / 1000000, pid, tid, arg0, (timestamp - self->rearm) / 1000);
}

carrick*:::vcpu-canceled,
carrick*:::vcpu-irq-kick
/self->rearm/
{
	@c["rearm-served"] = count();
	self->rearm = 0;
}

/*
 * A surfaced syscall exit also clears HVF's pending IRQ, but the thread then
 * leaves guest (in-guest flag down), so the kick's purpose is met; it is not
 * a drop.
 */
carrick*:::hvpatch-syscall-service-begin
/self->rearm/
{
	@c["rearm-superseded-by-syscall-exit"] = count();
	self->rearm = 0;
}

carrick*:::kick-rearm-irq
/(pid == $target || progenyof($target)) && g_drain/
{
	printf("%d REARM-IRQ pid=%d thread=%d pc=0x%x where=%d el0_pstate=0x%x elr_el1=0x%x open_us=%d\n",
	    walltimestamp / 1000000, pid, tid, arg0, arg1, arg2, arg3, (timestamp - g_drain) / 1000);
}

carrick*:::pt-pause-drain-wait
/pid == $target || progenyof($target)/
{
	printf("%d DRAIN-WAIT pid=%d coord=%d still_in_guest=%d wait_us=%d\n",
	    walltimestamp / 1000000, pid, arg0, arg1, arg2);
}

carrick*:::kick-in_kernel
/pid == $target || progenyof($target)/
{
	@c["kick-resumed-mid-el1"] = count();
}

carrick*:::pt-pause-ready
/(pid == $target || progenyof($target)) && self->drain/
{
	@c["drain-ready"] = count();
	@lat["drain-ready-us"] = quantize(arg2);
	@spins["drain-wait-rounds"] = quantize(arg1);
}

carrick*:::pt-pause-ready
/(pid == $target || progenyof($target)) && self->drain && arg2 >= 20000/
{
	printf("%d SLOW-DRAIN pid=%d coord=%d census=%d first_in_guest=%d kicks=%d dead=%d err=%d wait_us=%d rounds=%d coord_off_us=%d coord_max_off_us=%d\n",
	    walltimestamp / 1000000, pid, arg0, self->census, self->first,
	    self->kicks, self->deadkicks, self->errkicks, arg2, arg1,
	    self->offtotal / 1000, self->offmax / 1000);
}

carrick*:::pt-pause-timeout
/(pid == $target || progenyof($target))/
{
	@c["drain-TIMEOUT"] = count();
	printf("%d DRAIN-TIMEOUT pid=%d coord=%d census=%d first_in_guest=%d kicks=%d dead=%d err=%d wait_us=%d coord_off_us=%d coord_max_off_us=%d\n",
	    walltimestamp / 1000000, pid, arg0, self->census, self->first,
	    self->kicks, self->deadkicks, self->errkicks, arg1,
	    self->offtotal / 1000, self->offmax / 1000);
}

carrick*:::pt-pause-election-timeout
/(pid == $target || progenyof($target))/
{
	@c["election-TIMEOUT"] = count();
	printf("%d ELECTION-TIMEOUT pid=%d tid=%d wait_us=%d\n",
	    walltimestamp / 1000000, pid, arg0, arg1);
}

/*
 * The coordinator's own schedulability during its drain: time spent off CPU
 * inside the drain window. A drain whose coordinator was descheduled for most
 * of its budget did not wait on its siblings at all.
 */
sched:::off-cpu
/self->drain/
{
	self->off = timestamp;
}

sched:::on-cpu
/self->drain && self->off/
{
	this->d = timestamp - self->off;
	self->offtotal += this->d;
	self->offmax = this->d > self->offmax ? this->d : self->offmax;
	self->off = 0;
}

/*
 * Stall window: a global names the open drain (see the per-MM caveat in the
 * header). Once it has been open >= 100
 * ms, sample every OTHER host thread of that carrier on CPU (profile) and going
 * off CPU (sched), so the stuck sibling's host stack names what it is doing:
 * still in `hv_vcpu_run`, runnable-but-descheduled, or blocked in host code
 * with its in-guest flag still raised.
 */
carrick*:::pt-pause-begin
/pid == $target || progenyof($target)/
{
	g_drain = timestamp;
	g_pid = pid;
	g_coord = tid;
}

tick-10ms
/g_drain && timestamp - g_drain > 100000000 && !g_stall/
{
	g_stall = 1;
	printf("%d STALL-OPEN pid=%d coord_thread=%d open_ms=%d\n",
	    walltimestamp / 1000000, g_pid, g_coord, (timestamp - g_drain) / 1000000);
}

profile-997
/g_stall && pid == g_pid && tid != g_coord/
{
	@oncpu[tid, ustack(14)] = count();
}

profile-997
/g_stall && pid == g_pid && tid == g_coord/
{
	@coord_oncpu[ustack(8)] = count();
}

sched:::off-cpu
/g_stall && pid == g_pid && tid != g_coord/
{
	@offcpu[tid, ustack(14)] = count();
}

/*
 * Print the stall's stacks from the probe clause itself: the consumer then
 * symbolizes them within one switchrate period, while the carrier is still
 * alive. An END-time dump of a carrier that already died prints bare hex.
 */
carrick*:::pt-pause-ready,
carrick*:::pt-pause-timeout
/(pid == $target || progenyof($target)) && tid == g_coord && g_stall/
{
	printf("%d STALL-CLOSE pid=%d open_ms=%d\n", walltimestamp / 1000000, pid,
	    (timestamp - g_drain) / 1000000);
	printf("--- sibling threads ON cpu during the stall (tid, stack, samples)\n");
	printa(@oncpu);
	printf("--- sibling threads going OFF cpu during the stall\n");
	printa(@offcpu);
	printf("--- coordinator on cpu during the stall\n");
	printa(@coord_oncpu);
	trunc(@oncpu);
	trunc(@offcpu);
	trunc(@coord_oncpu);
}

carrick*:::pt-pause-ready,
carrick*:::pt-pause-timeout
/(pid == $target || progenyof($target)) && tid == g_coord/
{
	g_drain = 0;
	g_stall = 0;
}

carrick*:::pt-pause-ready,
carrick*:::pt-pause-timeout
/(pid == $target || progenyof($target))/
{
	self->drain = 0;
}

/* End with the traced CLI so `carrick trace` never lingers on a live consumer. */
proc:::exit
/pid == $target/
{
	exit(0);
}

/* Hard bound: never stream forever from a wedged guest. */
tick-1s
{
	secs++;
}

tick-1s
/secs >= 900/
{
	exit(0);
}

/*
 * How owed kicks end: the EL0 return state's I bit at settle time (I clear =
 * EL0 ran unmasked with the IRQ armed, yet a different exit surfaced first).
 */
carrick*:::owed-kick-settle
/pid == $target || progenyof($target)/
{
	@settle[(arg1 & 0xf) == 0 ? "settle-at-el0" : "settle-at-el1",
	    (arg2 & 0x80) ? "el0-I-masked" : "el0-I-clear"] = count();
}

carrick*:::owed-kick-settle
/(pid == $target || progenyof($target)) && settle_samples < 20/
{
	settle_samples++;
	printf("%d OWED-SETTLE pid=%d thread=%d pc=0x%x pstate=0x%x el0_state=0x%x\n",
	    walltimestamp / 1000000, pid, tid, arg0, arg1, arg2);
}

carrick*:::vcpu-irq-kick
/pid == $target || progenyof($target)/
{
	@c["irq-kick-taken"] = count();
}

carrick*:::kick-rearm-irq
/pid == $target || progenyof($target)/
{
	@c["kick-owed"] = count();
}
