#pragma D option quiet
#pragma D option bufsize=16m
#pragma D option aggsize=8m
#pragma D option dynvarsize=16m

/*
 * WHERE IS THE PER-FORK OVERHEAD?
 *
 * Measured: fork+child-exit+reap costs ~4.6ms under carrick vs ~530us native
 * macOS, and the extra ~4.1ms is NOT cpu (child burns ~939us), NOT the
 * multithreaded quiesce (skipped entirely at threads=0), NOT scaling with thread
 * count or mapped footprint. So it is blocking latency -- and blocking latency is
 * only explained by naming the HOST SYSCALL we are blocked inside.
 *
 * This attributes every host syscall's WALL time, and separately the OFF-CPU time
 * accumulated while inside it, per process role. `proc:::create` builds the pid
 * set so forked children (a guest fork makes a NEW host process) are followed.
 */

dtrace:::BEGIN
{
    printf("fork-cost-attribution: target=%d\n", $target);
    start = timestamp;
    track[$target] = 1;
    parent = $target;
}

proc:::create
/track[curpsinfo->pr_pid]/
{
    track[args[0]->pr_pid] = 1;
    @forks = count();
    child_born[args[0]->pr_pid] = timestamp;
}

/* Child lifetime: born (fork) -> exited. This is the span the parent waits on. */
proc:::exit
/track[pid] && child_born[pid]/
{
    @child_life_ns = sum(timestamp - child_born[pid]);
    @child_life_hist = quantize((timestamp - child_born[pid]) / 1000);
    child_born[pid] = 0;
}

/* Every host syscall: total wall time and count, split parent vs child. */
syscall:::entry
/track[pid]/
{
    self->sc_start = timestamp;
    self->sc_off = 0;
}

syscall:::return
/self->sc_start/
{
    this->wall = timestamp - self->sc_start;
    @sc_wall[pid == parent ? "parent" : "child", probefunc] = sum(this->wall);
    @sc_count[pid == parent ? "parent" : "child", probefunc] = count();
    @sc_off[pid == parent ? "parent" : "child", probefunc] = sum(self->sc_off);
    self->sc_start = 0;
    self->sc_off = 0;
}

/* Off-CPU while inside a syscall: attribute the blocked time to that syscall. */
sched:::off-cpu
/track[pid] && self->sc_start/
{
    self->off_ts = timestamp;
}

sched:::on-cpu
/self->off_ts/
{
    self->sc_off += timestamp - self->off_ts;
    @off_total = sum(timestamp - self->off_ts);
    self->off_ts = 0;
}

/* Time NOT inside any syscall (pure user-space execution incl. JIT/rebuild). */
sched:::off-cpu
/track[pid] && !self->sc_start/
{
    self->uoff_ts = timestamp;
}

sched:::on-cpu
/self->uoff_ts/
{
    @off_outside_syscall = sum(timestamp - self->uoff_ts);
    self->uoff_ts = 0;
}

dtrace:::END
{
    printf("\n== forks ==\n");            printa("%@d\n", @forks);
    printf("\n== child lifetime total ns (fork -> exit) ==\n"); printa("%@d\n", @child_life_ns);
    printf("\n== child lifetime distribution (us) ==\n");       printa("%@d\n", @child_life_hist);
    printf("\n== off-CPU inside syscalls (ns) ==\n");           printa("%@d\n", @off_total);
    printf("\n== off-CPU OUTSIDE syscalls (ns) ==\n");          printa("%@d\n", @off_outside_syscall);

    printf("\n== TOP host syscalls by TOTAL WALL ns (role, syscall) ==\n");
    trunc(@sc_wall, 18);
    printa("  %-7s %-22s %@d\n", @sc_wall);

    printf("\n== same syscalls: OFF-CPU ns (how much of that wall was blocked) ==\n");
    trunc(@sc_off, 18);
    printa("  %-7s %-22s %@d\n", @sc_off);

    printf("\n== call counts ==\n");
    trunc(@sc_count, 18);
    printa("  %-7s %-22s %@d\n", @sc_count);
}
