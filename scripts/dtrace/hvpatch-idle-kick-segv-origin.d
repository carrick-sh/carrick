#!/usr/sbin/dtrace -Zqs
/*
 * hvpatch-idle-kick-segv-origin.d - which fault ends a signed embed run with a
 * guest SIGSEGV, and whether an idle-entry EL0 kick (#890) preceded it.
 *
 * (a) WHAT IT MEASURES
 * --------------------
 * Question from #900: with the idle-entry EL0 kick owed to the EL1 scheduler
 * IRQ boundary, `el1_fork_cow_resolves_in_guest` ends with exit 139 more often
 * than main. Are those the faults main reaches later (runs that used to die at
 * the #885 zone fatal), or a new fault? Per run it prints:
 *   KICK4   every `kick-rearm-irq` with site 4 (idle-entry EL0, owed to the
 *           EL1 IRQ boundary; never fires on main, which has no site 4)
 *   cancel_el0 (END census only) `vcpu-canceled` at EL0, the raw kicks that
 *           can feed KICK4; most land on host-loaded tasks, not idle entry
 *   FAULT   every `vcpu-fault` (EL0 abort HVF surfaced to the host) and
 *           `hvpatch-guest-fault` (with Linux guest pid/tid)
 *   DELIVER `hvpatch-fault-delivery` / `hvpatch-fault-terminal` (the host
 *           lowered a fault to a signal or a terminal)
 *   SIG11   `signal-publish` of signum 11 (did not fire for any fault-lowered
 *           SIGSEGV in the #900 A/B: those surface only as DELIVER/FTERM)
 *   EXIT    `hvpatch-guest-exit` and `hvpatch-thread-terminal`
 *   TERMERR `hvpatch-terminal-error` with its formatted error
 *   NFAULT  `hvpatch-native-fault-supply` phases other than Cow/Supplied
 *           (Backing, Refused, OwnerWait, BackingFault, Unselected), with an
 *           END count per phase: the host's answer to a native owner fault
 *   REFUSE  `hvpatch-native-crossing-refused`, `el1-grant-refusal`,
 *           `el1-native-fork-refusal`, `el1-zone-capture-missing`,
 *           `el1-task-record-stale`
 * and an END census. Faults EL1 serves in the ring (native owners) do not
 * surface here; a SIGSEGV exit with no FAULT/DELIVER line was decided in the
 * ring, which is itself the answer to "where".
 *
 * (b) PROVIDER ABI (from `carrick-observability` probe declarations)
 * ------------------------------------------------------------------
 *   kick-rearm-irq (u64 pc, u32 site, u64 el0_pstate, u64 elr_el1)
 *   vcpu-canceled (u64 vcpu, u64 pc, u32 el, i32 resumed_mid_el1)
 *   vcpu-fault (u64 esr, u64 elr, u64 far, u64 x30, u64 sp, i32 tid)
 *   hvpatch-guest-fault (u64 esr, u64 elr, u64 far, i32 guest_pid, i32 guest_tid)
 *   hvpatch-fault-delivery (u64 far, i32 incoming, i32 delivered, u32 bus, i32 tid)
 *   hvpatch-fault-terminal (u64 far, i32 signum, i32 si_code, i32 tid)
 *   signal-publish (i32 target_tid, i32 signum, i32 kind)
 *   hvpatch-guest-exit (i32 guest_pid, i32 guest_tid, u32 asid, i64 status)
 *   Session end, qualified live on cloudmac (macOS 27, 2026-10-27): neither
 *   `proc:::exit` nor `syscall::exit:entry` fired for the process that
 *   emitted the guest probes (it is reaped, not exited), and `lifecycle`
 *   did not fire in the signed `el1_sched` executable; sessions armed on
 *   them ran to their bound. The session therefore ends after 60 s with no
 *   matching probe once one has fired.
 *   hvpatch-thread-terminal (i32 pid, i32 linux_tid, i32 registry_tid, u32 reason, i32 detail)
 *   hvpatch-terminal-error (i32 pid, i32 tid, char *error)
 *   hvpatch-native-fault-supply (u64 mm, u64 sequence, u32 phase, u64 page, u64 len)
 *     phase: 0 Cow, 1 Backing, 2 Supplied, 3 Refused, 4 OwnerWait,
 *     5 BackingFault, 6 Unselected
 *   hvpatch-native-crossing-refused (u64, u64, u32, u64, u64)
 *   el1-grant-refusal (u32, u64, u64, u64, u64)
 *   el1-native-fork-refusal (u32, u64, u64, char *)
 *   el1-zone-capture-missing (u64, u64)
 *   el1-task-record-stale (u64, u64, u64, u64, u64)
 * Scope: the signed embed test executable (`execname` starts `el1_sched`)
 * and its progeny; run it only while no other lane runs `el1_sched` on the
 * host. Arm with `-Z` (the executable starts after arming). The session ends
 * itself 60 s after the last matching probe, or after `$1` seconds
 * (`dtrace -Z -s this.d 900`). SIP refuses
 * `dtrace -c /bin/sh` on macOS ("failed to execute /bin/sh: Operation not
 * permitted"), so a `-c` waiter cannot bound it; never signal dtrace.
 *
 * (c) PERTURBATION
 * ----------------
 * Low-frequency probes only: kicks, cancellations, faults, signals and
 * terminals. No syscall, exit-class or scheduler hot path is instrumented.
 * Zero KICK4 lines on the fix means the probe did not fire in that run, not
 * that no kick landed elsewhere.
 */

#pragma D option quiet
#pragma D option strsize=512

dtrace:::BEGIN { kick4 = 0; cancel0 = 0; faults = 0; sig11 = 0; secs = 0; last = 0; }

tick-5s
/last != 0 && timestamp - last > 60000000000/
{
	printf("QUIET|secs=%d\n", secs);
	exit(0);
}

tick-1s
/++secs > $1/
{
	printf("BOUND|secs=%d\n", secs);
	exit(0);
}

carrick*:::kick-rearm-irq
/strstr(execname, "el1_sched") != NULL && arg1 == 4/
{
	last = timestamp;
	kick4++;
	printf("KICK4|ns=%d|pid=%d|tid=%d|pc=0x%x|pstate=0x%x|elr=0x%x\n",
	    timestamp, pid, tid, arg0, arg2, arg3);
}

carrick*:::vcpu-canceled
/strstr(execname, "el1_sched") != NULL && arg2 == 0/
{
	last = timestamp;
	cancel0++;
}

carrick*:::vcpu-fault
/strstr(execname, "el1_sched") != NULL/
{
	last = timestamp;
	faults++;
	printf("FAULT|ns=%d|pid=%d|esr=0x%x|elr=0x%x|far=0x%x|x30=0x%x|sp=0x%x|tid=%d\n",
	    timestamp, pid, arg0, arg1, arg2, arg3, arg4, (int)arg5);
}

carrick*:::hvpatch-guest-fault
/strstr(execname, "el1_sched") != NULL/
{
	last = timestamp;
	printf("GFAULT|ns=%d|esr=0x%x|elr=0x%x|far=0x%x|guest_pid=%d|guest_tid=%d\n",
	    timestamp, arg0, arg1, arg2, (int)arg3, (int)arg4);
}

carrick*:::hvpatch-fault-delivery
/strstr(execname, "el1_sched") != NULL/
{
	last = timestamp;
	printf("DELIVER|ns=%d|far=0x%x|incoming=%d|delivered=%d|bus=%d|tid=%d\n",
	    timestamp, arg0, (int)arg1, (int)arg2, (int)arg3, (int)arg4);
}

carrick*:::hvpatch-fault-terminal
/strstr(execname, "el1_sched") != NULL/
{
	last = timestamp;
	printf("FTERM|ns=%d|far=0x%x|signum=%d|si_code=%d|tid=%d\n",
	    timestamp, arg0, (int)arg1, (int)arg2, (int)arg3);
}

carrick*:::signal-publish
/strstr(execname, "el1_sched") != NULL && arg1 == 11/
{
	last = timestamp;
	sig11++;
	printf("SIG11|ns=%d|target_tid=%d|kind=%d\n", timestamp, (int)arg0, (int)arg2);
	ustack(12);
}

carrick*:::hvpatch-guest-exit
/strstr(execname, "el1_sched") != NULL/
{
	last = timestamp;
	printf("EXIT|ns=%d|guest_pid=%d|guest_tid=%d|asid=%u|status=%d\n",
	    timestamp, (int)arg0, (int)arg1, (uint32_t)arg2, (int64_t)arg3);
}

carrick*:::hvpatch-thread-terminal
/strstr(execname, "el1_sched") != NULL/
{
	last = timestamp;
	printf("TTERM|ns=%d|pid=%d|linux_tid=%d|registry_tid=%d|reason=%u|detail=%d\n",
	    timestamp, (int)arg0, (int)arg1, (int)arg2, (uint32_t)arg3, (int)arg4);
}

carrick*:::hvpatch-terminal-error
/strstr(execname, "el1_sched") != NULL/
{
	last = timestamp;
	printf("TERMERR|ns=%d|pid=%d|tid=%d|error=%s\n",
	    timestamp, (int)arg0, (int)arg1, copyinstr(arg2));
}

carrick*:::hvpatch-native-fault-supply
/strstr(execname, "el1_sched") != NULL/
{
	last = timestamp;
	@nfault[arg2] = count();
}

carrick*:::hvpatch-native-fault-supply
/strstr(execname, "el1_sched") != NULL && arg2 != 0 && arg2 != 2/
{
	last = timestamp;
	printf("NFAULT|ns=%d|mm=0x%x|seq=%d|phase=%d|page=0x%x|len=0x%x\n",
	    timestamp, arg0, arg1, (uint32_t)arg2, arg3, arg4);
}

carrick*:::hvpatch-native-crossing-refused
/strstr(execname, "el1_sched") != NULL/
{
	last = timestamp;
	printf("REFUSE|crossing|ns=%d|a=0x%x|b=0x%x|c=%u|d=0x%x|e=0x%x\n",
	    timestamp, arg0, arg1, (uint32_t)arg2, arg3, arg4);
}

carrick*:::el1-grant-refusal
/strstr(execname, "el1_sched") != NULL/
{
	last = timestamp;
	printf("REFUSE|grant|ns=%d|reason=%u|a=0x%x|b=0x%x|c=0x%x|d=0x%x\n",
	    timestamp, (uint32_t)arg0, arg1, arg2, arg3, arg4);
}

carrick*:::el1-native-fork-refusal
/strstr(execname, "el1_sched") != NULL/
{
	last = timestamp;
	printf("REFUSE|fork|ns=%d|reason=%u|a=0x%x|b=0x%x|detail=%s\n",
	    timestamp, (uint32_t)arg0, arg1, arg2, copyinstr(arg3));
}

carrick*:::el1-zone-capture-missing
/strstr(execname, "el1_sched") != NULL/
{
	last = timestamp;
	printf("REFUSE|capture-missing|ns=%d|a=0x%x|b=0x%x\n", timestamp, arg0, arg1);
}

carrick*:::el1-task-record-stale
/strstr(execname, "el1_sched") != NULL/
{
	last = timestamp;
	printf("REFUSE|record-stale|ns=%d|a=0x%x|b=0x%x|c=0x%x|d=0x%x|e=0x%x\n",
	    timestamp, arg0, arg1, arg2, arg3, arg4);
}

dtrace:::END
{
	printa("NFAULTCOUNT|phase=%d|count=%@d\n", @nfault);
	printf("CENSUS|kick4=%d|cancel_el0=%d|faults=%d|sig11=%d\n",
	    kick4, cancel0, faults, sig11);
}
