#!/usr/sbin/dtrace -qs
/*
 * Which native-child host crossings does the carrier refuse, by syscall
 * ordinal? A refused crossing returns a counted ENOSYS to the guest
 * (service.rs `HostFile`/`Crossing` + `ServiceResult::Refused`), so this
 * names the exact syscalls behind "Function not implemented" in a forked
 * child. A refusal that never fires this probe came from a ring-side check
 * instead, which this script cannot see: zero events means the refusal
 * is elsewhere, never that nothing was refused (#1335).
 *
 * Since #1530, a fork child's unclaimed syscall ordinal (an unknown or
 * Forward-only row, including an unserved exec) is refused in ring with a
 * counted ENOSYS (`Counters::refused`, carrick-el1-linux
 * `native_unstaged_exit`) and never reaches the carrier, so it no longer
 * fires this probe. The probe still fires for host file venue refusals and
 * for root/unowned native crossings. The qualification lines below predate
 * that change.
 *
 * What it measures: every carrick*:::hvpatch-native-crossing-refused event,
 * counted by ordinal (AArch64 syscall number) and child mm, plus a
 * timestamped line per event.
 *
 * Provider ABI (crates/carrick-observability/src/probes.rs,
 * `hvpatch_native_crossing_refused`): arg0 mm u64, arg1 incarnation u64,
 * arg2 record u32, arg3 sequence u64, arg4 ordinal u64. A host file venue
 * refusal reports 0x10000 + its HostFileOp wire value as the ordinal
 * (`carrick_core_abi::host_file::refusal_ordinal`; e.g. 65548 = Poll, 65537 =
 * Write), never a syscall number. Before #894's slice it reported 0, which
 * read as io_setup in the qualification below. Fired from
 * crates/carrick-vmm-hvf/src/metadata_grant/native_service.rs (`refuse` for
 * Crossing operations, `refuse_host_file` for host file venue refusals).
 *
 * Perturbation: one event per refused crossing; refusals are already the
 * slow path, so the cost is negligible next to the crossing itself.
 *
 * Live-qualified 2026-11-01 on macOS / arm64, main 09d43ed824, running
 * `carrick run --fs host localhost:5050/ltp:arm64 /bin/sh -c 'mkdir /tmp/b;
 * (: > /tmp/sub); ls -ld /tmp'`: the probe fires for forked children with
 * ordinals 34 mkdirat, 43 statfs, 198 socket, 222 mmap, 278 getrandom,
 * 29 ioctl, 9 lgetxattr, 11 llistxattr and 0 io_setup (io_setup is
 * Counted-ENOSYS by design). The admitted-credentials gate in
 * `begin_host_file_service` was measured NOT to refuse forked children (they
 * equal TaskCredentials::ROOT in ring; #1335).
 * Also live-qualified on the same binary with `(echo a | cat)`: exactly one
 * event, ordinal 59 pipe2 from the child (mm 2), the Temporary-forward row a
 * native child cannot forward (#1346).
 */
carrick*:::hvpatch-native-crossing-refused
{
	printf("%d refused ordinal=%d mm=%d inc=%d record=%d seq=%d\n",
	    timestamp, arg4, arg0, arg1, arg2, arg3);
	@refused[arg4] = count();
}

/*
 * Bound the session. carrick trace fails a script still running 60 s after
 * its child ends, so end with the traced CLI, plus a backstop under that.
 */
proc:::exit
/pid == $target/
{
	exit(0);
}

tick-45s
{
	exit(0);
}

END
{
	printf("\n== refused crossings by ordinal (AArch64 nr) ==\n");
	printa("  nr %-6d %@d\n", @refused);
}
