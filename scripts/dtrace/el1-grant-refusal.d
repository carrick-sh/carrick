#pragma D option quiet
/*
 * WHY DID PHYSICAL SUPPLY DECLINE AN OWNER-SELECTED WINDOW?
 * (a) Reports refused immutable window identity and overlapping physical
 *     aliases. It reads no guest bytes and grants no host policy authority.
 * (b) Source ABI el1-grant-refusal(row,a,b,c,d): row 11 means preparation
 *     declined, row 21 means service withdrew; units digit 1 is carrier/MM/
 *     incarnation/reservation-generation; digit 2 is start/len/protection/
 *     fault-page; digit 3 is source-handle/source-generation/offset/operation.
 *     hvpatch-el1-owner-grant-supply phase 8 is alias VA/size/owner-generation,
 *     9 is IPA/size/scope, 10 is fault-page/residency-size/owner-generation,
 *     11 is semantic-base/expected-IPA/physical-base. Row 24 is service errno,
 *     slot, wait cause and wait revision. These phase ABIs were
 *     live-qualified by el1-host-read-progress.d; this script must itself be
 *     qualified against the exact diagnostic artifact before drawing claims.
 *     Live-qualified 2026-10-04: g01 and g02 reproduced the unclaimed grant
 *     withdrawal. g02 SHA256
 *     6b7457e5b2dedfbc53cc8d9b5ac164c73347ff6d34039052ce551cca81a419ad
 *     returned diagnostic route 23: no open AddressSpaces grant, before the
 *     editor and descriptor claim. MM 2/incarnation 1/generation 0x350,
 *     anonymous RW page 0x6000008000; no overlap events. That temporary
 *     route tag and pre-carrier hold are absent from the production repair.
 *     Production now encodes authenticated waits in row 24 instead.
 *     hvpatch-thread-terminal reason 6 reports external settlement without
 *     a logical result: Linux pid/tid, registry tid, reason, production phase.
 *     It is included only for that failure, to correlate a removed peer with
 *     an unresolved join. g08 live-qualified reason 6/phase 14 for Linux
 *     tid 1 during the terminal-publication failure; g06 qualified row 24
 *     errno 11 / Editor cause 2 and completed successfully after that wait.
 *     guest-internal-write-fault phase 25 reports a failed clear_child_tid
 *     copy before the existing unconditional wake. arg0/1 are VA/length;
 *     arg3 is the USDT error string. Source-qualified pending live evidence.
 * (c) Only failed preparation emits the new probe. Existing overlap probes
 *     include peer-resident re-selections, so perturbation is proportional to
 *     conflicts, not syscalls. No events is failure, never absence evidence.
 *     Attach with dtrace -Z -p to the signed embed test during a diagnostic
 *     pre-carrier hold; that hold must be removed from acceptance artifacts.
 */
dtrace:::BEGIN { failures = 0; }
carrick*:::hvpatch-el1-owner-grant-supply
/(pid == $target || progenyof($target)) && arg2 >= 8 && arg2 <= 11/
{
    printf("GRANT1|ns=%d|pid=%d|tid=%d|phase=%d|a=0x%x|b=0x%x|d=0x%x\n",
        timestamp, pid, tid, arg2, arg0, arg1, arg3);
}
carrick*:::el1-grant-refusal
/pid == $target || progenyof($target)/
{
    failures++;
    printf("GRANT1|ns=%d|pid=%d|tid=%d|REFUSAL|row=%d|a=0x%x|b=0x%x|c=0x%x|d=0x%x\n",
        timestamp, pid, tid, arg0, arg1, arg2, arg3, arg4);
}
tick-1s { seconds++; }
carrick*:::guest-internal-write-fault
/(pid == $target || progenyof($target)) && arg2 == 25/
{
    failures++;
    printf("GRANT1|ns=%d|pid=%d|tid=%d|CLEAR_TID|va=0x%x|len=%d|error=%s\n",
        timestamp, pid, tid, arg0, arg1, copyinstr(arg3));
    ustack(24);
}
carrick*:::hvpatch-thread-terminal
/(pid == $target || progenyof($target)) && arg3 == 6/
{
    failures++;
    printf("GRANT1|ns=%d|pid=%d|tid=%d|TERMINAL|linux_pid=%d|linux_tid=%d|registry_tid=%d|reason=%d|phase=%d\n",
        timestamp, pid, tid, arg0, arg1, arg2, arg3, arg4);
    ustack(24);
}
tick-1s /seconds >= 30/ { exit(failures == 0 ? 1 : 0); }
END { printf("GRANT1|failure_rows=%d\n", failures); }
