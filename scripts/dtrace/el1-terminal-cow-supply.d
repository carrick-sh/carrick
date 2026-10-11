#pragma D option quiet
/*
 * WHICH OWNER SUPPLY REPEATS DURING TERMINAL CLEAR-CHILD-TID?
 * (a) Counts the exact host predecessor and supply outcomes, printing only
 *     the first 16 requests so a recursive failure cannot flood the trace.
 * (b) Source ABI: hvpatch-el1-owner-grant-supply(va,len,phase,detail);
 *     phase 6 is deferred-return reconciliation count, phase 7 is the
 *     boolean physical supply result. guest-internal-write-fault phase 26
 *     carries the COW scope refusal text. Verify a nonzero phase-7 count
 *     before interpreting its absence. Qualified against the signed ARM
 *     el1_sched binary after cbdde340d: terminal service reached supply.
 *     On 2026-10-11 diag-l, 207 successful supplies of VA 0x2d6000 did
 *     not progress; the selected transfer had root generation 1 while the
 *     exact stopped home record had generation 3. The host had confused
 *     reservation incarnation with hardware root generation.
 * (c) USDT fires only at physical supply and refusal. Aggregation is bounded
 *     by phase; the first-event cap avoids recursive failure amplification.
 */
dtrace:::BEGIN { supplies = 0; errors = 0; controls = 0; }
carrick*:::hvpatch-el1-owner-bind-result
/(pid == $target || progenyof($target))/ { controls++; }
carrick*:::hvpatch-el1-owner-grant-supply
/(pid == $target || progenyof($target)) && (arg2 == 6 || arg2 == 7)/
{
    @outcome[arg2, arg3] = count();
    if (arg2 == 7) { supplies++; }
    if (supplies <= 16) {
        printf("TCOW|phase=%d|va=0x%x|len=%d|detail=%d\n", arg2, arg0, arg1, arg3);
    }
}
carrick*:::guest-internal-write-fault
/(pid == $target || progenyof($target)) && arg2 == 26/
{ printf("TCOW|refusal=%s\n", copyinstr(arg3)); }
dtrace:::ERROR { errors++; }
proc:::exit /pid == $target/ { exit(controls == 0 || errors != 0 ? 3 : 0); }
tick-1s { seconds++; }
tick-1s /seconds >= 45/ { exit(4); }
END { printf("TCOW|supplies=%d|controls=%d|errors=%d\n", supplies, controls, errors); printa(@outcome); }
