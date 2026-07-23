/*
 * Bounded native FreeBSD/x86 xstate patch-graph census.
 *
 * The runtime fires edge-only records for completed cache-hit/pending patches
 * when CARRICK_NATIVE_X86_TRACE_XSTATE_GRAPH=1. This script retains only edges
 * that the neutral-domain policy classified neutral, then publishes the
 * 4,096 hottest candidates. Gateway-entry events and 16 KiB component hashes
 * remain disabled unless an explicit TRACE_PC also selects the transition.
 *
 * Launch only; never attach this USDT script to a continuing native process:
 *   carrick trace --script scripts/dtrace/native-x86-xstate-graph.d \
 *     --forward-env CARRICK_NATIVE_X86_TRACE_XSTATE_GRAPH=1 -- run ...
 */
#pragma D option quiet
#pragma D option aggsize=32m

dtrace:::BEGIN
{
    printf("native x86 xstate graph started at %Y target=%d\n",
        walltimestamp, $target);
}

carrick*:::native-x86-xstate-edge
/(pid == $target || progenyof($target)) &&
 (arg3 == 2 || arg3 == 4) &&
 (arg4 & 2) == 0 && (arg4 & 0x40) != 0/
{
    @edges[(int)arg0, arg1, arg2, arg3, arg4] = count();
}

proc:::exit
/pid == $target/
{
    exit(0);
}

tick-1s
{
    seconds++;
}

tick-1s
/seconds >= 180/
{
    printf("native x86 xstate graph reached 180-second bound\n");
    exit(0);
}

END
{
    trunc(@edges, 4096);
    printa("XGRAPH hostpid=%d source=%#x target=%#x event=%d flags=%#x count=%@d\n",
        @edges);
}
