/* Trace the fork-quiesce dynamics to corner the multithreaded-fork wedge.
 * fork-quiesce phase 0: a=others, b=kicker.count, tid. phase 1 (wait loop):
 * a=others, b=paused_count, tid. fork-post: child pid. Bounded. */
#pragma D option quiet

carrick*:::fork-quiesce
/pid == $target || progenyof($target)/
{
    printf("[%d] quiesce phase=%d others=%d paused/kick=%d tid=%d\n",
           pid, (int)arg0, (int)arg1, (int)arg2, (int)arg3);
}

carrick*:::fork-post
/pid == $target || progenyof($target)/
{
    printf("[%d] fork-post child=%d\n", pid, (int)arg0);
}

tick-1s { secs++; }
tick-1s /secs >= 25/ { exit(0); }
