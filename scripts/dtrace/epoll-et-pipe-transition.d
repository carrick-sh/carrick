/*
 * EPOLLET pipe transition discriminator for LTP epoll_wait06.
 *
 * Question: after a full nonblocking pipe is read halfway, does Carrick
 * incorrectly expose the writer as EPOLLOUT, or does it incorrectly re-deliver
 * the reader's still-level EPOLLIN? The former predicts that the premature
 * writer edge is latched and masks the real writer edge after the final drain.
 *
 * Provider ABI qualified on the macOS/HVF arm64 host against the signed
 * binary's __dof_carrick section and
 * crates/carrick-observability/src/probes.rs on 2026-08-26:
 *   epoll-interest:
 *     arg0=epfd (i32), arg1=watched fd (i32), arg2=requested bits (u32),
 *     arg3=raw-ready bits (u32), arg4=last-ready bits (u32),
 *     arg5=delivered-ready bits (u32).
 *   epoll-result:
 *     arg0=epfd (i32), arg1=ready count (i32), arg2=wait-fd count (i32),
 *     arg3=timeout milliseconds (i32), arg4=result kind (i32).
 *
 * This is a correctness-only, per-decision print trace. It perturbs the tiny
 * reproducer and must never be used for performance measurement. Run through
 * `carrick trace --script ... --require-script-exit -- ...`; the terminal ETP1
 * receipt fails closed if either provider does not fire.
 */

#pragma D option quiet
#pragma D option strsize=256
#pragma D option bufsize=4m
#pragma D option destructive

dtrace:::BEGIN
{
    interests = 0;
    results = 0;
    writer_new_out = 0;
    writer_masked_out = 0;
    reader_new_in = 0;
    printf("ETP1|begin|wall=%Y\n", walltimestamp);
}

carrick*:::epoll-interest
/(pid == $target || progenyof($target))/
{
    interests++;
    printf("ETP1|interest|hostpid=%d|hosttid=%d|wait-index=%d|epfd=%d|fd=%d|requested=%#x|raw=%#x|last=%#x|ready=%#x\n",
        pid, tid, results, (int)arg0, (int)arg1, (uint32_t)arg2,
        (uint32_t)arg3, (uint32_t)arg4, (uint32_t)arg5);

    if (arg1 == 4 && (arg3 & 4) != 0 && (arg4 & 4) == 0) {
        writer_new_out++;
    }
    if (arg1 == 3 && (arg3 & 1) != 0 && (arg4 & 1) == 0) {
        reader_new_in++;
    }
    if (arg1 == 4 && (arg3 & 4) != 0 && (arg4 & 4) != 0) {
        writer_masked_out++;
    }
}

carrick*:::epoll-result
/(pid == $target || progenyof($target))/
{
    printf("ETP1|result|hostpid=%d|hosttid=%d|index=%d|epfd=%d|ready=%d|wait-fds=%d|timeout=%d|kind=%d\n",
        pid, tid, results, (int)arg0, (int)arg1, (int)arg2, (int)arg3,
        (int)arg4);
    results++;
}

tick-5s
{
    if (interests == 0 || results == 0 ||
        !((writer_new_out > 0 && writer_masked_out > 0) || reader_new_in > 1)) {
        printf("ETP1|fail|interests=%d|results=%d|writer-new-out=%d|writer-masked-out=%d|reader-new-in=%d\n",
            interests, results, writer_new_out, writer_masked_out,
            reader_new_in);
        exit(1);
    }
    printf("ETP1|pass|interests=%d|results=%d|writer-new-out=%d|writer-masked-out=%d|reader-new-in=%d\n",
        interests, results, writer_new_out, writer_masked_out,
        reader_new_in);
    exit(0);
}
