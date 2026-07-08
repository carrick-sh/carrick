#pragma D option quiet
#pragma D option strsize=256

/*
 * Time Carrick's host-side fork phases.
 *
 * This is intentionally phase-level rather than per-syscall: a Linux guest fork
 * on HVF tears down the VM, calls host fork(2), then rebuilds a fresh VM/vCPU in
 * both parent and child. The fork-pre/fork-post USDT probes bracket that whole
 * sequence for serial fork loops such as LTP getpid01.
 */

dtrace:::BEGIN
{
    printf("fork phase trace start\n");
}

carrick*:::fork-pre
/(pid == $target || progenyof($target))/
{
    fork_start[pid] = timestamp;
    last_fork_start = timestamp;
    printf("[%d] fork-pre\n", pid);
}

carrick*:::fork-quiesce
/(pid == $target || progenyof($target))/
{
    printf("[%d] fork-quiesce phase=%d a=%d b=%d tid=%d\n",
        pid, (int)arg0, (int)arg1, (int)arg2, (int)arg3);
}

carrick*:::fork-rebuild
/(pid == $target || progenyof($target))/
{
    printf("[%d] fork-rebuild role=%d phase=%d desc=%d maps=%d elapsed_us=%d\n",
        pid, (int)arg0, (int)arg1, (uint64_t)arg2, (uint64_t)arg3,
        (uint64_t)arg4);
    @rebuild_us[(int)arg0, (int)arg1] = avg((uint64_t)arg4);
    @rebuild_maps[(int)arg0, (int)arg1] = avg((uint64_t)arg3);
    @rebuild_descs[(int)arg0, (int)arg1] = avg((uint64_t)arg2);
}

carrick*:::fork-lifecycle
/(pid == $target || progenyof($target))/
{
    printf("[%d] fork-lifecycle role=%d phase=%d elapsed_us=%d a=%d b=%d\n",
        pid, (int)arg0, (int)arg1, (uint64_t)arg2, (int64_t)arg3,
        (int64_t)arg4);
    @lifecycle_us[(int)arg0, (int)arg1] = avg((uint64_t)arg2);
    @lifecycle_count[(int)arg0, (int)arg1] = count();
}

carrick*:::fork-footprint
/(pid == $target || progenyof($target))/
{
    printf("[%d] fork-footprint phase=%d regions=%d arena_high_water=%d resident_bytes=%d virtual_bytes=%d\n",
        pid, (int)arg0, (uint64_t)arg1, (uint64_t)arg2, (uint64_t)arg3,
        (uint64_t)arg4);
    @footprint_regions[(int)arg0] = avg((uint64_t)arg1);
    @footprint_arena_high_water[(int)arg0] = avg((uint64_t)arg2);
    @footprint_resident_bytes[(int)arg0] = avg((uint64_t)arg3);
    @footprint_virtual_bytes[(int)arg0] = avg((uint64_t)arg4);
    @footprint_count[(int)arg0] = count();
}

carrick*:::fork-post
/(pid == $target || progenyof($target)) && fork_start[pid]/
{
    this->elapsed_us = (timestamp - fork_start[pid]) / 1000;
    @parent_rebuild_us = quantize(this->elapsed_us);
    @parent_rebuild_avg_us = avg(this->elapsed_us);
    printf("[%d] fork-post role=parent child=%d elapsed_us=%d\n",
        pid, (int)arg0, this->elapsed_us);
    parent_post_start[pid] = timestamp;
    fork_start[pid] = 0;
}

carrick*:::fork-post
/(pid == $target || progenyof($target)) && arg0 == 0 && last_fork_start/
{
    this->elapsed_us = (timestamp - last_fork_start) / 1000;
    @child_rebuild_us = quantize(this->elapsed_us);
    @child_rebuild_avg_us = avg(this->elapsed_us);
    printf("[%d] fork-post role=child elapsed_since_pre_us=%d\n",
        pid, this->elapsed_us);
    child_post_start[pid] = timestamp;
}

carrick*:::guest-exit
/(pid == $target || progenyof($target))/
{
    printf("[%d] guest-exit code=%d signal=%d\n", pid, (int)arg0, (int)arg1);
}

carrick*:::guest-exit
/(pid == $target || progenyof($target)) && child_post_start[pid]/
{
    this->elapsed_us = (timestamp - child_post_start[pid]) / 1000;
    @child_post_to_exit_us = avg(this->elapsed_us);
    printf("[%d] child-post-to-exit elapsed_us=%d\n", pid, this->elapsed_us);
    child_post_start[pid] = 0;
}

carrick*:::guest-exit
/(pid == $target || progenyof($target)) && parent_post_start[pid]/
{
    this->elapsed_us = (timestamp - parent_post_start[pid]) / 1000;
    @parent_post_to_exit_us = avg(this->elapsed_us);
    printf("[%d] parent-post-to-exit elapsed_us=%d\n", pid, this->elapsed_us);
    parent_post_start[pid] = 0;
}

tick-1s
{
    secs++;
}

tick-1s
/secs >= 20/
{
    exit(0);
}

dtrace:::END
{
    printa("parent rebuild avg us %@d\n", @parent_rebuild_avg_us);
    printa("child rebuild avg us %@d\n", @child_rebuild_avg_us);
    printa("parent rebuild us %@d\n", @parent_rebuild_us);
    printa("child rebuild us %@d\n", @child_rebuild_us);
    printa("rebuild us role=%d phase=%d %@d\n", @rebuild_us);
    printa("rebuild maps role=%d phase=%d %@d\n", @rebuild_maps);
    printa("rebuild descs role=%d phase=%d %@d\n", @rebuild_descs);
    printa("lifecycle us role=%d phase=%d %@d\n", @lifecycle_us);
    printa("lifecycle count role=%d phase=%d %@d\n", @lifecycle_count);
    printa("footprint regions phase=%d %@d\n", @footprint_regions);
    printa("footprint arena_high_water phase=%d %@d\n", @footprint_arena_high_water);
    printa("footprint resident_bytes phase=%d %@d\n", @footprint_resident_bytes);
    printa("footprint virtual_bytes phase=%d %@d\n", @footprint_virtual_bytes);
    printa("footprint count phase=%d %@d\n", @footprint_count);
    printa("child post-to-exit avg us %@d\n", @child_post_to_exit_us);
    printa("parent post-to-exit avg us %@d\n", @parent_post_to_exit_us);
}
