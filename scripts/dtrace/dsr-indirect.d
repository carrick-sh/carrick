#pragma D option quiet

BEGIN
{
    tracked[$target] = 1;
    active = 1;
    @direct_total[$target] = sum(0);
    @indirect_total[$target] = sum(0);
    @gateway_total[$target] = sum(0);
    @gateway_kind[$target, 1] = sum(0);
    @gateway_kind[$target, 2] = sum(0);
    @gateway_kind[$target, 3] = sum(0);
    @gateway_kind[$target, 4] = sum(0);
    @gateway_kind[$target, 5] = sum(0);
    @gateway_kind[$target, 6] = sum(0);
    @gateway_kind[$target, 7] = sum(0);
    @translation_attempts[$target] = sum(0);
    @binding_event[$target, 7] = sum(0);
    @binding_event[$target, 8] = sum(0);
    @binding_event[$target, 9] = sum(0);
    @binding_event[$target, 10] = sum(0);
    @binding_event[$target, 11] = sum(0);
    @binding_event[$target, 12] = sum(0);
}

proc:::exit
/pid == $target/
{
    target_exit_reason = arg0;
}

proc:::create
/(pid == $target || progenyof($target))/
{
    tracked[args[0]->pr_pid] = 1;
    active++;
}

proc:::exit
/(pid == $target || progenyof($target)) && tracked[pid] && active == 1/
{
    tracked[pid] = 0;
    active = 0;
    exit(0);
}

proc:::exit
/(pid == $target || progenyof($target)) && tracked[pid] && active > 1/
{
    tracked[pid] = 0;
    active--;
}

carrick*:::dsr-resolve-begin
/(pid == $target || progenyof($target)) && arg1 == 2/
{
    this->word = *(uint32_t *)copyin(arg2, 4);
    this->kind = (this->word & 0xfffffc1f) == 0xd65f0000 ? 3 :
        (this->word & 0xfffffc1f) == 0xd63f0000 ? 2 :
        (this->word & 0xfffffc1f) == 0xd61f0000 ? 1 : 0;
    @source[pid, arg2] = count();
    @pair[pid, arg2, arg3] = count();
    @indirect_kind[pid, this->kind] = count();
    @indirect_total[pid] = sum(1);
}

carrick*:::dsr-resolve-begin
/(pid == $target || progenyof($target)) && arg1 == 1/
{
    @direct_source[pid, arg2] = count();
    @direct_pair[pid, arg2, arg3] = count();
    @direct_total[pid] = sum(1);
}

carrick*:::dsr-run-end
/(pid == $target || progenyof($target))/
{
    @gateway_kind[pid, arg1] = sum(1);
    @gateway_total[pid] = sum(1);
}

carrick*:::dsr-translate-begin
/(pid == $target || progenyof($target))/
{
    @translation_attempts[pid] = sum(1);
}

carrick*:::dsr-cache-event
/(pid == $target || progenyof($target)) && arg1 >= 7/
{
    @binding_event[pid, arg1] = sum(1);
}

carrick*:::dsr-cache-event
/(pid == $target || progenyof($target)) && arg1 == 7 && arg4 != 0/
{
    @binding_cell[pid, arg4] = sum(1);
}

carrick*:::dsr-cache-event
/(pid == $target || progenyof($target)) && arg1 == 8/
{
    @binding_publish_cell[pid, arg4] = sum(1);
}

carrick*:::dsr-cache-event
/(pid == $target || progenyof($target)) && arg1 == 10/
{
    @binding_clear_cell[pid, arg2, arg3] = sum(1);
}

carrick*:::dsr-cache-event
/(pid == $target || progenyof($target)) && arg1 == 11/
{
    @binding_validation[pid, arg2, arg3, arg4] = sum(1);
}

carrick*:::dsr-cache-event
/(pid == $target || progenyof($target)) && arg1 == 12/
{
    @binding_unit[pid, arg2, arg3, arg4] = sum(1);
}

carrick*:::dsr-resolve-end
/(pid == $target || progenyof($target)) && arg1 == 1/
{
    @direct_outcome[pid, arg4] = count();
}

carrick*:::dsr-resolve-end
/(pid == $target || progenyof($target)) && arg1 == 2/
{
    @outcome[pid, arg4] = count();
}

END
{
    printa("DSRPROF1|count|phase=direct-source|pid=%d|source_pc=%#x|value=%@d\n", @direct_source);
    printa("DSRPROF1|count|phase=direct-pair|pid=%d|source_pc=%#x|target_pc=%#x|value=%@d\n", @direct_pair);
    printa("DSRPROF1|count|phase=direct-total|pid=%d|kind=1|value=%@d\n", @direct_total);
    printa("DSRPROF1|count|phase=gateway-kind|pid=%d|kind=%d|value=%@d\n", @gateway_kind);
    printa("DSRPROF1|count|phase=gateway-total|pid=%d|value=%@d\n", @gateway_total);
    printa("DSRPROF1|count|phase=translation-attempts|pid=%d|value=%@d\n", @translation_attempts);
    printa("DSRPROF1|count|phase=direct-outcome|pid=%d|kind=%d|value=%@d\n", @direct_outcome);
    printa("DSRPROF1|count|phase=indirect-source|pid=%d|source_pc=%#x|value=%@d\n", @source);
    printa("DSRPROF1|count|phase=indirect-pair|pid=%d|source_pc=%#x|target_pc=%#x|value=%@d\n", @pair);
    printa("DSRPROF1|count|phase=indirect-kind|pid=%d|kind=%d|value=%@d\n", @indirect_kind);
    printa("DSRPROF1|count|phase=indirect-total|pid=%d|kind=2|value=%@d\n", @indirect_total);
    printa("DSRPROF1|count|phase=indirect-outcome|pid=%d|kind=%d|value=%@d\n", @outcome);
    printa("DSRPROF1|count|phase=binding-event|pid=%d|kind=%d|value=%@d\n", @binding_event);
    printa("DSRPROF1|count|phase=binding-cell|pid=%d|cell_va=%#x|value=%@d\n", @binding_cell);
    printa("DSRPROF1|count|phase=binding-publish-cell|pid=%d|cell_va=%#x|value=%@d\n", @binding_publish_cell);
    printa("DSRPROF1|count|phase=binding-clear-cell|pid=%d|cell_va=%#x|kind=%d|value=%@d\n", @binding_clear_cell);
    printa("DSRPROF1|count|phase=binding-validation|pid=%d|source_pc=%#x|kind=%d|cell_va=%#x|value=%@d\n", @binding_validation);
    printa("DSRPROF1|count|phase=binding-unit|pid=%d|unit_id=%#x|record_count=%d|binding_data_bytes=%d|value=%@d\n", @binding_unit);
    printf("DSRPROF1|complete|profile=dsr-indirect|bounded=%d|target_exit_reason=%d\n",
        bounded, target_exit_reason);
}
