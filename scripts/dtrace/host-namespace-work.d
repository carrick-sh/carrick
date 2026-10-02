/* Bounded namespace host-syscall and owned namei-component census.
 * Use: carrick trace --profile host-namespace-work --trace-out FILE -- run ...
 * ABI: syscall-entry arg1=name, arg2=host address of six u64 syscall args;
 * syscall-return is on the same executor thread. fs-op arg1 is the path-stage
 * tag. Positive directory fds select perf_namespace_scale's measured phase.
 * All populations are DTrace aggregations: concurrent global scalar += loses
 * increments. Rust checks every request and host-call begin/end population,
 * the exact registered scale and every path-stage row; drops fail closed.
 * High perturbation; counts are evidence, wall time is not. Bound: 120 seconds.
 * Visits count executed dentry components and host namei parent/leaf visits,
 * including repeated walks and retries. They do not count lexical string work
 * or components walked internally by cap-std; host syscalls include those calls.
 */
#pragma D option quiet
#pragma D option aggsize=32m
#pragma D option dynvarsize=64m
#pragma D option bufsize=32m
#pragma D option strsize=128
BEGIN
{
    self->active = 0;
    self->host_active = 0;
    seen = 0; errors = 0; code = -1; bounded = 0; seconds = 0;
    printf("NSWORK1|header|program_sha256=/* CARRICK_NSWORK_PROGRAM_SHA256 */\n");
}
carrick*:::syscall-entry
/(pid == $target || progenyof($target)) && self->active/
{ errors = 1; }
carrick*:::syscall-entry
/pid == $target || progenyof($target)/
{
    this->name = copyinstr(arg1);
    this->args = (uint64_t *)copyin(arg2, 48);
    self->active = (int32_t)this->args[0] >= 0 &&
        (this->name == "renameat" || this->name == "renameat2" ||
         this->name == "unlinkat" || this->name == "linkat" || this->name == "openat");
    self->anchor = (uint32_t)this->args[0];
    self->op = this->name == "renameat2" ? "renameat" : this->name;
}
carrick*:::syscall-entry
/(pid == $target || progenyof($target)) && self->active/
{
    seen = 1;
    @begin[self->anchor, self->op] = count();
    @visits[self->anchor, self->op, "dentry"] = sum(0);
    @visits[self->anchor, self->op, "host-parent"] = sum(0);
    @visits[self->anchor, self->op, "host-leaf"] = sum(0);
}
carrick*:::syscall-return
/(pid == $target || progenyof($target)) && self->active/
{
    @end[self->anchor, self->op] = count();
    self->active = 0;
}
syscall:::entry
/(pid == $target || progenyof($target)) && self->active && self->host_active/
{ errors = 1; }
syscall:::entry
/(pid == $target || progenyof($target)) && self->active/
{
    self->host_active = 1;
    self->host_name = probefunc;
    @host_begin[self->anchor, self->op, probefunc] = count();
}
syscall:::return
/(pid == $target || progenyof($target)) && self->active && self->host_active/
{
    @host_end[self->anchor, self->op, self->host_name] = count();
    self->host_active = 0;
}
carrick*:::fs-op
/(pid == $target || progenyof($target)) && self->active && copyinstr(arg1) == "path-census:armed"/
{ @armed[self->anchor, self->op] = count(); }
carrick*:::fs-op
/(pid == $target || progenyof($target)) && self->active && copyinstr(arg1) == "path-visit:dentry"/
{ @visits[self->anchor, self->op, "dentry"] = sum(1); }
carrick*:::fs-op
/(pid == $target || progenyof($target)) && self->active && copyinstr(arg1) == "path-visit:host-parent"/
{ @visits[self->anchor, self->op, "host-parent"] = sum(1); }
carrick*:::fs-op
/(pid == $target || progenyof($target)) && self->active && copyinstr(arg1) == "path-visit:host-leaf"/
{ @visits[self->anchor, self->op, "host-leaf"] = sum(1); }
syscall::exit:entry /pid == $target/ { code = (int)arg0; }
proc:::exit /pid == $target/ { exit(seen && !errors && code == 0 ? 0 : 2); }
dtrace:::ERROR { errors = 1; exit(3); }
tick-1s { seconds++; }
tick-1s /seconds >= 120/ { bounded = 1; exit(2); }
END
{
    printf("NSWORK1|summary|seen=%d|errors=%d|code=%d|bounded=%d\n", seen, errors, code, bounded);
    printa("NSWORK1|begin|actor=%u|op=%s|count=%@d\n", @begin);
    printa("NSWORK1|end|actor=%u|op=%s|count=%@d\n", @end);
    printa("NSWORK1|armed|actor=%u|op=%s|count=%@d\n", @armed);
    printa("NSWORK1|host-begin|actor=%u|op=%s|name=%s|count=%@d\n", @host_begin);
    printa("NSWORK1|host-end|actor=%u|op=%s|name=%s|count=%@d\n", @host_end);
    printa("NSWORK1|visit|actor=%u|op=%s|stage=%s|count=%@d\n", @visits);
}
