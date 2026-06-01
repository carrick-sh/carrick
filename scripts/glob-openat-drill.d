/* Attribute host open() amplification to the in-flight GUEST syscall, and grab
 * the symbolicated host call path (ustack) at every host open. Pinpoints what
 * carrick code drives the ~300x open amplification on --fs host. Bounded. */
#pragma D option quiet
#pragma D option ustackframes=20

carrick*:::syscall-entry
/pid == $target || progenyof($target)/
{ self->gnr = arg0 + 1; }   /* +1 so an in-flight nr is always truthy */

carrick*:::syscall-return
/pid == $target || progenyof($target)/
{ self->gnr = 0; }

syscall::open*:entry
/pid == $target || progenyof($target)/
{
    @byguest[self->gnr ? self->gnr - 1 : -1] = count();
    @stacks[ustack(16)] = count();
    @hostopen = count();
}

tick-1s { secs++; }
tick-1s /secs >= 80/ { exit(0); }

END {
    printf("=== total host opens ===\n");
    printa("%@d\n", @hostopen);
    printf("=== host opens by in-flight guest syscall nr (-1 = none) ===\n");
    printa("guest_nr=%-6d host_opens=%@d\n", @byguest);
    printf("=== TOP host-open ustacks ===\n");
    trunc(@stacks, 5);
    printa(@stacks);
}
