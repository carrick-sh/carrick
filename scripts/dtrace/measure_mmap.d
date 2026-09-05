#pragma D option quiet
carrick*:::syscall-entry
/arg0 == 222/
{
    self->t = timestamp;
}
carrick*:::syscall-return
/arg0 == 222 && self->t != 0/
{
    @mmap_ns = quantize((timestamp - self->t));
    @avg_us = avg((timestamp - self->t) / 1000);
    self->t = 0;
}
tick-5s { exit(0); }
END {
    printa(@mmap_ns);
    printa("avg_us = %@d\n", @avg_us);
}
