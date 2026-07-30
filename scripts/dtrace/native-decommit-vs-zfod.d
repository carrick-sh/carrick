#!/usr/sbin/dtrace -s
/*
 * Workstream C: is the zero-fill fault term real guest memory use, or do we
 * decommit and re-fault the same pages?
 *
 * The reference workload takes ~1.72 M zfod faults over 50 processes -- 34,000
 * each, which at a 16 KB host page implies 564 MB of distinct anonymous memory
 * first-touched PER PROCESS. A `go` compile of one small package does not do
 * that, so the same addresses are being faulted repeatedly.
 *
 * Counts the host calls that can decommit a page, against zfod. If decommits
 * are the same order as zfod faults, the fault term is an artifact of how a
 * guest `madvise` is lowered, not of guest address-space size.
 */
#pragma D option quiet
#pragma D option aggsize=8m

tick-90s { exit(0); }

syscall::madvise:entry /execname == "carrick"/ { @adv[arg2] = count(); @dec = count(); }
syscall::munmap:entry  /execname == "carrick"/ { @munmap = count(); }
syscall::mmap:entry    /execname == "carrick"/ { @mmap = count(); }
vminfo:::zfod          /execname == "carrick"/ { @zfod = count(); }
vminfo:::as_fault      /execname == "carrick"/ { @as = count(); }

END {
  printf("ZFOD ");   printa("%@u\n", @zfod);
  printf("ASFLT ");  printa("%@u\n", @as);
  printf("MADVISE "); printa("%@u\n", @dec);
  printf("MUNMAP ");  printa("%@u\n", @munmap);
  printf("MMAP ");    printa("%@u\n", @mmap);
  printf("\n=== madvise by advice value ===\n");
  printa("ADVICE %d COUNT %@u\n", @adv);
}
