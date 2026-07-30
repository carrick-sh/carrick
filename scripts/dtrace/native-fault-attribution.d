#!/usr/sbin/dtrace -s
/*
 * Workstream C: attribute the address-space fault term.
 *
 * The go-build reference workload takes ~2.2 M address-space faults, of which
 * ~1.79 M are zero-fill (FIRST touch of anonymous memory), and kernel
 * non-syscall time -- overwhelmingly fault handling -- is the single largest
 * CPU bucket at 30.7%. Emitted JIT code was already measured at only 2.08% of
 * the zfod faults, so the mass is guest address-space setup, paid again per
 * forked guest process.
 *
 * This counts faults PER PROCESS so the per-process cost and the process count
 * can be read separately: a high per-process count argues for pre-faulting or
 * arena reuse, a high process count argues for attacking the fork model.
 */
#pragma D option quiet
#pragma D option aggsize=8m

vminfo:::as_fault  /execname == "carrick"/ { @as[pid]  = count(); @tas  = count(); }
vminfo:::zfod      /execname == "carrick"/ { @zf[pid]  = count(); @tzf  = count(); }
vminfo:::cow_fault /execname == "carrick"/ { @cow[pid] = count(); @tcow = count(); }

END {
  printf("TOTAL_AS "); printa("%@u\n", @tas);
  printf("TOTAL_ZFOD "); printa("%@u\n", @tzf);
  printf("TOTAL_COW "); printa("%@u\n", @tcow);
  printf("\n=== per-pid as_fault (top) ===\n");
  trunc(@as, 25); printa("PID %d AS %@u\n", @as);
  printf("\n=== per-pid zfod (top) ===\n");
  trunc(@zf, 25); printa("PID %d ZFOD %@u\n", @zf);
}
