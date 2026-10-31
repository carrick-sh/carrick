# ABI-born member retirement during executor load

`kernel.el1.guest-scheduler` and `kernel.el1.thread-lifecycle` require a
terminal sibling's queued or in-flight load to settle through the neutral
terminal owner. An EL1-born sibling retains its original control after host
adoption; its host-only birth fields are empty. The control lease retains the
exact process and thread identity independently of those fields and of pool
entry reuse. A declined load supplies that retained identity to
`missing_zone_continuation`; record absence alone never authorizes retirement.

The runtime bindings
`serial_host_process_exit_retires_abi_born_sibling_before_direct_load` and
`serial_host_group_close_retires_abi_born_sibling_during_direct_load` publish
real ABI births and retain two live Kernel threads. The first exercises
process graph cancellation of a kernel-owned ZoneWait before a queued claim
loads it. The second holds a load while the native `TerminalCustody` releases
its record, before any host retirement receipt. They require zero guest
entries for the retired member, one terminal settlement and every executor
joined and destroyed. The sibling's leader remains live in the second case;
MM retirement cannot supply its verdict. The no-terminal-intent control must
still fail closed. Channels bound the fixture's coordination, without adding
production waits, polling or retries. Hardware execution remains scripted;
`el1_sched_exit_group_with_parked_threads` supplies the director-owned signed
binding and its 20/20 single-artifact acceptance.
