# Follow-up 6: the other #2206 cases with distinct causes, not triaged by PR #2214

From run 43246641703 (`71985c0`, cloudmac-gate), `probe-cases.log`:
- `case_elf_exec_errno`: every variant, including a valid exec, returns errno 38 (line 179). The fixture execs from a fork child. Check the native exec service and #1093 / PR #2190.
- `case_private_file_*` and `case_immutable_private_file_*` (lines 120-346): Python EBADF / discard-visibility assertions. These belong to the private-file COW lanes.
- `case_m5_el0_nested_altstack_and_fault_frame_bindings`: `bus_setup_errno=38` (line 452). Its SIGBUS setup (probably `ftruncate` plus `mmap` of a file) is ENOSYS.
- `case_native_prefix_write_child_inherited_file`: the 180 s container deadline (line 388). That is a hang.
- `case_inotify_watch_churn`: image resolution against `localhost:5050` failed (line 789). Harness or registry, not the kernel.
- `case_sched_affinity_threads_mask_reflection`: `clock_gettime` EINVAL, #2109.

**Gate note:** #2206 exists because the merge-group gate reads all of these as "pre-existing" (the base fails the same set). #1933 tracks moving to plain pass/fail.
