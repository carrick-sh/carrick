title: prove successful x86 exec closes the CLOEXEC status-pipe writer
parent: #2271

The KVM failure-path witness creates pipe2(O_CLOEXEC), forks, attempts exec,
reports failure from the child and verifies the parent's read and final EOF.
It does not prove successful-exec closure. Production x86 exec currently
refuses before replacement (the existing CLI witness
mounted_static_x86_exec_refuses_before_replacement_identity records #1093's
boundary). Replacing that owner belongs to the exec lane, not fd/IPC routing.

After #1093 provides native successful exec, extend the same fixture to exec a
known mounted successor, keep both processes alive, and assert parent read
returns EOF without a child error report and without a host read/IPC forward.
