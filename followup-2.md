# epoll_pwait copy-out: the owner-less lane still forwards (IpcLeave::EpollCopyOut)

PR #2178 resolves a refused events copy-out in ring whenever a native owner
retains the caller's memory (`UserCopy::take_copyout_refusal` is `Some`). With
no owner (`dispatch.rs` `fallback_or_refuse_arm_process_call`, `process: None`),
the arm still forwards. That is correct only if the host can serve a zone epoll
for that task (HostIpc harvest of the shared table). Confirm with a census on a
run where that leave fires; if the host answers EBADF there too, the lane needs
an owner or an exact refusal.
