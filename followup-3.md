# epoll_pwait copy-out: witness the owner Wait arm and op-arena exhaustion

PR #2178's `prepare_output` handles `CopyoutPreparation::Wait` (park on the
owner, rerun on Retry) without a dedicated witness; add one through the
production native entry (raise the MM gate like the rt_sigprocmask OwnerWait
fixture in host_test_support). Also, `begin_operation` failing (operation arena
exhausted) still leaves as `NoOperationRecord` + Forward, matching the existing
park path; per AGENTS.md contention should be "not now" (enrol on the
operation-slot release and rerun), never a forward for a ring-owned epoll.
