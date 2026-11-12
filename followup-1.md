# epoll_pwait: a fresh call's sigmask is not re-armed when its copy-out preparation suspends

Found while fixing #1671 (PR #2178). When a fresh `epoll_pwait` with a non-NULL
sigmask harvests reports, its copy-out is refused, and the owner's preparation
yields (`Busy` -> `OwnedOperationYield::Suspended`) or suspends (`Suspended`,
fault service), the call resumes through `epoll::resume`, which never re-reads
the mask (`wait.is_some()`). If the re-harvest is then empty, the call parks
without the temporary mask. Ready/Wait reruns stay in the same frame and keep it.

Acceptance: a witness (fresh pwait with mask, copy-out refused then Busy-yield,
then nothing ready) shows the park under the temporary mask; fix by arming the
mask before the yield or carrying it in the operation.
