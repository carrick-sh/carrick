# Relative futex deadline port audit (#1745)

The admitted base is `71c57e106688ba954a5a9947c9868f8a92160660`.
The rebase was a no-op: the branch already descends from that exact base.
No earlier worker commits were removed. The four commits identified in the
lost-work check are present as ports, rather than identical commit objects.

This inventory covers every commit in PR #1749, from its recorded base
`0d5dfaa508e5b92edbe2b18404cd2c7d4230f719` through its published head
`089c454c1bb756e2592d2e000b0f69f8247a23cc`. “Kept” means the work is
already in admitted main through #1779; “ported” identifies this branch's
replacement. Superseded timeout experiments and their reversions are dropped
as a unit; none is an implementation dependency of the final fix.

| Original commit and subject | Disposition and reason |
|---|---|
| `69466c185b` docs(conformance): identify atomic futex copy prerequisite | Kept — already in admitted main as `9e55e0c05` through the atomic futex prerequisite; no duplicate replay. |
| `60c349737c` docs(conformance): record the futex atomic interface decision | Kept — already in admitted main as `5ce8ec452` through the atomic futex prerequisite; no duplicate replay. |
| `bc3725422f` test(el1): expose owner-refused futex word forwarding | Kept — already in admitted main as `80c910393` through the atomic futex prerequisite; no duplicate replay. |
| `f5aaf003bc` fix(el1): retain private futex word copies on owner waits | Kept — already in admitted main as `b988c7278` through the atomic futex prerequisite; no duplicate replay. |
| `81e3191adc` fix(arm): declare pan for guarded futex atomics | Kept — already in admitted main as `5474f3504` through the atomic futex prerequisite; no duplicate replay. |
| `6c5485c201` test(conformance): expose host futex owner refusal collapse | Kept — already in admitted main as `546327a46` through the atomic futex prerequisite; no duplicate replay. |
| `b8243acacb` fix(ipc): preserve host futex word owner refusals | Kept — already in admitted main as `adf46afd5` through the atomic futex prerequisite; no duplicate replay. |
| `80edde38af` docs(conformance): describe host futex atomic admission | Kept — already in admitted main as `953b04151` through the atomic futex prerequisite; no duplicate replay. |
| `f62435c1b4` test(el1): port futex owner wait checkpoint | Kept — already in admitted main as `b7462125d` through the atomic futex prerequisite; no duplicate replay. |
| `40c3cc6c0b` fix(core): retain futex atomic copy admission | Kept — already in admitted main as `0bd879cd7` through the atomic futex prerequisite; no duplicate replay. |
| `7a13edac7f` fix(runtime): forward futex atomic copies | Kept — already in admitted main as `c0213d1b7` through the atomic futex prerequisite; no duplicate replay. |
| `702944e468` fix(arm): select futex backing before atomics | Kept — already in admitted main as `64748b0be` through the atomic futex prerequisite; no duplicate replay. |
| `66727c7d29` fix(hvf): load selected futex words atomically | Kept — already in admitted main as `4f9b29d62` through the atomic futex prerequisite; no duplicate replay. |
| `e01e241979` fix(core): preserve futex timeout copy waits | Kept — already in admitted main as `e573345be` through the atomic futex prerequisite; no duplicate replay. |
| `399ead0e0d` fix(core): read futex deadlines once | Kept — already in admitted main as `e93bda674` through the atomic futex prerequisite; no duplicate replay. |
| `fb9184e561` fix(core): keep futex copy adapter input-only | Kept — already in admitted main as `cfb3eda78` through the atomic futex prerequisite; no duplicate replay. |
| `d3ecad5cd9` test(core): model atomic futex copies | Kept — already in admitted main as `a32bc3d81` through the atomic futex prerequisite; no duplicate replay. |
| `753d3aac0e` fix(core): satisfy futex atomic gates | Kept — already in admitted main as `5fc0a75bf` through the atomic futex prerequisite; no duplicate replay. |
| `94fc1bd35d` fix(core): keep futex refusals allocation-free | Kept — already in admitted main as `d8ed9699f` through the atomic futex prerequisite; no duplicate replay. |
| `a49601d450` test(arm): expose missing owner-authorized futex cas | Kept — already in admitted main as `ea8846236` through the atomic futex prerequisite; no duplicate replay. |
| `4f8b612aa5` fix(arm): retain owner selection through futex cas | Kept — already in admitted main as `b694678dc` through the atomic futex prerequisite; no duplicate replay. |
| `cc3899e95d` test(runtime): expose byte-loaded zone futex recheck | Kept — already in admitted main as `870ef7b8c` through the atomic futex prerequisite; no duplicate replay. |
| `30a636661f` fix(runtime): recheck zone futex words atomically | Kept — already in admitted main as `fc1403316` through the atomic futex prerequisite; no duplicate replay. |
| `05eceb815d` test(core): expose restarted futex owner timeout | Dropped — superseded deadline experiment or its paired reversion; the operation-owned implementation replaces the reverted scratch/context approach. Historical counterparts remain in main, with the experiment reverted. |
| `5668fd1482` test(el1): expose restarted futex owner timeout | Dropped — superseded deadline experiment or its paired reversion; the operation-owned implementation replaces the reverted scratch/context approach. Historical counterparts remain in main, with the experiment reverted. |
| `7c706d45bb` fix(core): retain futex deadlines across owner waits | Dropped — superseded deadline experiment or its paired reversion; the operation-owned implementation replaces the reverted scratch/context approach. Historical counterparts remain in main, with the experiment reverted. |
| `fff3c4803d` fix(el1): keep retry deadlines out of user registers | Dropped — superseded deadline experiment or its paired reversion; the operation-owned implementation replaces the reverted scratch/context approach. Historical counterparts remain in main, with the experiment reverted. |
| `85969f2592` fix(arm): keep atomic settlement in known authority owners | Kept — already in admitted main as `1b8e369af` through the atomic futex prerequisite; no duplicate replay. |
| `5cc8374971` Revert "fix(el1): keep retry deadlines out of user registers" | Dropped — superseded deadline experiment or its paired reversion; the operation-owned implementation replaces the reverted scratch/context approach. Historical counterparts remain in main, with the experiment reverted. |
| `dfd8a918c7` Revert "fix(core): retain futex deadlines across owner waits" | Dropped — superseded deadline experiment or its paired reversion; the operation-owned implementation replaces the reverted scratch/context approach. Historical counterparts remain in main, with the experiment reverted. |
| `807c760058` Revert "test(el1): expose restarted futex owner timeout" | Dropped — superseded deadline experiment or its paired reversion; the operation-owned implementation replaces the reverted scratch/context approach. Historical counterparts remain in main, with the experiment reverted. |
| `3cfa88691c` Revert "test(core): expose restarted futex owner timeout" | Dropped — superseded deadline experiment or its paired reversion; the operation-owned implementation replaces the reverted scratch/context approach. Historical counterparts remain in main, with the experiment reverted. |
| `e711e5fc07` test(ipc): expose relative futex deadline restart after owner wait | Ported — 9cffa61a1 and cc00bae47: separate timeout and mismatch episodes; production host and two-thread native red witnesses. |
| `6f8f490189` fix(ipc): own relative futex deadlines across memory service | Ported — f1d09a378, 7905b20d1, 605b0802b and 7e81939c3: owned host completion token and native member continuation; synchronous retry, final word recheck, signal and terminal cleanup. |
| `ce4e7fae11` fix(ipc): complete retry admission and cancellation witnesses | Ported — 7e81939c3 and 81c68a9a6: admission presence hint, sibling signal during owner service, fatal cancellation through the production host job, and contract mappings. |
| `089c454c1b` refactor(ipc): name the authenticated process entry snapshot | Ported — 7e81939c3: named AuthenticatedProcessEntry snapshot with both presence hints; stale FAR grouping retained. |

The out-of-fence runtime boundary fixture correction in `c8ab44468` is retained
from the earlier worker. It changes only test synchronization: the successor
stays at the observed boundary until the progress assertion runs. It makes no
guest ABI or production scheduling change.

The behavioral and evidence limits are described in
[futex-contention.md](futex-contention.md). This audit does not claim signed
wall-clock acceptance from VM-free deadline arithmetic.
