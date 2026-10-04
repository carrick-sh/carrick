# Lower copy-up matrix: load-sensitive completion read

The cloudmac `just test` gate reported this before the progress protocol:

```text
two_live_process_lower_copy_up_and_whiteout_matrix ... FAILED
lower n=32 population=128 same_parent=true: WaitTimedOut("read")
test result: FAILED. 2 passed; 1 failed; finished in 14.80s
```

The retained `/home/carrick/dev/ns-evidence/nsev.tgz` archive contains all
32 `dst` and all 32 `alias` names for **each** actor in the upper layer.
Tar represents one name of each hardlink pair as a hardlink entry, so counting
only regular-file entries incorrectly suggests missing names. The archive
proves both actors eventually completed their namespace mutations, but has no
timestamps that place their completion before or after the root read deadline.
The gate host had concurrent builds during this run.

Before changing the script, the exact `n=32, population=128,
same_parent=true` case passed seeds 0 through 1999 under
`ScriptedBackend::with_schedule(Schedule::explore(seed))` on linux-x86_64.
The scheduler controls `Step`, `DispatchUnlocked`, continuation enrollment
and resumption; it does not control elapsed host filesystem work inside a
dispatch or reactor thread scheduling. There is therefore no failing seeded
receipt for this wall-clock verdict. Exploring preemption inside a host call
would require a typed publication point after the backend lock is released;
reproducing elapsed-time starvation would additionally require a virtual-time
model, not merely another runnable-actor choice.

The original script sent one completion byte after all 32 child iterations,
then the parent imposed a single five-second read deadline on the entire
batch. The corrected script sends one byte after each child iteration; the
parent drains them only after its own batch. The actors' namespace operations
remain concurrent, and the existing five-second bound now diagnoses lack of
progress for one iteration rather than cumulative batch time.
