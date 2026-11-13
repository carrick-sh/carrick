# #2226's thread-start carrier death now reports "kernel fault policy refused: reason 9"

On current main `ace2260524` and on #2250's head, #2226's repro
(`python3 -P -c 'import _thread; _thread.start_new_thread(print,("x",)); ...'`)
exits 125 with
`kernel fault policy refused: reason 9, FaultDoorbellRecord { vector: 14,
error_code: 20, ... }` and `SnapshotRestoreFailed`, not with #2226's original
`idle CPL0 peer needs a host task handback`. Reason 9 is
`UserFaultSupply::Unresolved(9)` in `carrick-x86-cpl0/src/linux_personality.rs`
(`OwnerFaultSupplyOutcome::Wait` or `Unavailable`: "this lane has no
native-service birth handle, so it cannot mint an owner wait"). `py-thread`
on #2250's head stops here (error_code 4, a user read). Suggest updating
#2226 with the new message; the fault-path owner wait is the likely next
fix.
