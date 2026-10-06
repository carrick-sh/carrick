# x86 order 5 entry mapping

This table records the result/refusal mapping preserved while the entry owner
moves. Linux policy lives in `carrick-personality-linux`; core owns only exact
execution identity and completion admission.

| Pre-move condition | Pre-move result | Order 5 owner and result |
| --- | --- | --- |
| issued task, native x86_64 273 / canonical `set_robust_list`, length 24 | served, `0` | Linux entry, served `0`, one core completion |
| issued task, admitted robust-list with length other than 24 | served, `-22` (`EINVAL`) | Linux entry, served `-22`, one core completion |
| task generation or task identity absent | forward, no publication | core admission refuses; Linux entry forwards with no publication |
| lifecycle gate/hatch or exact thread lookup refuses | forward, no publication | Linux venue refuses; entry forwards with no publication |
| unknown or unported native ordinal | forward, no publication | Linux decoder leaves it unported; entry forwards with no publication |
| admitted call with pending host return work | served-with-work; host must not redispatch | Linux marks completed-with-work once and returns the sole core completion owner |
| completion presented after task/thread generation reuse | no prior typed completion check | core returns `WrongGeneration`; successor state is unchanged |

The ARM `TrapFrame`, ESR/IRQ classification, fixed-region acquisition, native
save/restore, x8 extraction, and x0 return remain in the EL1 adapter. The x86
`NativeFrame`, SYSCALL/IRET state, rax extraction and rax return remain in the
x86 adapter. Neither adapter owns a Linux ordinal table.
