# Shared exec preparation must preserve parent live authority

On source `aa5d55dd66b41f7a421f9fbf76bef9cd8f201526`, full CI passed
6,180 tests across 101 result groups, with zero failures and 12 existing ignores.
Its transcript is retained here (SHA-256
`a31bbabc0956db4fa428974e8a0d17b52e629089c7b89d9cf3fc18bf6c098c4f`).

Public probe promotion then passed generic shards 0 and 1 and completed 798
probe rows before GNU `forkexecstorm` aborted in anonymous discard with
unresolved parent root `0x9a00000000`. No output difference was reported before
the abort. Dedicated/CLI/retained probe stages and smoke/full were not reached.
Negative entitlement passed; both scoped run IDs had zero leftovers.

The same signed executable reproduces the abort with only `forkexecstorm`
selected. Its musl run completes, while GNU again aborts resolving the parent
root. The all-thread backtrace is retained here. The modified-memory core is
`target/el1-completion/live-integrated/forkexecstorm.core`, and its matching
executable is frozen under `forkexecstorm-before-fix/` in the same directory;
`before-identity.json` records its hash. Fresh native arm64 Docker runs of both
unchanged probe binaries match the committed Linux oracles and leave no
containers. Commands and identities are retained in `native-receipt.json`.

## Causal witness and correction

The existing VM-free shared-exec inventory test now also maps a parent VA,
checks translation, prepares the child exec inventory, and checks that the
parent still translates it. It fails on the unchanged runtime: the parent
translation becomes `None`. This is a behavioral failure, not a compile or
setup failure (`shared-exec-red.log`).

`begin_exec_inventory` creates a provisional child state around the parent's
shared page-table authority, then installed a child resolver backed by an empty
ledger. Installing that resolver mutates the shared authority. The correction
leaves the parent's resolver in place during preparation; the independent
successor gets its resolver in `execve_rebuild_inner`, as fixed in `aa5d55dd6`.
The causal witness now passes (`shared-exec-green.log`). No lookup scan,
weakened ownership check, retry, timeout change or serialization is introduced.

Full serial HVF validation passes 564 tests with 3 existing ignores. The signed
red-to-green `forkexecstorm` run passes both musl and GNU, matching the committed
source-hash-validated Linux oracles, with negative entitlement and zero scoped
leftovers. `after-identity.json`, `correction.patch` and `signed-artifacts.jsonl`
preserve the exact dirty-source patch and signed executable identity.
Full CI on this second correction and public probe/smoke/full promotion remain
open. EL1 first-touch execution and the complete migration scope remain open.
