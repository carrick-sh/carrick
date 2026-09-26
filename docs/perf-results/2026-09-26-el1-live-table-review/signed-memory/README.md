# Signed memory foundation checks

Product source: `54f3167a7`. Signed fork source receipt: `b6ce9ab26`;
occupancy source receipt: `5c1116d55`. Changes between these revisions are
only committed evidence/controller documentation. Full CI passed before these
signed runs. This is focused live-table foundation proof, not EL1 memory-stage
or full migration acceptance.

## Fork semantics and deterministic work

`fork_stage1_image_structural_contract` selected exactly three tests: direct,
dirty parent, and shell/exec. Each ran scales 1/8/32/128 and passed semantics,
complete measurements, and all registered structural budgets. Fresh image
counts were direct 1/1/2/2, dirty 1/1/1/2 and shell 0/1/1/1. Host mapping counts
were exactly the fork scale; projection counts were 20/174/702/3070 in each
mode. The separate allocator witness proves zero large buffer allocations in
warmed reuse; these pool counters alone do not prove that property.

The same-image native Docker semantic controls are in the sibling
`native-fork-54f3167a7` receipt. Signed negative entitlement passed and both
run IDs had zero remaining processes. The frozen fork binary is retained at
`target/el1-completion/live-integrated/signed-fork-frozen/conformance_contracts-38fb068f15bda479`.
Its SHA-256 is `bd64c57cd84927480c9cc129a773e27578769b594c6705505e5cc35f113acba1`.
`fork-artifacts.jsonl` records CDHash, UUID, entitlement, DOF and exact test names.

## Concurrent memory edits and forks

On the same pinned Ubuntu manifest, native arm64 Docker completed 150 forks
per process with 20 writers and zero failure counters. Signed Carrick completed
150 forks per process with 8 writers: parent 1064 edits, child 941 edits, all
failure counters zero. The fixture SHA-256 matches across both executions.
Docker finished and its named container was removed before Carrick ran.

Signed default, scheduler-disabled, futex-disabled and GIC-disabled controls
all passed exactly one occupancy test. All three controls used the unchanged
frozen signed executable and every scoped cleanup reported zero processes.
The default run's unentitled negative control also passed. The frozen artifact
is `target/el1-completion/live-integrated/occupancy-controls/signed-frozen`,
SHA-256 `11cefa914d29b316630284c7d8294b0bfe918cc8b1efbc35dc90c2cfbe2303f9`.
Full artifact identity and control environments are retained in the JSON files.

No timing ratio is claimed: the counters-enabled runs use their default CPU
populations and are semantic/structural witnesses. Public probe/smoke/full
promotion, actual EL1 fault handling, elastic frame grants/return, the full
memory contract, and every later migration stage remain open. The first-touch
structural red is unchanged. Preserve this foundation while implementing the
metadata ownership/allocation and fault-entry prerequisites.
