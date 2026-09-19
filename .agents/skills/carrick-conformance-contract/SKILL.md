---
name: carrick-conformance-contract
description: Use when planning or implementing a Carrick change that can affect guest-visible Linux behavior or operational cost.
---

# Carrick conformance contract workflow

## Core rule

Guest-visible correctness includes Linux semantics and non-pathological work.
A semantic pass never excuses a structural-budget or runtime-ratio failure.

## Required workflow

1. Read `AGENTS.md`, `docs/conformance-contracts.md`, and the active controller.
2. Name the guest surface and existing contract ID. If none exists, add the
   contract red-first.
3. State the Linux semantic authority and Carrick structural invariant.
4. Choose the cheapest capable layer and capture semantic and structural red
   evidence before changing implementation code.
5. Implement the smallest architectural correction. Do not weaken a budget,
   retry, increase a timeout, lower concurrency, poll, or serialize symptoms.
6. Run the VM-free contract, signed embed binding, and applicable Docker
   differential. Carrick and Docker phases stay serialized.
7. When the change reaches signed acceptance, promote one exact artifact in
   order: `just conformance-probes`, `just conformance smoke`, `just conformance`.
8. Record exact evidence, artifact provenance, scoped cleanup, and every
   uncompleted higher-layer gate.

## Stop conditions

Stop promotion and report the named failure when:

- measurement is incomplete, unknown, overflowed, or dropped;
- source, binary, image, probe, lane, or oracle identity is missing or mismatched;
- a required execution layer has no registered binding; or
- a valid completing workload is at least 10x Docker.

Do not convert these states to skips, expected gaps, retries, or wider budgets.

## Quick reference

| Question | Required answer |
|---|---|
| What changed? | Guest surface and contract ID |
| What is correct? | Linux authority plus structural invariant |
| Where is the first proof? | Cheapest capable layer |
| What must be red first? | Semantic or deterministic work assertion |
| What times the result? | Uninstrumented release Carrick vs pinned same-image Docker |
| What closes it? | Green lower layers, signed promotion, provenance, cleanup |

## Red flags

- “The output matches, so performance can follow later.”
- “The test is flaky; retry it.”
- “Raise the timeout or reduce concurrency.”
- “The instrumented run is fast enough.”
- “This path has no contract, so use the nearest test.”

Each statement means stop and restore the contract workflow.

## Common rationalizations

| Excuse | Reality |
|---|---|
| “It is only an optimization.” | Guest-visible amplification changes correctness. |
| “Docker is too expensive for the inner loop.” | Use cached authority and VM-free structure; Docker remains the deliberate oracle phase. |
| “The counter is implementation detail.” | Use stable architectural work units and scaling laws, not line-level events. |
| “This focused pass closes the issue.” | It closes only the named contract; higher-layer acceptance remains explicit. |
