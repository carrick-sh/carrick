# Final metadata refusal review and director correction

Worker 68bb6dc79 completed its third and final review round. Its five host
commands pass independently, and the real >8-arena publication refusal now
flows through production converters under an allocator refusal guard.
However, source still contained the old fitted admission caps despite the
worker report and README claiming derived bounds and a negative-control test.
The report alone was not accepted. No fourth worker round was opened.

The director replaced those caps with structure-derived budgets, published
fixture setup before measuring admission, removed an unused public converter
used only by tests, and bound the actual budget witness in the contract.
Authentic production-mutation red/green evidence is preserved in
../../2026-09-26-mmu-metadata-refusal/director-final-controls/.
Exact growth fails at scale 32 (112 allocations > 99); a new rollback Vec
fails at scale 1 (one allocation > zero). Restored source passes all scales.

All five commands pass on the final correction. An intermediate registry
failure from an unsupported host_heap_bytes metric is preserved separately;
the existing metric schema is retained and requested-byte assertions remain
inside the registered VM-free test. Source code was unchanged by that schema
repair. No guest ran and no checkpoint or full CI acceptance is claimed here.
Known infallible MMU lifecycle paths remain explicit migration obligations.
