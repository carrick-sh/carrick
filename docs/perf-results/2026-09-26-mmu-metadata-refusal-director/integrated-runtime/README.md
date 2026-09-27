# Integrated runtime refusal conversion

Compiler capture on c697c35fa failed with E0004: clone TID publication's
MemoryError diagnostic match omitted MetadataAllocation. This is an actual
integration compile failure, not semantic red evidence. The four-package
worker checks did not compile this runtime caller.

The correction adds an explicit typed diagnostic result, appending ordinal 6
without renumbering existing provider values. Publication still returns false
on refusal, and the transaction retains both preimages for rollback. The five
serial clone TID tests pass, including the new metadata-refusal control; the
provider ABI test also passes. Commands:

- RUSTC_WRAPPER= cargo test -p carrick-runtime --lib clone_tid_output_tests -- --test-threads=1
- RUSTC_WRAPPER= cargo test -p carrick-observability --lib mn_clone_tid_output_provider_keeps_role_and_memory_error_typed

Full CI, refreshed authority inventory and signed promotion remain pending.
