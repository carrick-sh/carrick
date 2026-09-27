# Integrated CI correction

Full `just ci` at `25cbc949f` failed in Clippy with three errors in the
fault-entry test code: identical branches and constant-value assertions.
The correction combines the equivalent predicates and evaluates vector
region bounds in a const block. No runtime implementation changes.

Targeted `cargo clippy -p carrick-mem --all-targets -- -D warnings` passes.
The full CI rerun remains required; this targeted result does not close it.
