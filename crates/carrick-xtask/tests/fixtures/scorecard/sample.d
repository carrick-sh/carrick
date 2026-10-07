# Makefile-style dep-info fixture for unit testing parse_dep_info
target/release/sample.d: crates/carrick-core/src/lib.rs \
 crates/carrick-core/src/entry.rs \
 crates/carrick-core/src/mm/mod.rs \
 crates/carrick-core/src/path\ with\ space/foo.rs

target/release/sample: crates/carrick-core/src/lib.rs \
 crates/carrick-core/src/entry.rs

# Prerequisite-only rules
crates/carrick-core/src/lib.rs:
crates/carrick-core/src/entry.rs:
crates/carrick-core/src/mm/mod.rs:
crates/carrick-core/src/path\ with\ space/foo.rs:
