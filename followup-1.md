# Follow-up: HostFileOp discriminant 22 is claimed twice (#2214 Fchdir, #2084 Readlinkat)

Both open PRs add `HostFileOp::<op> = 22` in `crates/carrick-core-abi/src/host_file.rs`, along with the
matching `from_u32` arm and `resolves_path` entry. A textual rebase may not flag
it, because the enum lines differ. Whichever lands second must renumber its op to 23 and update
both tables. Its venue tests then confirm that the record round-trips.
