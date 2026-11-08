# Print the directory cargo builds into when invoked from crate directory $1.
#
# Ask cargo rather than re-deriving its rules: CARGO_TARGET_DIR,
# CARGO_BUILD_TARGET_DIR and `build.target-dir` in any inherited cargo config
# all move it, and a hand-written subset copied a stale binary without error
# when one of the others was set (#1913 review). Worker VMs set
# CARGO_TARGET_DIR to a shared state directory (carrick-conductor
# worker_exec), so a fixture script that hard-codes "<crate>/target" copies
# from a directory cargo never wrote. Sourced by the scripts/build-embed-*.sh
# fixture builders. POSIX sh has no `local`, so only "$1" is used here and the
# caller's variables are left untouched.
cargo_target_dir() {
    (cd "$1" && cargo metadata --format-version 1 --no-deps --locked) |
        sed -n 's/.*"target_directory":"\([^"]*\)".*/\1/p'
}
