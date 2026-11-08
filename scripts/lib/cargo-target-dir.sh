# Print the directory cargo builds into when invoked from crate directory $1.
#
# cargo honours CARGO_TARGET_DIR (resolved against the invoking directory when
# relative) and otherwise uses <crate>/target. Worker VMs set CARGO_TARGET_DIR
# to a shared state directory (carrick-conductor worker_exec), so a fixture
# script that hard-codes "$crate_dir/target" copies from a directory cargo
# never wrote (#1888). Sourced by the scripts/build-embed-*.sh fixture builders.
cargo_target_dir() {
    crate_dir=$1
    case "${CARGO_TARGET_DIR:-}" in
        "") printf '%s\n' "$crate_dir/target" ;;
        /*) printf '%s\n' "$CARGO_TARGET_DIR" ;;
        *) printf '%s\n' "$crate_dir/$CARGO_TARGET_DIR" ;;
    esac
}
