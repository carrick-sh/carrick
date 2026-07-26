#!/bin/sh
# vm-entry-attrs.sh - run the top-level VM-entry walker against one pid as root.
#
# WHY THIS EXISTS
# ---------------
# host fork(2) of a carrick guest costs ~16x an ordinary process, and the cost is
# kernel CPU under task_create_internal / vm_map_terminate. xnu's vm_map_fork()
# iterates TOP-LEVEL vm_map entries and classifies each one by its inheritance,
# submap-ness, wiring and backing-object properties; some dispositions are cheap
# (VM_INHERIT_SHARE, VM_INHERIT_NONE) and some run a symmetric-CoW preflight that
# can degrade to one pmap_protect call PER RESIDENT PAGE. To reason about which
# disposition carrick's entries actually take we need the REAL per-entry
# attributes of a live guest process.
#
# `vmmap -v` cannot answer this: it decomposes nested submaps (the dyld shared
# cache is ONE top-level entry) into ~23,000 rows, so its row count measures the
# wrong quantity. The helper walks with mach_vm_region_recurse and pins
# *nesting_depth = 0 on every call, which reports top-level entries only.
#
# task_for_pid() on another process needs root, hence this wrapper (sudo is
# NOPASSWD for scripts under scripts/*/). It is READ-ONLY: it inspects a VM map
# and prints a TSV table. It starts, signals and modifies nothing.
#
#   usage: sudo scripts/sudo/vm-entry-attrs.sh <helper-binary> <pid>
#
# The helper binary is built outside the repo (scratch dir) and passed in; this
# wrapper only sanity-checks it and execs it, so the privileged surface stays
# small and readable.

set -eu

helper="${1:-}"
pid="${2:-}"

if [ -z "$helper" ] || [ -z "$pid" ]; then
    echo "usage: vm-entry-attrs.sh <helper-binary> <pid>" >&2
    exit 2
fi

# Scope the privilege: only ever exec the one named diagnostic helper.
case "$(basename "$helper")" in
    vm_entry_attrs) ;;
    *) echo "vm-entry-attrs.sh: refusing to exec '$helper' (expected basename vm_entry_attrs)" >&2
       exit 2 ;;
esac

if [ ! -x "$helper" ]; then
    echo "vm-entry-attrs.sh: '$helper' is not an executable file" >&2
    exit 2
fi

# pid must be a bare positive integer.
case "$pid" in
    ''|*[!0-9]*) echo "vm-entry-attrs.sh: pid '$pid' is not a number" >&2; exit 2 ;;
esac

exec "$helper" "$pid"
