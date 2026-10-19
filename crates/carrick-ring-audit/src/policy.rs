//! The ring stack budget each ring image must meet.

use crate::frames::{Arch, IndirectRule, NamedCeiling, Policy, RecursionMember, RecursionRule};

/// Ceiling on any single ring function's own frame: low enough that a
/// by-value record like #338's 0x2190-byte `publish_exit` frame fails. A
/// frame wider than its ring's guard must also probe page by page (checked
/// per image), so no frame steps over a guard without touching it.
pub const RING_FUNCTION_FRAME_CEILING: u64 = 0x2000;
const _: () = assert!(RING_FUNCTION_FRAME_CEILING < carrick_el1_abi::EL1_STACK_GUARD_SIZE);

/// The frames that retain stack across owner entry and exit, pinned for
/// #338 and relied on by #673/#691. Tail-call wrappers do not stand in for
/// their callee's budget.
pub const EL1_EXIT_FRAME_CEILINGS: &[NamedCeiling] = &[
    // Runtime table construction stays in place on the heap, never
    // materializing the pending-fork array on a 16 KiB EL1 stack.
    NamedCeiling {
        symbol: "::PendingForkStorage::initialize::",
        ceiling: 0x100,
        required: true,
    },
    NamedCeiling {
        symbol: "::dispatch::dispatch_syscall::",
        ceiling: 0x600,
        required: true,
    },
    NamedCeiling {
        symbol: "::aarch64_process::admit_entry_runtime::",
        ceiling: 0x1200,
        required: true,
    },
    NamedCeiling {
        symbol: "::exit_with_status::",
        ceiling: 0x600,
        required: true,
    },
    NamedCeiling {
        symbol: "::finish_exit::",
        ceiling: 0x800,
        required: true,
    },
    NamedCeiling {
        symbol: "::aarch64_process::resume_selected::",
        ceiling: 0xa00,
        required: true,
    },
    NamedCeiling {
        symbol: "::resume_checkpoint::",
        ceiling: 0x400,
        required: true,
    },
    // The ARM codec is dormant until #323 routes rt_sigreturn in-ring. Once
    // linked, its frame must fit; #323 makes this symbol required as part of
    // the atomic signal-owner cutover.
    NamedCeiling {
        symbol: "Aarch64Backend$GT$::restore_signal_frame::",
        ceiling: 0x1300,
        required: false,
    },
];

/// Recursion shared by both rings, with its reviewed activation bounds.
pub const RECURSION: &[RecursionRule] = &[
    RecursionRule {
        members: &[
            RecursionMember {
                pattern: "descriptor_txn::Executor<W,J>::descend",
                max_live: 4,
            },
            RecursionMember {
                pattern: "descriptor_txn::Executor<W,J>::visit_entry",
                max_live: 4,
            },
            RecursionMember {
                pattern: "descriptor_txn::Executor<W,J>::visit_live_table",
                max_live: 4,
            },
        ],
        why: "one activation per stage-1 table level; the AArch64 walk has four (L0..L3)",
    },
    RecursionRule {
        members: &[RecursionMember {
            pattern: "x86::descriptor_txn::Planner<W>::edit",
            max_live: 4,
        }],
        why: "one activation per x86 paging level; the walk has four (PML4..PT)",
    },
    RecursionRule {
        members: &[
            RecursionMember {
                pattern: "carrick_core::mm::fork::copy_entry",
                max_live: 4,
            },
            RecursionMember {
                pattern: "carrick_core::mm::fork::copy_table",
                max_live: 4,
            },
        ],
        why: "fork copies one table per translation level; four levels",
    },
    RecursionRule {
        members: &[
            RecursionMember {
                pattern: "carrick_core::mm::fork::census_entry",
                max_live: 4,
            },
            RecursionMember {
                pattern: "carrick_core::mm::fork::census_table",
                max_live: 4,
            },
        ],
        why: "fork census visits one table per translation level; four levels",
    },
    RecursionRule {
        members: &[
            RecursionMember {
                pattern: "Reservations<Policy,Geometry,C>::release_tree",
                max_live: 29,
            },
            RecursionMember {
                pattern: "Reservations<Policy,Geometry,C>::build_balanced",
                max_live: 29,
            },
            RecursionMember {
                pattern: "Reservations<Policy,Geometry,C>::source_insert",
                max_live: 29,
            },
            RecursionMember {
                pattern: "Reservations<Policy,Geometry,C>::copy_in_order",
                max_live: 29,
            },
            RecursionMember {
                pattern: "Reservations<Policy,Geometry,C>::observe_tree",
                max_live: 29,
            },
        ],
        why: "AVL height bound: storage holds at most 1024 + 256 * 4096 nodes, and an AVL tree \
              of fewer than F(31) - 1 = 1346268 nodes is at most 29 levels high",
    },
    RecursionRule {
        members: &[
            RecursionMember {
                pattern: "NativeProcessError::errno",
                max_live: 2,
            },
            RecursionMember {
                pattern: "NativeProcessError::run_failure_reason",
                max_live: 2,
            },
        ],
        why: "an error wraps at most one nested native-process error",
    },
    RecursionRule {
        members: &[
            RecursionMember {
                pattern: "signal_delivery::force_delivery_fault",
                max_live: 2,
            },
            RecursionMember {
                pattern: "signal_delivery::deliver_signal_on_syscall_return",
                max_live: 2,
            },
        ],
        why: "a failed delivery forces SIGSEGV once; the forced delivery cannot fault again",
    },
    RecursionRule {
        members: &[
            RecursionMember {
                pattern: "core::slice::sort::stable::quicksort::quicksort",
                max_live: 25,
            },
            RecursionMember {
                pattern: "core::slice::sort::stable::drift::sort",
                max_live: 2,
            },
            RecursionMember {
                pattern: "core::slice::sort::unstable::quicksort::quicksort",
                max_live: 25,
            },
            RecursionMember {
                pattern: "core::slice::sort::shared::pivot::median3_rec",
                max_live: 5,
            },
        ],
        why: "core's quicksort limit is 2 * ilog2(len) and ring sorts hold at most ZONE_RECORDS \
              (4096) elements; median3_rec recurses once per factor of eight",
    },
    RecursionRule {
        members: &[RecursionMember {
            pattern: "BTreeMap<K,V,A> as core::clone::Clone>::clone::clone_subtree",
            max_live: 12,
        }],
        why: "one activation per B-tree level; a B-tree of B = 6 holding 4096 entries has at most 12",
    },
];

/// Indirect calls shared by both rings. Each budget is a reviewed
/// assumption about what the call can reach, charged at every such call.
pub const INDIRECT: &[IndirectRule] = &[
    IndirectRule {
        caller: "carrick_mmu_core::",
        budget: 0x400,
        why: "descriptor words, journals and TLB maintenance behind `&dyn` leaf traits",
    },
    IndirectRule {
        caller: "carrick_core::mm::reservation::",
        budget: 0x400,
        why: "node storage resolution and observer closures",
    },
    IndirectRule {
        caller: "alloc::",
        budget: 0x400,
        why: "drop glue of boxed values held in collections",
    },
    IndirectRule {
        caller: "core::",
        budget: 0x400,
        why: "drop glue and iterator closures",
    },
    IndirectRule {
        caller: "carrick_core::",
        budget: 0x800,
        why: "portal, lifecycle and terminal venue callbacks into the ring personality",
    },
    IndirectRule {
        caller: "carrick_sched_core::",
        budget: 0x800,
        why: "scheduler and process-registry venue callbacks",
    },
    IndirectRule {
        caller: "carrick_personality_linux::",
        budget: 0x800,
        why: "syscall families dispatched through the personality's venue traits",
    },
    IndirectRule {
        caller: "carrick_el1_linux::",
        budget: 0x800,
        why: "the ring Linux personality's native process service and venues",
    },
    IndirectRule {
        caller: "carrick_el1::",
        budget: 0x800,
        why: "native process service and drop glue behind trait objects",
    },
    IndirectRule {
        caller: "carrick_x86_",
        budget: 0x800,
        why: "carrier personality hooks",
    },
];

/// Ratchet on the ARM entry chain with recursion at its bounds. It exceeds
/// the usable stack today (#369): it may only decrease, and reaches
/// [`carrick_el1_abi::EL1_ENTRY_STACK_BUDGET`] when the bounded worst case
/// fits. Until then a deep enough recursion runs into the guard page.
pub const AARCH64_BOUNDED_CEILING: u64 = 0x6800;

pub const AARCH64: Policy = Policy {
    arch: Arch::Aarch64,
    entries: &["carrick_el1_syscall"],
    stack_budget: carrick_el1_abi::EL1_ENTRY_STACK_BUDGET,
    bounded_ceiling: AARCH64_BOUNDED_CEILING,
    guard: carrick_el1_abi::EL1_STACK_GUARD_SIZE,
    function_ceiling: RING_FUNCTION_FRAME_CEILING,
    named_ceilings: EL1_EXIT_FRAME_CEILINGS,
    recursion: RECURSION,
    indirect: INDIRECT,
};

pub const X86_64: Policy = Policy {
    arch: Arch::X86_64,
    entries: &[
        "carrick_x86_syscall",
        "carrick_x86_user_page_fault",
        "carrick_x86_irq_common",
        "carrick_x86_initial_boot",
        "carrick_x86_peer_boot",
    ],
    stack_budget: carrick_el1_abi::X86_CPL0_ENTRY_STACK_BUDGET,
    bounded_ceiling: carrick_el1_abi::X86_CPL0_ENTRY_STACK_BUDGET,
    guard: carrick_el1_abi::X86_CPL0_KERNEL_STACK_GUARD_SIZE,
    function_ceiling: RING_FUNCTION_FRAME_CEILING,
    named_ceilings: &[],
    recursion: RECURSION,
    indirect: INDIRECT,
};

/// A ring image a `cargo clippy` run builds goes through `clippy-driver`,
/// which turns MIR optimization off. Such an image never ships, and its
/// frames are not the shipped image's: EL1 `prepare_mm` takes 0x403f bytes
/// there (more than the whole stack) against 0xabf in the real image, CPL0
/// `prepare_loaned` 0x5030. A clippy build enforces exactly the #338 EL1
/// exit-frame pins, as before #369; every other build enforces the whole
/// policy for its architecture.
const fn unoptimized_mir(policy: Policy) -> Policy {
    Policy {
        entries: &[],
        stack_budget: u64::MAX,
        bounded_ceiling: u64::MAX,
        guard: u64::MAX,
        function_ceiling: u64::MAX,
        ..policy
    }
}

pub const AARCH64_UNOPTIMIZED_MIR: Policy = unoptimized_mir(AARCH64);
pub const X86_64_UNOPTIMIZED_MIR: Policy = unoptimized_mir(X86_64);

/// The policy a build script applies to the ring image of `arch` it built.
/// `clippy` is the build script's own `cfg!(clippy)`: under `cargo clippy`
/// the build script and the nested image build both go through
/// `clippy-driver`.
pub const fn for_build(arch: Arch, clippy: bool) -> &'static Policy {
    match (arch, clippy) {
        (Arch::Aarch64, false) => &AARCH64,
        (Arch::Aarch64, true) => &AARCH64_UNOPTIMIZED_MIR,
        (Arch::X86_64, false) => &X86_64,
        (Arch::X86_64, true) => &X86_64_UNOPTIMIZED_MIR,
    }
}

/// The policy for a ring image of `arch`.
pub const fn for_arch(arch: Arch) -> &'static Policy {
    match arch {
        Arch::Aarch64 => &AARCH64,
        Arch::X86_64 => &X86_64,
    }
}
