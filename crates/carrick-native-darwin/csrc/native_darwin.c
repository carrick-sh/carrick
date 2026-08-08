#ifndef _XOPEN_SOURCE
#define _XOPEN_SOURCE 700
#endif
#ifndef _DARWIN_C_SOURCE
#define _DARWIN_C_SOURCE
#endif
#include <dlfcn.h>
#include <errno.h>
#include <libkern/OSCacheControl.h>
#include <mach/arm/exception.h>
#include <mach/arm/thread_status.h>
#include <mach/mach.h>
#include <mach/mach_vm.h>
#include <mach-o/dyld.h>
#include <pthread.h>
#include <ptrauth.h>
#include <setjmp.h>
#include <signal.h>
#include <stddef.h>
#include <stdbool.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <ucontext.h>
#include <unistd.h>

#include "carrick_mach_exc_server.h"

struct carrick_native_ucontext_snapshot {
    uint64_t x[31];
    uint64_t sp;
    uint64_t pc;
    uint64_t pstate;
    uint8_t v[32][16];
    uint32_t fpsr;
    uint32_t fpcr;
    int32_t event_kind;
    int32_t signal;
    int32_t signal_code;
    uint64_t fault_address;
    uint64_t esr;
    uint64_t far;
};

struct carrick_native_executable_range_node {
    uint64_t start;
    uint64_t end;
    const struct carrick_native_executable_range_node *next;
};

struct carrick_native_executable_range_catalog {
    _Atomic(struct carrick_native_executable_range_node *) head;
};

struct carrick_native_dsr_signal_context {
    struct carrick_native_ucontext_snapshot snapshot;
    uint64_t host_sp;
    uint8_t gateway_private[232];
    uint64_t entry;
    uint64_t exit_target;
    uint64_t exit_source;
    uint32_t exit_status;
    uint32_t exit_pad;
    uint64_t exit_link;
    uint32_t exit_has_link;
    uint32_t exit_link_pad;
    uint8_t gateway_tail[32];
    uint32_t entry_in_progress;
    uint32_t entry_pad;
    uint64_t indirect_x15_scratch;
    uint64_t indirect_x30_scratch;
    uint64_t cache_start;
    uint64_t cache_end;
    uint64_t host_bias;
    uint64_t biased_guest_fault_address;
    /* Interrupted physical x19 (the DSR reserved scratch), stashed at
       fault/kick capture for the reserved-resident commit recovery. */
    uint64_t physical_reserved;
    /* Gateway exit entry points; see the Rust mirror. Appended, so every
       offset above is unchanged. */
    uint64_t exit_syscall_addr;
    uint64_t exit_direct_addr;
    uint64_t exit_indirect_addr;
    uint64_t exit_sensitive_addr;
    uint64_t exit_unsupported_addr;
    uint64_t exit_signal_addr;
    const void *generation_bindings;
    /* The DSR indirect-cache pointer, relocated here (read-mostly line)
       from the store-heavy 1136 slot; opaque to the signal handler. */
    uint64_t indirect_cache_hot;
    uint64_t direct_binding_cell;
    uint32_t direct_binding_ordinal;
    uint32_t direct_binding_present;
    uint64_t direct_binding_target;
    const struct carrick_native_executable_range_catalog
        *executable_range_catalog;
} __attribute__((aligned(16)));

/* Append-only mirror of direct.rs' DirectThreadSlots. Existing emitted code
   bakes offsets through resume_extras; the fault handoff deliberately follows
   it so those offsets stay unchanged. */
struct carrick_native_direct_guest_context {
    uint64_t x[31];
    uint64_t sp;
    uint64_t pc;
    uint64_t handler;
    uint64_t host_sp;
    uint64_t host_lr;
    uint64_t leave;
};

struct carrick_native_direct_extras {
    uint64_t restore;
    uint64_t pstate;
    uint64_t fpsr;
    uint64_t fpcr;
    uint64_t pad[2];
    uint8_t v[32][16];
};

struct carrick_native_direct_fault {
    uint64_t pending;
    int32_t signal;
    int32_t code;
    uint64_t address;
    uint64_t esr;
    uint64_t far;
};

struct carrick_native_direct_exception_telemetry {
    uint64_t installs;
    uint64_t fork_rebinds;
    uint64_t exception_entries;
    uint64_t bad_access_entries;
    uint64_t breakpoint_entries;
    uint64_t recovery_services;
    uint64_t execute_switches;
    uint64_t write_switches;
    uint64_t failures;
    uint64_t last_exception;
    uint64_t last_status;
    uint64_t bad_instruction_entries;
    uint64_t sysreg_emulations;
};

struct carrick_native_direct_slots {
    struct carrick_native_direct_guest_context context;
    uint64_t guest_tls;
    uint64_t guest_x18;
    uint64_t fp_align;
    struct carrick_native_direct_extras parked_fp;
    struct carrick_native_direct_extras resume_extras;
    struct carrick_native_direct_fault fault;
    struct carrick_native_direct_exception_telemetry exception_telemetry;
};

_Static_assert(sizeof(struct carrick_native_direct_guest_context) == 296,
               "Tier-D direct guest context size");
_Static_assert(sizeof(struct carrick_native_direct_extras) == 560,
               "Tier-D direct extras size");
_Static_assert(offsetof(struct carrick_native_direct_slots, guest_tls) == 296,
               "Tier-D direct TLS offset");
_Static_assert(offsetof(struct carrick_native_direct_slots, guest_x18) == 304,
               "Tier-D direct x18 offset");
_Static_assert(offsetof(struct carrick_native_direct_slots, parked_fp) == 320,
               "Tier-D direct parked FP offset");
_Static_assert(offsetof(struct carrick_native_direct_slots, resume_extras) == 880,
               "Tier-D direct resume extras offset");
_Static_assert(offsetof(struct carrick_native_direct_slots, fault) == 1440,
               "Tier-D direct fault offset");
_Static_assert(offsetof(struct carrick_native_direct_slots,
                        exception_telemetry) == 1480,
               "Tier-D direct exception telemetry offset");
_Static_assert(sizeof(struct carrick_native_direct_exception_telemetry) == 104,
               "Tier-D direct exception telemetry size");
_Static_assert(sizeof(struct carrick_native_direct_slots) == 1584,
               "Tier-D direct slots size");

#define CARRICK_NATIVE_DIRECT_EXCEPTION_MASK                                \
    (EXC_MASK_BAD_ACCESS | EXC_MASK_BREAKPOINT | EXC_MASK_BAD_INSTRUCTION)

extern int carrick_native_direct_emulate_sysreg(uint32_t instruction,
                                                uint64_t *value);

/* A Mach exception suspends the guest thread and delivers its GPR state to a
   server thread. The server redirects the guest to a plain-RX trampoline;
   that trampoline runs on the original thread, so the per-thread MAP_JIT
   switch affects the right execution context. It ends with a private BRK,
   allowing the server to return the original GPR state exactly. */
struct carrick_native_direct_exception_registration {
    uint8_t vector[32][16];
    uint64_t fpsr;
    uint64_t fpcr;
    struct carrick_native_direct_exception_registration *next;
    struct carrick_native_direct_slots *slots;
    arm_thread_state64_t original_state;
    mach_msg_type_number_t original_state_count;
    mach_port_t exception_port;
    mach_port_t thread_port;
    exception_mask_t old_masks[EXC_TYPES_COUNT];
    mach_port_t old_handlers[EXC_TYPES_COUNT];
    exception_behavior_t old_behaviors[EXC_TYPES_COUNT];
    thread_state_flavor_t old_flavors[EXC_TYPES_COUNT];
    mach_msg_type_number_t old_count;
    uintptr_t fault_pc;
    uintptr_t fault_address;
    int64_t fault_code;
    int32_t fault_exception;
    int32_t recovery_kind;
    int32_t service_status;
    int32_t recovery_pending;
};

_Static_assert(offsetof(
                   struct carrick_native_direct_exception_registration,
                   vector) == 0,
               "Mach recovery vector offset");
_Static_assert(offsetof(
                   struct carrick_native_direct_exception_registration,
                   fpsr) == 512,
               "Mach recovery FPSR offset");
_Static_assert(offsetof(
                   struct carrick_native_direct_exception_registration,
                   fpcr) == 520,
               "Mach recovery FPCR offset");

_Static_assert(ATOMIC_POINTER_LOCK_FREE == 2,
               "DSR executable range catalog requires lock-free pointers");
_Static_assert(sizeof(struct carrick_native_executable_range_catalog) == 8,
               "DSR executable range catalog header size");
_Static_assert(_Alignof(struct carrick_native_executable_range_catalog) == 8,
               "DSR executable range catalog header alignment");
_Static_assert(offsetof(struct carrick_native_executable_range_catalog, head) == 0,
               "DSR executable range catalog head offset");
_Static_assert(sizeof(struct carrick_native_executable_range_node) == 24,
               "DSR executable range catalog node size");
_Static_assert(_Alignof(struct carrick_native_executable_range_node) == 8,
               "DSR executable range catalog node alignment");
_Static_assert(offsetof(struct carrick_native_executable_range_node, start) == 0,
               "DSR executable range start offset");
_Static_assert(offsetof(struct carrick_native_executable_range_node, end) == 8,
               "DSR executable range end offset");
_Static_assert(offsetof(struct carrick_native_executable_range_node, next) == 16,
               "DSR executable range next offset");
_Static_assert(offsetof(struct carrick_native_dsr_signal_context, host_sp) == 832,
               "DSR signal host SP offset");
_Static_assert(offsetof(struct carrick_native_dsr_signal_context, exit_target) == 1080,
               "DSR signal target offset");
_Static_assert(offsetof(struct carrick_native_dsr_signal_context, exit_source) == 1088,
               "DSR signal source offset");
_Static_assert(offsetof(struct carrick_native_dsr_signal_context, exit_status) == 1096,
               "DSR signal status offset");
_Static_assert(offsetof(struct carrick_native_dsr_signal_context, exit_link) == 1104,
               "DSR signal physical x18 offset");
_Static_assert(offsetof(struct carrick_native_dsr_signal_context, exit_has_link) == 1112,
               "DSR signal phase offset");
_Static_assert(offsetof(struct carrick_native_dsr_signal_context, entry_in_progress) == 1152,
               "DSR entry-progress offset");
_Static_assert(offsetof(struct carrick_native_dsr_signal_context, indirect_x15_scratch) == 1160,
               "DSR indirect x15 scratch offset");
_Static_assert(offsetof(struct carrick_native_dsr_signal_context, indirect_x30_scratch) == 1168,
               "DSR indirect x30 scratch offset");
_Static_assert(offsetof(struct carrick_native_dsr_signal_context, cache_start) == 1176,
               "DSR cache start offset");
_Static_assert(offsetof(struct carrick_native_dsr_signal_context, cache_end) == 1184,
               "DSR cache end offset");
_Static_assert(offsetof(struct carrick_native_dsr_signal_context, host_bias) == 1192,
               "DSR host bias offset");
_Static_assert(offsetof(struct carrick_native_dsr_signal_context, biased_guest_fault_address) == 1200,
               "DSR biased guest fault address offset");
_Static_assert(offsetof(struct carrick_native_dsr_signal_context, physical_reserved) == 1208,
               "DSR signal physical reserved-scratch offset");
_Static_assert(offsetof(struct carrick_native_dsr_signal_context, exit_syscall_addr) == 1216,
               "DSR gateway syscall exit address offset");
_Static_assert(offsetof(struct carrick_native_dsr_signal_context, generation_bindings) == 1264,
               "DSR generation binding pointer offset");
_Static_assert(offsetof(struct carrick_native_dsr_signal_context, indirect_cache_hot) == 1272,
               "DSR relocated indirect-cache pointer offset");
_Static_assert(offsetof(struct carrick_native_dsr_signal_context, direct_binding_cell) == 1280,
               "DSR direct binding cell offset");
_Static_assert(offsetof(struct carrick_native_dsr_signal_context, direct_binding_ordinal) == 1288,
               "DSR direct binding ordinal offset");
_Static_assert(offsetof(struct carrick_native_dsr_signal_context, direct_binding_present) == 1292,
               "DSR direct binding present offset");
_Static_assert(offsetof(struct carrick_native_dsr_signal_context, direct_binding_target) == 1296,
               "DSR direct binding target offset");
_Static_assert(offsetof(struct carrick_native_dsr_signal_context, executable_range_catalog) == 1304,
               "DSR executable range catalog pointer offset");
_Static_assert(sizeof(struct carrick_native_dsr_signal_context) == 1312,
               "DSR signal context size");
_Static_assert(_Alignof(struct carrick_native_dsr_signal_context) == 16,
               "DSR signal context alignment");

struct carrick_native_kick_state {
    _Atomic uint64_t requested;
    _Atomic uint64_t acknowledged;
    _Atomic bool pending;
};

static _Thread_local struct carrick_native_kick_state
    *carrick_native_bound_kick_state;

static bool carrick_native_kick_state_take(
    struct carrick_native_kick_state *state) {
    if (state == 0 || !atomic_exchange_explicit(
                          &state->pending,
                          false,
                          memory_order_seq_cst)) {
        return false;
    }
    uint64_t requested = atomic_load_explicit(
        &state->requested,
        memory_order_seq_cst);
    atomic_store_explicit(
        &state->acknowledged,
        requested,
        memory_order_seq_cst);
    return true;
}

void *carrick_native_kick_state_create(void) {
    struct carrick_native_kick_state *state = calloc(1, sizeof(*state));
    if (state == 0) {
        return 0;
    }

    atomic_init(&state->requested, 0);
    atomic_init(&state->acknowledged, 0);
    atomic_init(&state->pending, false);
    if (!atomic_is_lock_free(&state->requested) ||
        !atomic_is_lock_free(&state->acknowledged) ||
        !atomic_is_lock_free(&state->pending)) {
        free(state);
        errno = ENOTSUP;
        return 0;
    }
    return state;
}

void carrick_native_kick_state_destroy(void *opaque) {
    free(opaque);
}

int carrick_native_kick_state_request(void *opaque) {
    struct carrick_native_kick_state *state = opaque;
    if (state == 0) {
        errno = EINVAL;
        return -1;
    }

    atomic_fetch_add_explicit(&state->requested, 1, memory_order_seq_cst);
    bool was_pending = atomic_exchange_explicit(
        &state->pending,
        true,
        memory_order_seq_cst);
    return was_pending ? 0 : 1;
}

void carrick_native_kick_state_acknowledge(void *opaque) {
    struct carrick_native_kick_state *state = opaque;
    (void)carrick_native_kick_state_take(state);
}

int carrick_native_kick_state_bind_current(void *opaque) {
    struct carrick_native_kick_state *state = opaque;
    if (state == 0) {
        errno = EINVAL;
        return -1;
    }
    carrick_native_bound_kick_state = state;
    return 0;
}

void carrick_native_kick_state_unbind_current(void *opaque) {
    if (carrick_native_bound_kick_state == opaque) {
        carrick_native_bound_kick_state = 0;
    }
}

uint64_t carrick_native_kick_state_requested(void *opaque) {
    struct carrick_native_kick_state *state = opaque;
    return state == 0
               ? 0
               : atomic_load_explicit(
                     &state->requested,
                     memory_order_seq_cst);
}

uint64_t carrick_native_kick_state_acknowledged(void *opaque) {
    struct carrick_native_kick_state *state = opaque;
    return state == 0
               ? 0
               : atomic_load_explicit(
                     &state->acknowledged,
                     memory_order_seq_cst);
}

#if defined(__aarch64__)
static _Thread_local unsigned char carrick_native_signal_stack[64 * 1024]
    __attribute__((aligned(16)));
static _Thread_local uint64_t carrick_native_host_tpidr_el0;
static _Thread_local struct carrick_native_dsr_signal_context
    *carrick_native_active_dsr_context;
#define CARRICK_NATIVE_DIRECT_RANGE_CAPACITY 128
#define CARRICK_NATIVE_DIRECT_PUBLICATION_CAPACITY 4096
#define CARRICK_NATIVE_DIRECT_EXCEPTION_ROUTE_CAPACITY 8192
struct carrick_native_direct_range {
    _Atomic uintptr_t start;
    _Atomic uintptr_t end;
    /* `mapping_generation` prevents a late publisher from an unmapped range
       authorizing an unrelated MAP_JIT mapping later created at the same
       address. `publication_cursor` is never reset, so an in-flight writer
       also cannot collide with a reused slot's first publication. */
    _Atomic uint64_t mapping_generation;
    _Atomic uint64_t publication_cursor;
    /* Cursor value at mapping registration, used only to distinguish a
       current mapping's journal overflow from entries left by an older
       mapping that occupied the same fixed catalog slot. */
    _Atomic uint64_t publication_floor;
    /* A write transition does not revoke unrelated code publications: JITs
       commonly compile elsewhere in one large MAP_JIT mapping. It does bump
       this epoch so verification refuses if any write transition races its
       read of the current published bytes. */
    _Atomic uint64_t write_epoch;
    /* Generation consumed directly by the byte-preserving Tier-D shadow
       translator. Unlike `write_epoch`, this never resets to zero when a
       catalog slot is reused: mapping identity seeds it and every admitted
       write window advances it before bytes become writable. */
    _Atomic uint64_t shadow_generation;
    /* A shadow range keeps the guest-visible bytes readable but
       non-executable. EXC_BAD_ACCESS execute faults park into Rust/DSR rather
       than replying to the original PC, which is the fork-safe x18 route. */
    _Atomic bool shadow;
    /* Conservative whole-range dirtiness. MAP_JIT permissions are
       per-thread, so after one write-mode transition later stores may not
       fault; one observed write/execute transition therefore dirties the
       entire mapping. */
    _Atomic bool dirty;
};
struct carrick_native_direct_publication {
    /* Zero means an in-progress/uncommitted entry. A publisher clears this
       word before changing the payload and release-publishes the monotonically
       increasing sequence last; readers use it as a seqlock. */
    _Atomic uint64_t commit;
    _Atomic uint64_t mapping_generation;
    _Atomic uintptr_t start;
    _Atomic uintptr_t end;
};
struct carrick_native_direct_exception_route {
    /* Release-published last. Routes are append-only for this process; the
       mapping generation invalidates stale entries after unmap/address reuse. */
    _Atomic uint64_t commit;
    _Atomic uint64_t mapping_generation;
    _Atomic uintptr_t site;
    _Atomic uintptr_t entry;
    _Atomic uintptr_t return_pc;
    _Atomic uintptr_t resume_pc;
};
static struct carrick_native_direct_range
    carrick_native_direct_ranges[CARRICK_NATIVE_DIRECT_RANGE_CAPACITY];
static struct carrick_native_direct_publication
    carrick_native_direct_publications[CARRICK_NATIVE_DIRECT_RANGE_CAPACITY]
                                       [CARRICK_NATIVE_DIRECT_PUBLICATION_CAPACITY];
static struct carrick_native_direct_exception_route
    carrick_native_direct_exception_routes[
        CARRICK_NATIVE_DIRECT_EXCEPTION_ROUTE_CAPACITY];
static _Atomic uint64_t carrick_native_direct_exception_route_cursor;
static _Atomic uint64_t carrick_native_direct_next_mapping_generation = 1;
static pthread_mutex_t carrick_native_direct_exception_lock =
    PTHREAD_MUTEX_INITIALIZER;
static pthread_once_t carrick_native_direct_exception_once = PTHREAD_ONCE_INIT;
static const pthread_once_t carrick_native_direct_exception_once_initial =
    PTHREAD_ONCE_INIT;
static mach_port_t carrick_native_direct_exception_port_set = MACH_PORT_NULL;
static int carrick_native_direct_exception_init_error;
static bool carrick_native_direct_exception_atfork_installed;
static struct carrick_native_direct_exception_registration
    *carrick_native_direct_exception_registrations;
static _Thread_local struct carrick_native_direct_exception_registration
    *carrick_native_direct_exception_current;

/* libsystem's mach_msg_server allocates its request/reply buffers with
   vm_allocate(anywhere).  That is not an ownership boundary in Tier D: the
   Linux guest and Carrick's in-process exec teardown share this vm_map, and a
   stale guest-mapping owner can later munmap a reused VM allocation.  XNU has
   already dequeued and destroyed a request when copyout returns
   MACH_RCV_INVALID_DATA, permanently stranding the faulting thread.

   Keep both IPC buffers in Carrick's Mach-O data instead.  Guest VM teardown
   never owns these pages, the buffers survive in-process exec, and fork gives
   the child its own COW copy before its replacement server starts. */
#define CARRICK_NATIVE_DIRECT_EXCEPTION_MESSAGE_MAX                         \
    ((sizeof(union __RequestUnion__catch_mach_exc_subsystem) >              \
      sizeof(union __ReplyUnion__catch_mach_exc_subsystem))                 \
         ? sizeof(union __RequestUnion__catch_mach_exc_subsystem)           \
         : sizeof(union __ReplyUnion__catch_mach_exc_subsystem))

union carrick_native_direct_exception_message_buffer {
    max_align_t alignment;
    uint8_t bytes[CARRICK_NATIVE_DIRECT_EXCEPTION_MESSAGE_MAX +
                  sizeof(mach_msg_max_trailer_t)];
};

static union carrick_native_direct_exception_message_buffer
    carrick_native_direct_exception_request_buffer;
static union carrick_native_direct_exception_message_buffer
    carrick_native_direct_exception_reply_buffer;

extern int carrick_native_direct_dynamic_page_safe(const uint8_t *start,
                                                   size_t len);
extern void carrick_native_direct_exception_probe(uint32_t phase,
                                                  uint64_t a,
                                                  uint64_t b,
                                                  uint64_t c,
                                                  uint64_t d);
static void carrick_native_direct_exception_recover(void);
static void carrick_native_direct_exception_abort(void);
/* -1 = not probed, 0 = unavailable, 1 = XNU preserved physical x18. The
   exception server may only READ this cache: probing performs a syscall and
   is therefore forbidden while servicing another thread's exception. */
static _Atomic int carrick_native_direct_physical_x18_state = -1;
int carrick_native_direct_physical_x18_probe(void);

#define CARRICK_THREAD_STATE_NO_PTRAUTH UINT32_C(0x1)
#define CARRICK_THREAD_STATE_IB_SIGNED_LR UINT32_C(0x2)
#define CARRICK_THREAD_STATE_KERNEL_SIGNED_PC UINT32_C(0x4)
#define CARRICK_THREAD_STATE_KERNEL_SIGNED_LR UINT32_C(0x8)
#define CARRICK_THREAD_STATE_USER_DIVERSIFIER_MASK UINT32_C(0xff000000)

/* The arm64 SDK deliberately labels the final word `pad` unless the whole C
   translation unit adopts the arm64e calling ABI. XNU still sends the opaque
   PAC representation over Mach on PAC-capable hardware. Mirror that
   wire-compatible layout locally so signal ucontexts elsewhere in this file
   keep their ordinary raw-pointer SDK view. */
struct carrick_native_arm_thread_state64_pac {
    uint64_t x[29];
    void *fp;
    void *lr;
    void *sp;
    void *pc;
    uint32_t cpsr;
    uint32_t flags;
};

_Static_assert(
    sizeof(struct carrick_native_arm_thread_state64_pac) ==
        sizeof(arm_thread_state64_t),
    "opaque ARM_THREAD_STATE64 layout size");

static const struct carrick_native_arm_thread_state64_pac *
carrick_native_direct_pac_state_const(const arm_thread_state64_t *state) {
    return (const struct carrick_native_arm_thread_state64_pac *)(const void *)state;
}

static struct carrick_native_arm_thread_state64_pac *
carrick_native_direct_pac_state(arm_thread_state64_t *state) {
    return (struct carrick_native_arm_thread_state64_pac *)(void *)state;
}

static ptrauth_extra_data_t carrick_native_direct_state_discriminator(
    const arm_thread_state64_t *state,
    ptrauth_extra_data_t base) {
    const struct carrick_native_arm_thread_state64_pac *opaque =
        carrick_native_direct_pac_state_const(state);
    uintptr_t user_diversifier =
        opaque->flags & CARRICK_THREAD_STATE_USER_DIVERSIFIER_MASK;
    return user_diversifier == 0
               ? base
               : ptrauth_blend_discriminator(
                     (void *)user_diversifier,
                     base);
}

static uintptr_t carrick_native_direct_get_reply_pc(
    const arm_thread_state64_t *state) {
    const struct carrick_native_arm_thread_state64_pac *opaque =
        carrick_native_direct_pac_state_const(state);
    if (opaque->pc == 0 ||
        (opaque->flags & CARRICK_THREAD_STATE_NO_PTRAUTH)) {
        return (uintptr_t)opaque->pc;
    }
    ptrauth_extra_data_t discriminator = ptrauth_string_discriminator("pc");
    if (!(opaque->flags & CARRICK_THREAD_STATE_KERNEL_SIGNED_PC)) {
        discriminator = carrick_native_direct_state_discriminator(
            state, discriminator);
    }
    return (uintptr_t)ptrauth_auth_data(
        opaque->pc,
        ptrauth_key_process_independent_code,
        discriminator);
}

static uintptr_t carrick_native_direct_get_reply_lr(
    const arm_thread_state64_t *state) {
    const struct carrick_native_arm_thread_state64_pac *opaque =
        carrick_native_direct_pac_state_const(state);
    if (opaque->lr == 0 ||
        (opaque->flags &
         (CARRICK_THREAD_STATE_NO_PTRAUTH |
          CARRICK_THREAD_STATE_IB_SIGNED_LR))) {
        return (uintptr_t)opaque->lr;
    }
    ptrauth_extra_data_t discriminator = ptrauth_string_discriminator("lr");
    if (!(opaque->flags & CARRICK_THREAD_STATE_KERNEL_SIGNED_LR)) {
        discriminator = carrick_native_direct_state_discriminator(
            state, discriminator);
    }
    return (uintptr_t)ptrauth_auth_data(
        opaque->lr,
        ptrauth_key_process_independent_code,
        discriminator);
}

static uintptr_t carrick_native_direct_get_reply_data_pointer(
    const arm_thread_state64_t *state,
    void *pointer,
    ptrauth_extra_data_t discriminator) {
    if (pointer == 0 ||
        (carrick_native_direct_pac_state_const(state)->flags &
         CARRICK_THREAD_STATE_NO_PTRAUTH)) {
        return (uintptr_t)pointer;
    }
    return (uintptr_t)ptrauth_auth_data(
        pointer,
        ptrauth_key_process_independent_data,
        discriminator);
}

static void carrick_native_direct_set_reply_sp(
    arm_thread_state64_t *state,
    uintptr_t sp) {
    struct carrick_native_arm_thread_state64_pac *opaque =
        carrick_native_direct_pac_state(state);
    void *pointer = (void *)sp;
    opaque->sp =
        pointer != 0 &&
                !(opaque->flags & CARRICK_THREAD_STATE_NO_PTRAUTH)
            ? ptrauth_sign_unauthenticated(
                  pointer,
                  ptrauth_key_process_independent_data,
                  ptrauth_string_discriminator("sp"))
            : pointer;
}

/* ARM_THREAD_STATE64 delivered by PAC-capable XNU carries a kernel-signed PC
   plus a flag saying who signed it. Merely overwriting the opaque PC word
   while retaining KERNEL_SIGNED_PC makes machine_thread_state_convert_from_user
   reject/poison the reply (a debugger changes that policy and hid the bug).

   Carrick's route targets are trusted scalar addresses from its immutable
   catalogs. Sign the replacement with the process-independent code key and
   the exact `pc` discriminator used by XNU, then mark it user-signed. Enabling
   ptrauth intrinsics does not opt the C shim into the arm64e calling ABI. */
static void carrick_native_direct_set_reply_pc(
    arm_thread_state64_t *state,
    uintptr_t pc) {
#if __has_feature(ptrauth_intrinsics)
    struct carrick_native_arm_thread_state64_pac *opaque =
        carrick_native_direct_pac_state(state);
    ptrauth_extra_data_t discriminator =
        ptrauth_string_discriminator("pc");
    uintptr_t user_diversifier =
        opaque->flags & CARRICK_THREAD_STATE_USER_DIVERSIFIER_MASK;
    if (user_diversifier != 0) {
        discriminator = ptrauth_blend_discriminator(
            (void *)user_diversifier,
            discriminator);
    }
    opaque->pc = ptrauth_sign_unauthenticated(
        (void *)pc,
        ptrauth_key_process_independent_code,
        discriminator);
    opaque->flags &= ~CARRICK_THREAD_STATE_KERNEL_SIGNED_PC;
#else
    arm_thread_state64_set_pc_fptr(
        *state, (void (*)(void))(uintptr_t)pc);
#endif
}

static int carrick_native_direct_range_index(uintptr_t address) {
    for (size_t i = 0; i < CARRICK_NATIVE_DIRECT_RANGE_CAPACITY; i++) {
        uintptr_t start = atomic_load_explicit(
            &carrick_native_direct_ranges[i].start, memory_order_acquire);
        if (start == 0 || start == UINTPTR_MAX) {
            continue;
        }
        uintptr_t end = atomic_load_explicit(
            &carrick_native_direct_ranges[i].end, memory_order_relaxed);
        if (address >= start && address < end) {
            return (int)i;
        }
    }
    return -1;
}

static int carrick_native_direct_range_interval_index(
    uintptr_t start,
    uintptr_t end) {
    if (start == 0 || start >= end) {
        return -1;
    }
    for (size_t i = 0; i < CARRICK_NATIVE_DIRECT_RANGE_CAPACITY; i++) {
        uintptr_t current_start = atomic_load_explicit(
            &carrick_native_direct_ranges[i].start, memory_order_acquire);
        if (current_start == 0 || current_start == UINTPTR_MAX) {
            continue;
        }
        uintptr_t current_end = atomic_load_explicit(
            &carrick_native_direct_ranges[i].end, memory_order_relaxed);
        if (current_start <= start && end <= current_end) {
            return (int)i;
        }
    }
    return -1;
}

static bool carrick_native_direct_range_contains(uintptr_t address) {
    return carrick_native_direct_range_index(address) >= 0;
}

static int carrick_native_direct_range_begin_write(uintptr_t address) {
    int index = carrick_native_direct_range_index(address);
    if (index < 0) {
        return 0;
    }
    struct carrick_native_direct_range *range =
        &carrick_native_direct_ranges[index];
    /* Keep exact publication authority for unchanged code elsewhere in this
       large mapping, but make any verifier already reading bytes detect this
       new write epoch before it enables execution. */
    atomic_fetch_add_explicit(&range->write_epoch, 1, memory_order_acq_rel);
    atomic_fetch_add_explicit(
        &range->shadow_generation, 1, memory_order_acq_rel);
    atomic_store_explicit(&range->dirty, true, memory_order_release);
    if (atomic_load_explicit(&range->shadow, memory_order_acquire)) {
        uintptr_t start = atomic_load_explicit(
            &range->start, memory_order_acquire);
        uintptr_t end = atomic_load_explicit(
            &range->end, memory_order_relaxed);
        if (start == 0 || start == UINTPTR_MAX || start >= end ||
            mach_vm_protect(mach_task_self(), start, end - start, false,
                            VM_PROT_READ | VM_PROT_WRITE) != KERN_SUCCESS) {
            return 0;
        }
    }
    return 1;
}

static bool carrick_native_direct_range_is_shadow(uintptr_t address) {
    int index = carrick_native_direct_range_index(address);
    return index >= 0 && atomic_load_explicit(
                             &carrick_native_direct_ranges[index].shadow,
                             memory_order_acquire);
}

static int carrick_native_direct_range_finish_shadow_write(
    uintptr_t address) {
    int index = carrick_native_direct_range_index(address);
    if (index < 0) {
        return 0;
    }
    struct carrick_native_direct_range *range =
        &carrick_native_direct_ranges[index];
    if (!atomic_load_explicit(&range->shadow, memory_order_acquire)) {
        return 0;
    }
    uintptr_t start = atomic_load_explicit(
        &range->start, memory_order_acquire);
    uintptr_t end = atomic_load_explicit(
        &range->end, memory_order_relaxed);
    return start != 0 && start != UINTPTR_MAX && start < end &&
                   mach_vm_protect(mach_task_self(), start, end - start,
                                   false, VM_PROT_READ) == KERN_SUCCESS
               ? 1
               : 0;
}

int carrick_native_direct_register_exception_route(
    uintptr_t site,
    uintptr_t entry,
    uintptr_t return_pc,
    uintptr_t resume_pc) {
    int range_index = carrick_native_direct_range_index(site);
    if (range_index < 0 || entry == 0 || return_pc == 0 || resume_pc == 0) {
        errno = EINVAL;
        return 0;
    }
    uint64_t ticket = atomic_fetch_add_explicit(
        &carrick_native_direct_exception_route_cursor,
        1,
        memory_order_acq_rel);
    if (ticket >= CARRICK_NATIVE_DIRECT_EXCEPTION_ROUTE_CAPACITY) {
        errno = ENOSPC;
        return 0;
    }
    struct carrick_native_direct_exception_route *route =
        &carrick_native_direct_exception_routes[ticket];
    uint64_t generation = atomic_load_explicit(
        &carrick_native_direct_ranges[range_index].mapping_generation,
        memory_order_acquire);
    atomic_store_explicit(&route->commit, 0, memory_order_release);
    atomic_store_explicit(
        &route->mapping_generation, generation, memory_order_relaxed);
    atomic_store_explicit(&route->site, site, memory_order_relaxed);
    atomic_store_explicit(&route->entry, entry, memory_order_relaxed);
    atomic_store_explicit(&route->return_pc, return_pc, memory_order_relaxed);
    atomic_store_explicit(&route->resume_pc, resume_pc, memory_order_relaxed);
    atomic_store_explicit(&route->commit, ticket + 1, memory_order_release);
    return 1;
}

/* Resolve one of Carrick's private dynamic UDFs without any allocation,
   lock, or text dereference beyond the already-read instruction. Returns 1
   for site->veneer entry, 2 for veneer return->guest resume, 0 otherwise. */
static int carrick_native_direct_exception_route_lookup(
    uintptr_t pc,
    uint32_t instruction,
    uintptr_t *target) {
    const uint32_t entry_udf = 0x0000b452;  /* udf #0xb452 */
    const uint32_t return_udf = 0x0000b453; /* udf #0xb453 */
    if (target == 0 ||
        (instruction != entry_udf && instruction != return_udf)) {
        return 0;
    }
    uint64_t cursor = atomic_load_explicit(
        &carrick_native_direct_exception_route_cursor,
        memory_order_acquire);
    if (cursor > CARRICK_NATIVE_DIRECT_EXCEPTION_ROUTE_CAPACITY) {
        cursor = CARRICK_NATIVE_DIRECT_EXCEPTION_ROUTE_CAPACITY;
    }
    /* A JIT may republish the same code-cage address without replacing the
       mapping. Search newest-first so that site's current UDF reaches the
       veneer built from the newest instruction, never an older route whose
       mapping generation is still legitimately live. */
    for (uint64_t i = cursor; i != 0; i--) {
        struct carrick_native_direct_exception_route *route =
            &carrick_native_direct_exception_routes[i - 1];
        uint64_t first = atomic_load_explicit(
            &route->commit, memory_order_acquire);
        if (first == 0) {
            continue;
        }
        uint64_t generation = atomic_load_explicit(
            &route->mapping_generation, memory_order_relaxed);
        uintptr_t site = atomic_load_explicit(
            &route->site, memory_order_relaxed);
        uintptr_t entry = atomic_load_explicit(
            &route->entry, memory_order_relaxed);
        uintptr_t return_pc = atomic_load_explicit(
            &route->return_pc, memory_order_relaxed);
        uintptr_t resume_pc = atomic_load_explicit(
            &route->resume_pc, memory_order_relaxed);
        uint64_t second = atomic_load_explicit(
            &route->commit, memory_order_acquire);
        if (first != second) {
            continue;
        }
        int range_index = carrick_native_direct_range_index(site);
        if (range_index < 0 ||
            atomic_load_explicit(
                &carrick_native_direct_ranges[range_index].mapping_generation,
                memory_order_acquire) != generation) {
            continue;
        }
        if (instruction == entry_udf && pc == site) {
            *target = entry;
            return 1;
        }
        if (instruction == return_udf && pc == return_pc) {
            *target = resume_pc;
            return 2;
        }
    }
    return 0;
}

/* Return the newest exact cache-publication interval for the current mapping
   generation that contains `pc`. The fixed journal is deliberately an
   authority cache, not a best-effort hint: eviction can cause a named
   fail-closed result (-1), but no overwritten entry can authorize bytes. */
static int carrick_native_direct_publication_for_pc_internal(
    uintptr_t pc,
    uintptr_t *published_start,
    uintptr_t *published_end,
    uint64_t *published_sequence,
    uint64_t *mapping_generation,
    uint64_t *write_epoch) {
    int index = carrick_native_direct_range_index(pc);
    if (index < 0 || published_start == 0 || published_end == 0 ||
        published_sequence == 0 || mapping_generation == 0 ||
        write_epoch == 0) {
        return 0;
    }
    struct carrick_native_direct_range *range =
        &carrick_native_direct_ranges[index];
    uint64_t generation = atomic_load_explicit(
        &range->mapping_generation, memory_order_acquire);
    uint64_t epoch = atomic_load_explicit(
        &range->write_epoch, memory_order_acquire);
    uint64_t floor = atomic_load_explicit(
        &range->publication_floor, memory_order_acquire);
    uint64_t cursor = atomic_load_explicit(
        &range->publication_cursor, memory_order_acquire);
    uint64_t best_sequence = 0;
    uintptr_t best_start = 0;
    uintptr_t best_end = 0;

    for (size_t i = 0; i < CARRICK_NATIVE_DIRECT_PUBLICATION_CAPACITY; i++) {
        struct carrick_native_direct_publication *publication =
            &carrick_native_direct_publications[index][i];
        uint64_t first = atomic_load_explicit(
            &publication->commit, memory_order_acquire);
        if (first == 0 || first <= floor || first <= best_sequence) {
            continue;
        }
        uint64_t publication_generation = atomic_load_explicit(
            &publication->mapping_generation, memory_order_relaxed);
        uintptr_t start = atomic_load_explicit(
            &publication->start, memory_order_relaxed);
        uintptr_t end = atomic_load_explicit(
            &publication->end, memory_order_relaxed);
        uint64_t second = atomic_load_explicit(
            &publication->commit, memory_order_acquire);
        if (first != second || publication_generation != generation ||
            start > pc || pc >= end) {
            continue;
        }
        best_sequence = first;
        best_start = start;
        best_end = end;
    }

    /* Recheck the mapping identity and write epoch after the scan. A
       concurrent unmap/reuse or write transition can only revoke the
       candidate, never race it into acceptance. */
    uintptr_t current_start = atomic_load_explicit(
        &range->start, memory_order_acquire);
    uintptr_t current_end = atomic_load_explicit(
        &range->end, memory_order_relaxed);
    uint64_t current_generation = atomic_load_explicit(
        &range->mapping_generation, memory_order_acquire);
    uint64_t current_epoch = atomic_load_explicit(
        &range->write_epoch, memory_order_acquire);
    if (current_start == 0 || current_start == UINTPTR_MAX ||
        pc < current_start || pc >= current_end ||
        current_generation != generation || current_epoch != epoch) {
        return 0;
    }
    if (best_sequence == 0) {
        return cursor - floor > CARRICK_NATIVE_DIRECT_PUBLICATION_CAPACITY
                   ? -1
                   : 0;
    }
    *published_start = best_start;
    *published_end = best_end;
    *published_sequence = best_sequence;
    *mapping_generation = generation;
    *write_epoch = epoch;
    return 1;
}

static bool carrick_native_direct_publication_still_current_internal(
    uintptr_t pc,
    uintptr_t published_start,
    uintptr_t published_end,
    uint64_t published_sequence,
    uint64_t mapping_generation,
    uint64_t write_epoch,
    bool require_write_epoch) {
    int index = carrick_native_direct_range_index(pc);
    if (index < 0 || published_sequence == 0 ||
        published_start > pc || pc >= published_end) {
        return false;
    }
    struct carrick_native_direct_range *range =
        &carrick_native_direct_ranges[index];
    if (atomic_load_explicit(
            &range->mapping_generation, memory_order_acquire) !=
            mapping_generation ||
        (require_write_epoch &&
         atomic_load_explicit(
             &range->write_epoch, memory_order_acquire) != write_epoch)) {
        return false;
    }
    size_t slot = (size_t)((published_sequence - 1) %
                           CARRICK_NATIVE_DIRECT_PUBLICATION_CAPACITY);
    struct carrick_native_direct_publication *publication =
        &carrick_native_direct_publications[index][slot];
    uint64_t first = atomic_load_explicit(
        &publication->commit, memory_order_acquire);
    uint64_t generation = atomic_load_explicit(
        &publication->mapping_generation, memory_order_relaxed);
    uintptr_t start = atomic_load_explicit(
        &publication->start, memory_order_relaxed);
    uintptr_t end = atomic_load_explicit(
        &publication->end, memory_order_relaxed);
    uint64_t second = atomic_load_explicit(
        &publication->commit, memory_order_acquire);
    return first == published_sequence && second == published_sequence &&
           generation == mapping_generation && start == published_start &&
           end == published_end;
}

enum {
    CARRICK_NATIVE_DIRECT_RECOVERY_EXECUTE = 1,
    CARRICK_NATIVE_DIRECT_RECOVERY_WRITE = 2,
};

static struct carrick_native_direct_exception_registration *
carrick_native_direct_exception_find(mach_port_t exception_port) {
    struct carrick_native_direct_exception_registration *registration =
        carrick_native_direct_exception_registrations;
    while (registration != 0) {
        if (registration->exception_port == exception_port) {
            return registration;
        }
        registration = registration->next;
    }
    return 0;
}

static void carrick_native_direct_exception_park_failure(
    struct carrick_native_direct_exception_registration *registration) {
    struct carrick_native_direct_slots *slots = registration->slots;
    arm_thread_state64_t *state = &registration->original_state;
    for (size_t i = 0; i < 29; i++) {
        slots->context.x[i] = state->__x[i];
    }
    slots->context.x[18] =
        atomic_load_explicit(&carrick_native_direct_physical_x18_state,
                             memory_order_acquire) == 1
            ? state->__x[18]
            : slots->guest_x18;
    const struct carrick_native_arm_thread_state64_pac *opaque =
        carrick_native_direct_pac_state_const(state);
    slots->context.x[29] = carrick_native_direct_get_reply_data_pointer(
        state, opaque->fp, ptrauth_string_discriminator("fp"));
    slots->context.x[30] = carrick_native_direct_get_reply_lr(state);
    slots->context.sp = carrick_native_direct_get_reply_data_pointer(
        state, opaque->sp, ptrauth_string_discriminator("sp"));
    slots->context.pc = carrick_native_direct_get_reply_pc(state);
    slots->parked_fp.pstate = state->__cpsr;
    slots->parked_fp.fpsr = registration->fpsr;
    slots->parked_fp.fpcr = registration->fpcr;
    memcpy(slots->parked_fp.v,
           registration->vector,
           sizeof(registration->vector));
    slots->fault.signal = registration->fault_exception;
    slots->fault.code = (int32_t)registration->fault_code;
    slots->fault.address = registration->fault_address;
    slots->fault.esr = 0;
    slots->fault.far = registration->fault_address;
    slots->fault.pending = 1;
}

__attribute__((used, noinline))
static int carrick_native_direct_exception_service(
    struct carrick_native_direct_exception_registration *registration) {
    int status = 0;
    bool expected_shadow_park = false;
    registration->slots->exception_telemetry.recovery_services++;
    carrick_native_direct_exception_probe(
        5,
        (uint64_t)registration->recovery_kind,
        registration->fault_pc,
        registration->fault_address,
        (uintptr_t)registration);
    if (registration->recovery_kind ==
        CARRICK_NATIVE_DIRECT_RECOVERY_EXECUTE) {
        if (carrick_native_direct_range_is_shadow(
                registration->fault_pc)) {
            /* The source mapping is deliberately never executable. Close a
               preceding write window process-wide, then park the exact
               architectural state into Rust; the DSR gateway will execute a
               generation-guarded translation of these unchanged bytes. */
            status = carrick_native_direct_range_finish_shadow_write(
                         registration->fault_pc)
                         ? EAGAIN
                         : EIO;
            expected_shadow_park = status == EAGAIN;
        } else {
        uintptr_t published_start = 0;
        uintptr_t published_end = 0;
        uint64_t published_sequence = 0;
        uint64_t mapping_generation = 0;
        uint64_t write_epoch = 0;
        int publication = carrick_native_direct_publication_for_pc_internal(
            registration->fault_pc,
            &published_start,
            &published_end,
            &published_sequence,
            &mapping_generation,
            &write_epoch);
        if (publication < 0) {
            status = EOVERFLOW;
        } else if (publication == 0 ||
                   carrick_native_direct_dynamic_page_safe(
                       (const uint8_t *)published_start,
                       published_end - published_start) == 0) {
            status = EILSEQ;
        } else if (!carrick_native_direct_publication_still_current_internal(
                       registration->fault_pc,
                       published_start,
                       published_end,
                       published_sequence,
                       mapping_generation,
                       write_epoch,
                       true)) {
            status = EAGAIN;
        } else {
            sys_icache_invalidate(
                (void *)published_start, published_end - published_start);
            pthread_jit_write_protect_np(1);
            registration->slots->exception_telemetry.execute_switches++;
        }
        }
    } else if (registration->recovery_kind ==
               CARRICK_NATIVE_DIRECT_RECOVERY_WRITE) {
        if (carrick_native_direct_range_is_shadow(
                registration->fault_address)) {
            /* `range_begin_write` already made the plain shadow source RW.
               A direct reply would zero physical x18 before the faulting
               static guest store retries. Park the original exception state
               instead; Rust re-enters it through the full-register stub. */
            status = EAGAIN;
            expected_shadow_park = true;
        } else {
            pthread_jit_write_protect_np(0);
            registration->slots->exception_telemetry.write_switches++;
        }
    } else {
        status = EINVAL;
    }
    if (status != 0 && !expected_shadow_park) {
        registration->slots->exception_telemetry.failures++;
    }
    registration->slots->exception_telemetry.last_status = (uint64_t)status;
    carrick_native_direct_exception_probe(
        6,
        (uint64_t)status,
        (uint64_t)registration->recovery_kind,
        registration->fault_pc,
        registration->fault_address);
    registration->service_status = status;
    return status;
}

/* x0 is the registration pointer and SP is the entry gateway's parked host
   stack. Preserve the complete FP/SIMD file around the host service; the
   second Mach exception restores GPRs, PC, SP and PSTATE from the first
   exception's state, so this function needs no register-transparent branch. */
__attribute__((naked, noinline))
static void carrick_native_direct_exception_recover(void) {
    __asm__ volatile(
        "stp q0, q1, [x0, #0]\n"
        "stp q2, q3, [x0, #32]\n"
        "stp q4, q5, [x0, #64]\n"
        "stp q6, q7, [x0, #96]\n"
        "stp q8, q9, [x0, #128]\n"
        "stp q10, q11, [x0, #160]\n"
        "stp q12, q13, [x0, #192]\n"
        "stp q14, q15, [x0, #224]\n"
        "stp q16, q17, [x0, #256]\n"
        "stp q18, q19, [x0, #288]\n"
        "stp q20, q21, [x0, #320]\n"
        "stp q22, q23, [x0, #352]\n"
        "stp q24, q25, [x0, #384]\n"
        "stp q26, q27, [x0, #416]\n"
        "stp q28, q29, [x0, #448]\n"
        "stp q30, q31, [x0, #480]\n"
        "mrs x1, fpsr\n"
        "str x1, [x0, #512]\n"
        "mrs x1, fpcr\n"
        "str x1, [x0, #520]\n"
        "mov x19, x0\n"
        "bl _carrick_native_direct_exception_service\n"
        "mov x0, x19\n"
        "ldr x1, [x0, #512]\n"
        "msr fpsr, x1\n"
        "ldr x1, [x0, #520]\n"
        "msr fpcr, x1\n"
        "ldp q0, q1, [x0, #0]\n"
        "ldp q2, q3, [x0, #32]\n"
        "ldp q4, q5, [x0, #64]\n"
        "ldp q6, q7, [x0, #96]\n"
        "ldp q8, q9, [x0, #128]\n"
        "ldp q10, q11, [x0, #160]\n"
        "ldp q12, q13, [x0, #192]\n"
        "ldp q14, q15, [x0, #224]\n"
        "ldp q16, q17, [x0, #256]\n"
        "ldp q18, q19, [x0, #288]\n"
        "ldp q20, q21, [x0, #320]\n"
        "ldp q22, q23, [x0, #352]\n"
        "ldp q24, q25, [x0, #384]\n"
        "ldp q26, q27, [x0, #416]\n"
        "ldp q28, q29, [x0, #448]\n"
        "ldp q30, q31, [x0, #480]\n"
        "brk #0xc471\n"
        "brk #0\n");
}

/* Failure returns to the normal gateway landing label with the faulting guest
   state parked in DirectThreadSlots for a named Tier-D refusal. */
__attribute__((naked, noinline))
static void carrick_native_direct_exception_abort(void) {
    __asm__ volatile(
        "ldr x1, [x0, #272]\n"
        "mov sp, x1\n"
        "ldr x30, [x0, #280]\n"
        "ret\n");
}

__attribute__((visibility("hidden")))
int carrick_native_direct_is_recovery_breakpoint(uint32_t instruction,
                                                 int recovery_pending) {
    /* A64 `brk #imm16` is 0xd4200000 | (imm16 << 5). The recovery trampoline
       emits Carrick's private `brk #0xc471`; debugger and fasttrap BRKs must
       continue through the prior exception-port chain instead. */
    const uint32_t recovery_brk = 0xd4388e20;
    return recovery_pending != 0 && instruction == recovery_brk;
}

kern_return_t catch_mach_exception_raise_state(
    mach_port_t exception_port,
    exception_type_t exception,
    const mach_exception_data_t code,
    mach_msg_type_number_t code_count,
    int *flavor,
    const thread_state_t old_state,
    mach_msg_type_number_t old_state_count,
    thread_state_t new_state,
    mach_msg_type_number_t *new_state_count) {
    if (flavor == 0 || *flavor != ARM_THREAD_STATE64 ||
        old_state_count != ARM_THREAD_STATE64_COUNT ||
        new_state_count == 0) {
        return KERN_INVALID_ARGUMENT;
    }
    pthread_mutex_lock(&carrick_native_direct_exception_lock);
    struct carrick_native_direct_exception_registration *registration =
        carrick_native_direct_exception_find(exception_port);
    pthread_mutex_unlock(&carrick_native_direct_exception_lock);
    if (registration == 0) {
        carrick_native_direct_exception_probe(
            8,
            (uint64_t)exception,
            (uint64_t)exception_port,
            code_count,
            0);
        return KERN_FAILURE;
    }
    struct carrick_native_direct_exception_telemetry *telemetry =
        &registration->slots->exception_telemetry;
    telemetry->exception_entries++;
    telemetry->last_exception = (uint64_t)exception;
    const arm_thread_state64_t *state =
        (const arm_thread_state64_t *)(const void *)old_state;
    uintptr_t pc = carrick_native_direct_get_reply_pc(state);
    carrick_native_direct_exception_probe(
        3,
        (uint64_t)exception,
        code_count > 0 ? (uint64_t)code[0] : 0,
        pc,
        code_count > 1 ? (uint64_t)code[1] : 0);

    uint32_t exception_instruction = 0;
    if (exception == EXC_BREAKPOINT) {
        memcpy(&exception_instruction,
               (const void *)pc,
               sizeof(exception_instruction));
        carrick_native_direct_exception_probe(
            9,
            pc,
            exception_instruction,
            (uint64_t)registration->recovery_pending,
            (uint64_t)registration->service_status);
    } else if (exception == EXC_BAD_INSTRUCTION && code_count >= 2) {
        exception_instruction = (uint32_t)code[1];
    }

    if (exception == EXC_BREAKPOINT &&
        carrick_native_direct_is_recovery_breakpoint(
            exception_instruction, registration->recovery_pending)) {
        telemetry->breakpoint_entries++;
        carrick_native_direct_exception_probe(
            7,
            (uint64_t)registration->service_status,
            registration->fault_pc,
            registration->fault_address,
            (uintptr_t)registration);
        memcpy(new_state,
               &registration->original_state,
               sizeof(registration->original_state));
        *new_state_count = registration->original_state_count;
        if (registration->service_status != 0) {
            carrick_native_direct_exception_park_failure(registration);
            arm_thread_state64_t *state =
                (arm_thread_state64_t *)(void *)new_state;
            state->__x[0] = (uintptr_t)registration->slots;
            carrick_native_direct_set_reply_sp(
                state, registration->slots->context.host_sp);
            carrick_native_direct_set_reply_pc(
                state, (uintptr_t)carrick_native_direct_exception_abort);
        }
        registration->recovery_pending = 0;
        return KERN_SUCCESS;
    }

    uintptr_t dynamic_redirect = 0;
    int dynamic_route =
        (exception == EXC_BREAKPOINT || exception == EXC_BAD_INSTRUCTION)
                            ? carrick_native_direct_exception_route_lookup(
                                  pc,
                                  exception_instruction,
                                  &dynamic_redirect)
                            : 0;
    if (dynamic_route != 0) {
        if (exception == EXC_BREAKPOINT) {
            telemetry->breakpoint_entries++;
        } else {
            telemetry->bad_instruction_entries++;
        }
        memcpy(new_state, old_state, old_state_count * sizeof(natural_t));
        *new_state_count = old_state_count;
        arm_thread_state64_t *redirected_state =
            (arm_thread_state64_t *)(void *)new_state;
        carrick_native_direct_set_reply_pc(
            redirected_state, dynamic_redirect);
        carrick_native_direct_exception_probe(
            16,
            (uint64_t)dynamic_route,
            pc,
            dynamic_redirect,
            exception_instruction);
        return KERN_SUCCESS;
    }

    if (exception == EXC_BAD_INSTRUCTION) {
        telemetry->bad_instruction_entries++;
        if (code_count < 2) {
            telemetry->failures++;
            return KERN_FAILURE;
        }
        uint32_t instruction = (uint32_t)code[1];
        uint64_t value = 0;
        if (carrick_native_direct_emulate_sysreg(instruction, &value) == 0) {
            telemetry->failures++;
            return KERN_FAILURE;
        }

        memcpy(new_state, old_state, old_state_count * sizeof(natural_t));
        *new_state_count = old_state_count;
        arm_thread_state64_t *emulated_state =
            (arm_thread_state64_t *)(void *)new_state;
        uint32_t destination = instruction & 0x1f;
        if (destination != 31) {
            /* ARM_THREAD_STATE64's first 31 u64 words are x0..x30 in both
               opaque and non-opaque SDK layouts. Write the architectural GPR
               image directly: CTR/DCZID values are integers, not pointers to
               be pointer-authenticated by the fp/lr accessors. */
            ((uint64_t *)(void *)emulated_state)[destination] = value;
        }
        carrick_native_direct_set_reply_pc(
            emulated_state, pc + sizeof(uint32_t));
        telemetry->sysreg_emulations++;
        carrick_native_direct_exception_probe(
            10, pc, instruction, value, destination);
        return KERN_SUCCESS;
    }

    if (exception != EXC_BAD_ACCESS || code_count < 2 ||
        code[0] != KERN_PROTECTION_FAILURE) {
        telemetry->failures++;
        return KERN_FAILURE;
    }
    telemetry->bad_access_entries++;
    uintptr_t address = (uintptr_t)code[1];
    int recovery_kind = 0;
    if (carrick_native_direct_range_contains(pc)) {
        recovery_kind = CARRICK_NATIVE_DIRECT_RECOVERY_EXECUTE;
    } else if (carrick_native_direct_range_contains(address)) {
        recovery_kind = CARRICK_NATIVE_DIRECT_RECOVERY_WRITE;
        if (carrick_native_direct_range_begin_write(address) == 0) {
            telemetry->failures++;
            return KERN_FAILURE;
        }
    } else {
        telemetry->failures++;
        return KERN_FAILURE;
    }

    memcpy(&registration->original_state, state, sizeof(*state));
    registration->original_state_count = old_state_count;
    registration->fault_pc = pc;
    registration->fault_address = address;
    registration->fault_code = code[0];
    registration->fault_exception = exception;
    registration->recovery_kind = recovery_kind;
    registration->service_status = 0;
    registration->recovery_pending = 1;

    memcpy(new_state, old_state, old_state_count * sizeof(natural_t));
    *new_state_count = old_state_count;
    arm_thread_state64_t *recovery_state =
        (arm_thread_state64_t *)(void *)new_state;
    recovery_state->__x[0] = (uintptr_t)registration;
    carrick_native_direct_set_reply_sp(
        recovery_state, registration->slots->context.host_sp);
    carrick_native_direct_set_reply_pc(
        recovery_state, (uintptr_t)carrick_native_direct_exception_recover);
    return KERN_SUCCESS;
}

kern_return_t catch_mach_exception_raise(
    mach_port_t exception_port,
    mach_port_t thread,
    mach_port_t task,
    exception_type_t exception,
    mach_exception_data_t code,
    mach_msg_type_number_t code_count) {
    (void)exception_port;
    (void)thread;
    (void)task;
    (void)exception;
    (void)code;
    (void)code_count;
    return KERN_FAILURE;
}

kern_return_t catch_mach_exception_raise_state_identity(
    mach_port_t exception_port,
    mach_port_t thread,
    mach_port_t task,
    exception_type_t exception,
    mach_exception_data_t code,
    mach_msg_type_number_t code_count,
    int *flavor,
    thread_state_t old_state,
    mach_msg_type_number_t old_state_count,
    thread_state_t new_state,
    mach_msg_type_number_t *new_state_count) {
    (void)exception_port;
    (void)thread;
    (void)task;
    (void)exception;
    (void)code;
    (void)code_count;
    (void)flavor;
    (void)old_state;
    (void)old_state_count;
    (void)new_state;
    (void)new_state_count;
    return KERN_FAILURE;
}

__attribute__((visibility("hidden")))
mach_msg_size_t carrick_native_direct_exception_server_limit(void);

__attribute__((visibility("hidden")))
mach_msg_size_t carrick_native_direct_exception_subsystem_max(void);

__attribute__((visibility("hidden")))
mach_msg_size_t carrick_native_direct_exception_request_max(void);

static void *carrick_native_direct_exception_server(void *opaque) {
    (void)opaque;
    mach_msg_header_t *request =
        (mach_msg_header_t *)(void *)
            carrick_native_direct_exception_request_buffer.bytes;
    mach_msg_header_t *reply =
        (mach_msg_header_t *)(void *)
            carrick_native_direct_exception_reply_buffer.bytes;

    for (;;) {
        mach_msg_return_t mr = mach_msg(
            request,
            MACH_RCV_MSG | MACH_RCV_LARGE,
            0,
            (mach_msg_size_t)sizeof(
                carrick_native_direct_exception_request_buffer.bytes),
            carrick_native_direct_exception_port_set,
            MACH_MSG_TIMEOUT_NONE,
            MACH_PORT_NULL);
        if (mr != MACH_MSG_SUCCESS) {
            /* MACH_RCV_INVALID_DATA is not retryable: XNU consumed the
               exception request before reporting the failed copyout.  A
               too-large result with MACH_RCV_LARGE remains queued, but the
               generated MIG request union is already the maximum legal
               request.  Both cases are internal invariant failures; exit
               loudly instead of leaving a guest thread suspended forever. */
            carrick_native_direct_exception_probe(
                14,
                (uint64_t)mr,
                0,
                (uint64_t)carrick_native_direct_exception_port_set,
                0);
            carrick_native_direct_exception_init_error = mr;
            _exit(125);
        }

        memset(reply, 0, CARRICK_NATIVE_DIRECT_EXCEPTION_MESSAGE_MAX);
        (void)mach_exc_server(request, reply);

        mig_reply_error_t *reply_error = (mig_reply_error_t *)(void *)reply;
        kern_return_t service_status =
            (reply->msgh_bits & MACH_MSGH_BITS_COMPLEX)
                ? KERN_SUCCESS
                : reply_error->RetCode;
        if (service_status == MIG_NO_REPLY) {
            reply->msgh_remote_port = MACH_PORT_NULL;
        } else if (service_status != KERN_SUCCESS) {
            /* MIG transferred the reply right into `reply`; destroy the
               request's remaining descriptors without consuming that right. */
            request->msgh_remote_port = MACH_PORT_NULL;
            mach_msg_destroy(request);
        }

        if (reply->msgh_remote_port == MACH_PORT_NULL) {
            continue;
        }

        mr = mach_msg(
            reply,
            MACH_SEND_MSG,
            reply->msgh_size,
            0,
            MACH_PORT_NULL,
            MACH_MSG_TIMEOUT_NONE,
            MACH_PORT_NULL);
        if (mr == MACH_MSG_SUCCESS) {
            continue;
        }

        /* An exception reply carries a send-once right, so it cannot block.
           A dead destination merely means the faulting thread/process went
           away; consume any unsent rights and keep serving live ports. */
        if (mr == MACH_SEND_INVALID_DEST || mr == MACH_SEND_INTERRUPTED ||
            mr == MACH_SEND_TIMED_OUT) {
            mach_msg_destroy(reply);
            continue;
        }

        carrick_native_direct_exception_probe(
            14,
            (uint64_t)mr,
            0,
            (uint64_t)carrick_native_direct_exception_port_set,
            0);
        carrick_native_direct_exception_init_error = mr;
        _exit(125);
    }
}

/* Kept as hidden link-visible functions so the Rust unit gate can compare
   the receive limit actually passed to libsystem with MIG's generated
   subsystem contract. */
__attribute__((visibility("hidden")))
mach_msg_size_t carrick_native_direct_exception_server_limit(void) {
    mach_msg_size_t request_max = (mach_msg_size_t)sizeof(
        union __RequestUnion__catch_mach_exc_subsystem);
    return request_max > catch_mach_exc_subsystem.maxsize
               ? request_max
               : catch_mach_exc_subsystem.maxsize;
}

__attribute__((visibility("hidden")))
mach_msg_size_t carrick_native_direct_exception_subsystem_max(void) {
    return catch_mach_exc_subsystem.maxsize;
}

__attribute__((visibility("hidden")))
mach_msg_size_t carrick_native_direct_exception_request_max(void) {
    return (mach_msg_size_t)sizeof(
        union __RequestUnion__catch_mach_exc_subsystem);
}

static void carrick_native_direct_exception_atfork_prepare(void) {
    pthread_mutex_lock(&carrick_native_direct_exception_lock);
}

static void carrick_native_direct_exception_atfork_parent(void) {
    pthread_mutex_unlock(&carrick_native_direct_exception_lock);
}

static void carrick_native_direct_exception_atfork_child(void) {
    carrick_native_direct_exception_port_set = MACH_PORT_NULL;
    carrick_native_direct_exception_registrations = 0;
    carrick_native_direct_exception_init_error = 0;
    memcpy(&carrick_native_direct_exception_once,
           &carrick_native_direct_exception_once_initial,
           sizeof(carrick_native_direct_exception_once));
    pthread_mutex_unlock(&carrick_native_direct_exception_lock);
}

static void carrick_native_direct_exception_initialize(void) {
    if (!carrick_native_direct_exception_atfork_installed) {
        int atfork_rc = pthread_atfork(
            carrick_native_direct_exception_atfork_prepare,
            carrick_native_direct_exception_atfork_parent,
            carrick_native_direct_exception_atfork_child);
        if (atfork_rc != 0) {
            carrick_native_direct_exception_init_error = atfork_rc;
            return;
        }
        carrick_native_direct_exception_atfork_installed = true;
    }
    kern_return_t kr = mach_port_allocate(
        mach_task_self(),
        MACH_PORT_RIGHT_PORT_SET,
        &carrick_native_direct_exception_port_set);
    if (kr != KERN_SUCCESS) {
        carrick_native_direct_exception_init_error = kr;
        return;
    }
    pthread_t thread;
    int rc = pthread_create(
        &thread, 0, carrick_native_direct_exception_server, 0);
    if (rc != 0) {
        carrick_native_direct_exception_init_error = rc;
        return;
    }
    pthread_detach(thread);
}

static void carrick_native_direct_exception_dispose_port(mach_port_t port) {
    if (port == MACH_PORT_NULL) {
        return;
    }
    mach_port_mod_refs(
        mach_task_self(), port, MACH_PORT_RIGHT_SEND, -1);
    mach_port_mod_refs(
        mach_task_self(), port, MACH_PORT_RIGHT_RECEIVE, -1);
}

void *carrick_native_direct_exception_install(void *opaque_slots) {
    struct carrick_native_direct_slots *slots = opaque_slots;
    if (slots == 0) {
        errno = EINVAL;
        return 0;
    }
    if (carrick_native_direct_exception_current != 0) {
        if (carrick_native_direct_exception_current->slots == slots) {
            return carrick_native_direct_exception_current;
        }
        errno = EINVAL;
        return 0;
    }
    pthread_once(
        &carrick_native_direct_exception_once,
        carrick_native_direct_exception_initialize);
    if (carrick_native_direct_exception_init_error != 0 ||
        carrick_native_direct_exception_port_set == MACH_PORT_NULL) {
        errno = EIO;
        return 0;
    }

    struct carrick_native_direct_exception_registration *registration =
        calloc(1, sizeof(*registration));
    if (registration == 0) {
        return 0;
    }
    registration->slots = slots;
    registration->thread_port = mach_thread_self();
    kern_return_t kr = mach_port_allocate(
        mach_task_self(),
        MACH_PORT_RIGHT_RECEIVE,
        &registration->exception_port);
    if (kr == KERN_SUCCESS) {
        kr = mach_port_insert_right(
            mach_task_self(),
            registration->exception_port,
            registration->exception_port,
            MACH_MSG_TYPE_MAKE_SEND);
    }
    if (kr == KERN_SUCCESS) {
        kr = mach_port_move_member(
            mach_task_self(),
            registration->exception_port,
            carrick_native_direct_exception_port_set);
    }
    if (kr != KERN_SUCCESS) {
        if (registration->exception_port != MACH_PORT_NULL) {
            carrick_native_direct_exception_dispose_port(
                registration->exception_port);
        }
        mach_port_deallocate(mach_task_self(), registration->thread_port);
        free(registration);
        errno = EIO;
        return 0;
    }

    pthread_mutex_lock(&carrick_native_direct_exception_lock);
    registration->next = carrick_native_direct_exception_registrations;
    carrick_native_direct_exception_registrations = registration;
    pthread_mutex_unlock(&carrick_native_direct_exception_lock);

    registration->old_count = EXC_TYPES_COUNT;
    exception_mask_t mask = CARRICK_NATIVE_DIRECT_EXCEPTION_MASK;
    kr = thread_swap_exception_ports(
        registration->thread_port,
        mask,
        registration->exception_port,
        EXCEPTION_STATE | MACH_EXCEPTION_CODES,
        ARM_THREAD_STATE64,
        registration->old_masks,
        &registration->old_count,
        registration->old_handlers,
        registration->old_behaviors,
        registration->old_flavors);
    if (kr != KERN_SUCCESS) {
        pthread_mutex_lock(&carrick_native_direct_exception_lock);
        carrick_native_direct_exception_registrations = registration->next;
        pthread_mutex_unlock(&carrick_native_direct_exception_lock);
        mach_port_move_member(
            mach_task_self(), registration->exception_port, MACH_PORT_NULL);
        carrick_native_direct_exception_dispose_port(
            registration->exception_port);
        mach_port_deallocate(mach_task_self(), registration->thread_port);
        free(registration);
        errno = EIO;
        return 0;
    }
    carrick_native_direct_exception_current = registration;
    slots->exception_telemetry.installs++;
    carrick_native_direct_exception_probe(
        1,
        (uintptr_t)slots,
        (uintptr_t)registration,
        (uint64_t)registration->exception_port,
        (uint64_t)carrick_native_direct_exception_port_set);
    return registration;
}

void carrick_native_direct_exception_uninstall_current(void) {
    struct carrick_native_direct_exception_registration *registration =
        carrick_native_direct_exception_current;
    if (registration == 0) {
        return;
    }
    /* Install normally precedes libdtrace's attachment to a freshly exec'd
       guest.  Publish the accumulated counters while the registration and
       slots are still authoritative so a normal process exit leaves a late,
       bounded proof that the channel existed and whether it carried faults. */
    const struct carrick_native_direct_exception_telemetry *telemetry =
        &registration->slots->exception_telemetry;
    carrick_native_direct_exception_probe(
        11,
        telemetry->installs,
        telemetry->fork_rebinds,
        telemetry->exception_entries,
        telemetry->recovery_services);
    carrick_native_direct_exception_probe(
        12,
        telemetry->bad_access_entries,
        telemetry->breakpoint_entries,
        telemetry->bad_instruction_entries,
        telemetry->sysreg_emulations);
    carrick_native_direct_exception_probe(
        13,
        telemetry->execute_switches,
        telemetry->write_switches,
        telemetry->failures,
        telemetry->last_status);
    exception_mask_t mask = CARRICK_NATIVE_DIRECT_EXCEPTION_MASK;
    thread_set_exception_ports(
        registration->thread_port,
        mask,
        MACH_PORT_NULL,
        EXCEPTION_DEFAULT,
        THREAD_STATE_NONE);
    for (mach_msg_type_number_t i = 0; i < registration->old_count; i++) {
        thread_set_exception_ports(
            registration->thread_port,
            registration->old_masks[i],
            registration->old_handlers[i],
            registration->old_behaviors[i],
            registration->old_flavors[i]);
        if (registration->old_handlers[i] != MACH_PORT_NULL) {
            mach_port_deallocate(
                mach_task_self(), registration->old_handlers[i]);
        }
    }

    pthread_mutex_lock(&carrick_native_direct_exception_lock);
    struct carrick_native_direct_exception_registration **cursor =
        &carrick_native_direct_exception_registrations;
    while (*cursor != 0 && *cursor != registration) {
        cursor = &(*cursor)->next;
    }
    if (*cursor == registration) {
        *cursor = registration->next;
    }
    pthread_mutex_unlock(&carrick_native_direct_exception_lock);

    mach_port_move_member(
        mach_task_self(), registration->exception_port, MACH_PORT_NULL);
    carrick_native_direct_exception_dispose_port(
        registration->exception_port);
    mach_port_deallocate(mach_task_self(), registration->thread_port);
    carrick_native_direct_exception_current = 0;
    free(registration);
}

int carrick_native_direct_exception_after_fork_child(void) {
    struct carrick_native_direct_exception_registration *inherited =
        carrick_native_direct_exception_current;
    if (inherited == 0) {
        return 0;
    }
    if (inherited->slots == 0) {
        errno = EINVAL;
        return -1;
    }
    struct carrick_native_direct_slots *slots = inherited->slots;
    slots->exception_telemetry.fork_rebinds++;
    carrick_native_direct_exception_probe(
        2,
        (uintptr_t)slots,
        slots->exception_telemetry.fork_rebinds,
        (uintptr_t)inherited,
        (uint64_t)carrick_native_direct_exception_port_set);
    carrick_native_direct_exception_current = 0;
    free(inherited);

    mach_port_t thread = mach_thread_self();
    thread_set_exception_ports(
        thread,
        CARRICK_NATIVE_DIRECT_EXCEPTION_MASK,
        MACH_PORT_NULL,
        EXCEPTION_DEFAULT,
        THREAD_STATE_NONE);
    mach_port_deallocate(mach_task_self(), thread);
    return carrick_native_direct_exception_install(slots) == 0 ? -1 : 0;
}

static _Thread_local bool carrick_native_dsr_test_phase_zero_host_kick;
static _Thread_local volatile sig_atomic_t carrick_native_dsr_deferred_kick;
static _Thread_local bool carrick_native_dsr_kick_unblocked;

extern void carrick_dsr_exit_signal(void);
extern unsigned char carrick_dsr_exit_common_start[];
extern unsigned char carrick_dsr_exit_common_end[];

typedef void (*carrick_native_update_tpidr_fn)(uint64_t, uint64_t);
_Static_assert(sizeof(carrick_native_update_tpidr_fn) == sizeof(uint64_t),
               "native Darwin updater pointer must fit x1");

static carrick_native_update_tpidr_fn carrick_native_update_tpidr;
static uint64_t carrick_native_update_tpidr_address;
static pthread_once_t carrick_native_update_tpidr_once = PTHREAD_ONCE_INIT;
static int carrick_native_update_tpidr_errno;

static int carrick_native_unblock_kick_signal(void);
static int carrick_native_block_kick_signal(void);

#define CARRICK_NATIVE_CUSTOM_X18_BIT UINT64_C(0x0001000000000000)
#define CARRICK_NATIVE_TPIDR_BASE_MASK UINT64_C(0xfffffffffff00000)
#define CARRICK_NATIVE_EVENT_SIGNAL 1
#define CARRICK_NATIVE_EVENT_KICK 2

static uint64_t carrick_native_read_tpidr_el0(void) {
    uint64_t value;
    __asm__ volatile("mrs %0, TPIDR_EL0" : "=r"(value));
    return value;
}

// The public setter aborts on a same-state call. Signal entry can race that
// strict check, so use its exported idempotent TPIDR update hook directly.
static void carrick_native_init_custom_x18_once(void) {
    void *set_symbol = dlsym(RTLD_DEFAULT, "os_set_custom_x18_abi_enabled");
    void *get_symbol = dlsym(RTLD_DEFAULT, "os_custom_x18_abi_enabled");
    void *update_symbol = dlsym(RTLD_DEFAULT, "update_tpidr");
    if (set_symbol == 0 || get_symbol == 0 || update_symbol == 0) {
        carrick_native_update_tpidr_errno = ENOTSUP;
        return;
    }
    memcpy(&carrick_native_update_tpidr, update_symbol,
           sizeof(carrick_native_update_tpidr));
    if (carrick_native_update_tpidr == 0) {
        carrick_native_update_tpidr_errno = ENOTSUP;
        return;
    }
    memcpy(&carrick_native_update_tpidr_address,
           &carrick_native_update_tpidr,
           sizeof(carrick_native_update_tpidr_address));
}

static int carrick_native_init_custom_x18(void) {
    int rc = pthread_once(&carrick_native_update_tpidr_once,
                          carrick_native_init_custom_x18_once);
    if (rc != 0) {
        errno = rc;
        return -1;
    }
    if (carrick_native_update_tpidr_errno != 0 ||
        carrick_native_update_tpidr == 0) {
        errno = carrick_native_update_tpidr_errno != 0
                    ? carrick_native_update_tpidr_errno
                    : ENOTSUP;
        return -1;
    }
    return 0;
}

static void carrick_native_set_custom_x18(bool custom) {
    uint64_t encoded =
        carrick_native_read_tpidr_el0() & CARRICK_NATIVE_TPIDR_BASE_MASK;
    encoded &= ~CARRICK_NATIVE_CUSTOM_X18_BIT;
    if (custom) {
        encoded |= CARRICK_NATIVE_CUSTOM_X18_BIT;
    }
    carrick_native_update_tpidr(encoded, carrick_native_update_tpidr_address);
}

static void carrick_native_enter_host_x18_abi(void) {
    if (carrick_native_update_tpidr != 0) {
        carrick_native_set_custom_x18(false);
    }
}

static int carrick_native_enter_guest_x18_abi(void) {
    if (carrick_native_init_custom_x18() != 0) {
        return -1;
    }
    carrick_native_set_custom_x18(true);
    return 0;
}

int carrick_native_dsr_enter_guest_abi(void *context) {
    carrick_native_active_dsr_context = context;
    if (carrick_native_dsr_deferred_kick) {
        struct carrick_native_dsr_signal_context *deferred = context;
        carrick_native_dsr_deferred_kick = 0;
        deferred->exit_target = deferred->snapshot.pc;
        deferred->exit_source = 0;
        deferred->exit_status = 8;
        carrick_native_active_dsr_context = 0;
        return 1;
    }
    if (carrick_native_enter_guest_x18_abi() != 0) {
        carrick_native_active_dsr_context = 0;
        return -1;
    }
    if (carrick_native_dsr_test_phase_zero_host_kick) {
        carrick_native_dsr_test_phase_zero_host_kick = false;
        ((struct carrick_native_dsr_signal_context *)context)->entry_in_progress = 0;
        if (raise(SIGPIPE) != 0) {
            return -1;
        }
    }
    if (!carrick_native_dsr_kick_unblocked &&
        carrick_native_unblock_kick_signal() != 0) {
        carrick_native_active_dsr_context = 0;
        carrick_native_enter_host_x18_abi();
        return -1;
    }
    carrick_native_dsr_kick_unblocked = true;
    return 0;
}

void carrick_native_dsr_test_phase_zero_host_kick_once(void) {
    carrick_native_dsr_test_phase_zero_host_kick = true;
}

void carrick_native_dsr_enter_host_abi(void) {
    // Keep the kick transport deliverable in host code. Host-window kicks are
    // deferred by the signal handler and consumed at the next gateway entry;
    // blocking here made two pthread_sigmask transitions the dominant gateway
    // cost.
    carrick_native_enter_host_x18_abi();
    carrick_native_active_dsr_context = 0;
}

int carrick_native_direct_register_range(uintptr_t start, uintptr_t end) {
    if (start == 0 || start >= end) {
        errno = EINVAL;
        return -1;
    }
    for (size_t i = 0; i < CARRICK_NATIVE_DIRECT_RANGE_CAPACITY; i++) {
        uintptr_t empty = 0;
        if (atomic_compare_exchange_strong_explicit(
                &carrick_native_direct_ranges[i].start,
                &empty,
                UINTPTR_MAX,
                memory_order_acq_rel,
                memory_order_acquire)) {
            uint64_t generation = atomic_fetch_add_explicit(
                &carrick_native_direct_next_mapping_generation,
                1,
                memory_order_relaxed);
            if (generation == 0) {
                generation = atomic_fetch_add_explicit(
                    &carrick_native_direct_next_mapping_generation,
                    1,
                    memory_order_relaxed);
            }
            uint64_t cursor = atomic_load_explicit(
                &carrick_native_direct_ranges[i].publication_cursor,
                memory_order_relaxed);
            atomic_store_explicit(
                &carrick_native_direct_ranges[i].end,
                end,
                memory_order_relaxed);
            atomic_store_explicit(
                &carrick_native_direct_ranges[i].mapping_generation,
                generation,
                memory_order_relaxed);
            atomic_store_explicit(
                &carrick_native_direct_ranges[i].publication_floor,
                cursor,
                memory_order_relaxed);
            atomic_store_explicit(
                &carrick_native_direct_ranges[i].write_epoch,
                0,
                memory_order_relaxed);
            atomic_store_explicit(
                &carrick_native_direct_ranges[i].shadow_generation,
                generation,
                memory_order_relaxed);
            atomic_store_explicit(
                &carrick_native_direct_ranges[i].shadow,
                false,
                memory_order_relaxed);
            atomic_store_explicit(
                &carrick_native_direct_ranges[i].dirty,
                false,
                memory_order_relaxed);
            atomic_store_explicit(
                &carrick_native_direct_ranges[i].start,
                start,
                memory_order_release);
            return 0;
        }
    }
    errno = ENOSPC;
    return -1;
}

void carrick_native_direct_forget_range(uintptr_t start, uintptr_t end) {
    for (size_t i = 0; i < CARRICK_NATIVE_DIRECT_RANGE_CAPACITY; i++) {
        uintptr_t current_start = atomic_load_explicit(
            &carrick_native_direct_ranges[i].start, memory_order_acquire);
        uintptr_t current_end = atomic_load_explicit(
            &carrick_native_direct_ranges[i].end, memory_order_relaxed);
        if (current_start != 0 && current_start != UINTPTR_MAX &&
            current_end > start && end > current_start) {
            if (!atomic_compare_exchange_strong_explicit(
                    &carrick_native_direct_ranges[i].start,
                    &current_start,
                    UINTPTR_MAX,
                    memory_order_acq_rel,
                    memory_order_acquire)) {
                continue;
            }
            uint64_t invalid_generation = atomic_fetch_add_explicit(
                &carrick_native_direct_next_mapping_generation,
                1,
                memory_order_relaxed);
            atomic_store_explicit(
                &carrick_native_direct_ranges[i].mapping_generation,
                invalid_generation,
                memory_order_release);
            atomic_store_explicit(
                &carrick_native_direct_ranges[i].publication_floor,
                atomic_load_explicit(
                    &carrick_native_direct_ranges[i].publication_cursor,
                    memory_order_acquire),
                memory_order_release);
            atomic_fetch_add_explicit(
                &carrick_native_direct_ranges[i].write_epoch,
                1,
                memory_order_acq_rel);
            atomic_fetch_add_explicit(
                &carrick_native_direct_ranges[i].shadow_generation,
                1,
                memory_order_acq_rel);
            atomic_store_explicit(
                &carrick_native_direct_ranges[i].shadow,
                false,
                memory_order_release);
            atomic_store_explicit(
                &carrick_native_direct_ranges[i].end,
                0,
                memory_order_relaxed);
            atomic_store_explicit(
                &carrick_native_direct_ranges[i].start,
                0,
                memory_order_release);
        }
    }
}

int carrick_native_direct_range_is_pristine(uintptr_t start, uintptr_t end) {
    if (start == 0 || start >= end) {
        return 0;
    }
    for (size_t i = 0; i < CARRICK_NATIVE_DIRECT_RANGE_CAPACITY; i++) {
        uintptr_t current_start = atomic_load_explicit(
            &carrick_native_direct_ranges[i].start, memory_order_acquire);
        if (current_start == 0 || current_start == UINTPTR_MAX) {
            continue;
        }
        uintptr_t current_end = atomic_load_explicit(
            &carrick_native_direct_ranges[i].end, memory_order_relaxed);
        if (current_start <= start && end <= current_end) {
            return atomic_load_explicit(
                       &carrick_native_direct_ranges[i].dirty,
                       memory_order_acquire)
                       ? 0
                       : 1;
        }
    }
    return 0;
}

/* Darwin refuses mach_vm_protect/mprotect on the original MAP_JIT mapping,
   even when the requested protection is strictly weaker.  A MAP_JIT backing
   can, however, mint a Mach memory entry whose aliases accept ordinary
   protections.  The fork child uses that property to keep V8's source bytes
   at their exact Linux address while removing execute permission there; DSR
   executes a translated copy elsewhere.

   The caller must have fork-child/exclusive authority over the range.  This
   routine deliberately leaves a failed child unable to resume if the final
   fixed map fails after deallocation: silently falling back to direct MAP_JIT
   execution would reintroduce the physical-x18 corruption this transition is
   meant to prevent. */
static kern_return_t carrick_native_direct_remap_map_jit_shadow(
    uintptr_t start,
    uintptr_t end) {
    mach_vm_size_t len = (mach_vm_size_t)(end - start);
    memory_object_size_t entry_len = (memory_object_size_t)len;
    mach_port_t entry = MACH_PORT_NULL;
    kern_return_t kr = mach_make_memory_entry_64(
        mach_task_self(),
        &entry_len,
        (memory_object_offset_t)start,
        VM_PROT_READ | VM_PROT_WRITE | VM_PROT_EXECUTE,
        &entry,
        MACH_PORT_NULL);
    if (kr != KERN_SUCCESS) {
        if (entry != MACH_PORT_NULL) {
            mach_port_deallocate(mach_task_self(), entry);
        }
        return kr;
    }
    if (entry_len != (memory_object_size_t)len) {
        mach_port_deallocate(mach_task_self(), entry);
        return KERN_INVALID_ARGUMENT;
    }

    /* Prove the entry maps before removing the only mapping at the guest
       address.  Keep this alias alive across the fixed replacement so the VM
       object has an independent live reference throughout the transition. */
    mach_vm_address_t probe = 0;
    kr = mach_vm_map(
        mach_task_self(),
        &probe,
        len,
        0,
        VM_FLAGS_ANYWHERE,
        entry,
        0,
        false,
        VM_PROT_READ,
        VM_PROT_READ | VM_PROT_WRITE,
        VM_INHERIT_COPY);
    if (kr != KERN_SUCCESS) {
        mach_port_deallocate(mach_task_self(), entry);
        return kr;
    }

    kr = mach_vm_deallocate(mach_task_self(), start, len);
    if (kr == KERN_SUCCESS) {
        mach_vm_address_t replacement = start;
        kr = mach_vm_map(
            mach_task_self(),
            &replacement,
            len,
            0,
            VM_FLAGS_FIXED | VM_FLAGS_OVERWRITE,
            entry,
            0,
            false,
            VM_PROT_READ,
            VM_PROT_READ | VM_PROT_WRITE,
            VM_INHERIT_COPY);
        if (kr == KERN_SUCCESS && replacement != start) {
            mach_vm_deallocate(mach_task_self(), replacement, len);
            kr = KERN_NO_SPACE;
        }
    }

    mach_vm_deallocate(mach_task_self(), probe, len);
    mach_port_deallocate(mach_task_self(), entry);
    return kr;
}

int carrick_native_direct_enable_shadow(uintptr_t start, uintptr_t end) {
    int index = carrick_native_direct_range_interval_index(start, end);
    if (index < 0) {
        errno = EINVAL;
        return -1;
    }
    struct carrick_native_direct_range *range =
        &carrick_native_direct_ranges[index];
    uintptr_t range_start = atomic_load_explicit(
        &range->start, memory_order_acquire);
    uintptr_t range_end = atomic_load_explicit(
        &range->end, memory_order_relaxed);
    if (range_start == 0 || range_start == UINTPTR_MAX ||
        range_start >= range_end) {
        errno = EACCES;
        return -1;
    }
    kern_return_t protect_kr = mach_vm_protect(
        mach_task_self(),
        range_start,
        range_end - range_start,
        false,
        VM_PROT_READ);
    if (protect_kr != KERN_SUCCESS &&
        carrick_native_direct_remap_map_jit_shadow(
            range_start, range_end) != KERN_SUCCESS) {
        errno = EACCES;
        return -1;
    }
    /* Protection is revoked before publication. Once `shadow` is visible,
       no CPU can still enter the guest-visible bytes directly. */
    atomic_fetch_add_explicit(
        &range->shadow_generation, 1, memory_order_acq_rel);
    atomic_store_explicit(&range->shadow, true, memory_order_release);
    return 0;
}

int carrick_native_direct_range_shadowed(uintptr_t address) {
    return carrick_native_direct_range_is_shadow(address) ? 1 : 0;
}

const uint64_t *carrick_native_direct_shadow_generation(
    uintptr_t pc,
    uint64_t *expected) {
    int index = carrick_native_direct_range_index(pc);
    if (index < 0 || expected == 0) {
        return 0;
    }
    struct carrick_native_direct_range *range =
        &carrick_native_direct_ranges[index];
    if (!atomic_load_explicit(&range->shadow, memory_order_acquire)) {
        return 0;
    }
    *expected = atomic_load_explicit(
        &range->shadow_generation, memory_order_acquire);
    return (const uint64_t *)(const void *)&range->shadow_generation;
}

int carrick_native_direct_publish_dynamic_code(
    uintptr_t start,
    uintptr_t end) {
    int published = 0;
    int index = (start % sizeof(uint32_t) == 0 &&
                 end % sizeof(uint32_t) == 0)
                    ? carrick_native_direct_range_interval_index(start, end)
                    : -1;
    if (index >= 0) {
        struct carrick_native_direct_range *range =
            &carrick_native_direct_ranges[index];
        uint64_t generation = atomic_load_explicit(
            &range->mapping_generation, memory_order_acquire);
        uint64_t ticket = atomic_fetch_add_explicit(
            &range->publication_cursor, 1, memory_order_acq_rel);
        uint64_t sequence = ticket + 1;
        if (sequence != 0) {
            size_t slot = (size_t)(ticket %
                                   CARRICK_NATIVE_DIRECT_PUBLICATION_CAPACITY);
            struct carrick_native_direct_publication *publication =
                &carrick_native_direct_publications[index][slot];
            atomic_store_explicit(
                &publication->commit, 0, memory_order_release);
            atomic_store_explicit(
                &publication->mapping_generation,
                generation,
                memory_order_relaxed);
            atomic_store_explicit(
                &publication->start, start, memory_order_relaxed);
            atomic_store_explicit(
                &publication->end, end, memory_order_relaxed);
            atomic_store_explicit(
                &publication->commit, sequence, memory_order_release);

            uintptr_t current_start = atomic_load_explicit(
                &range->start, memory_order_acquire);
            uintptr_t current_end = atomic_load_explicit(
                &range->end, memory_order_relaxed);
            uint64_t current_generation = atomic_load_explicit(
                &range->mapping_generation, memory_order_acquire);
            if (current_start <= start && end <= current_end &&
                current_generation == generation) {
                atomic_store_explicit(
                    &range->dirty, true, memory_order_release);
                published = 1;
            }
        } else {
            errno = EOVERFLOW;
        }
    } else {
        errno = EINVAL;
    }
    /* Phase 15 is the exact AArch64 cache-publication boundary. The island
       resumes libgcc's original cache maintenance after this lock-free journal
       commit; traced time remains attribution-only. */
    carrick_native_direct_exception_probe(
        15,
        (uint64_t)start,
        (uint64_t)end,
        (uint64_t)published,
        0);
    return published;
}

int carrick_native_direct_publication_for_pc(
    uintptr_t pc,
    uintptr_t *published_start,
    uintptr_t *published_end,
    uint64_t *published_sequence,
    uint64_t *mapping_generation,
    uint64_t *write_epoch) {
    return carrick_native_direct_publication_for_pc_internal(
        pc,
        published_start,
        published_end,
        published_sequence,
        mapping_generation,
        write_epoch);
}

int carrick_native_direct_publication_still_current(
    uintptr_t pc,
    uintptr_t published_start,
    uintptr_t published_end,
    uint64_t published_sequence,
    uint64_t mapping_generation,
    uint64_t write_epoch,
    int require_write_epoch) {
    return carrick_native_direct_publication_still_current_internal(
               pc,
               published_start,
               published_end,
               published_sequence,
               mapping_generation,
               write_epoch,
               require_write_epoch != 0)
               ? 1
               : 0;
}

int carrick_native_direct_begin_dynamic_write(uintptr_t address) {
    return carrick_native_direct_range_begin_write(address);
}

// Test-only measurement entrypoints. They are not called by the production
// gateway and therefore add no branch or counter traffic to its hot path. Each
// pair invokes the exact primitives used by the ABI closure while returning to
// the same state in which it started.
int carrick_native_dsr_benchmark_signal_mask_pair(void) {
    if (carrick_native_unblock_kick_signal() != 0) {
        return -1;
    }
    return carrick_native_block_kick_signal();
}

int carrick_native_dsr_benchmark_custom_x18_pair(void) {
    if (carrick_native_init_custom_x18() != 0) {
        return -1;
    }
    carrick_native_set_custom_x18(true);
    carrick_native_set_custom_x18(false);
    return 0;
}

// The GPRs carrick owns inside translated code, whose guest values therefore
// live in snapshot.x[] rather than the physical register: Darwin's platform
// register x18, the DSR context pointer x28, and the memory lowering's
// reserved address scratch (carrick-dsr-aarch64's gateway::RESERVED_SCRATCH,
// pinned to 19 by a Rust-side const assert because this file and
// gateway_aarch64.S cannot read it).
#define CARRICK_NATIVE_DSR_RESERVED_SCRATCH 19

static void carrick_native_snapshot_mcontext(
    struct carrick_native_ucontext_snapshot *out,
    const struct __darwin_mcontext64 *mc,
    bool preserve_virtual_registers) {
    for (int i = 0; i < 29; i++) {
        if (!preserve_virtual_registers ||
            (i != 18 && i != 28 &&
             i != CARRICK_NATIVE_DSR_RESERVED_SCRATCH)) {
            out->x[i] = mc->__ss.__x[i];
        }
    }
    out->x[29] = mc->__ss.__fp;
    out->x[30] = mc->__ss.__lr;
    out->sp = mc->__ss.__sp;
    out->pc = mc->__ss.__pc;
    out->pstate = mc->__ss.__cpsr;
    memcpy(out->v, mc->__ns.__v, sizeof(out->v));
    out->fpsr = mc->__ns.__fpsr;
    out->fpcr = mc->__ns.__fpcr;
    out->esr = mc->__es.__esr;
    out->far = mc->__es.__far;
}

static void carrick_native_write_literal(const char *s) {
    size_t len = 0;
    while (s[len] != 0) {
        len++;
    }
    (void)write(STDERR_FILENO, s, len);
}

static void carrick_native_write_decimal(int value) {
    char buf[16];
    size_t pos = sizeof(buf);
    unsigned int n = value < 0 ? (unsigned int)(-value) : (unsigned int)value;
    if (n == 0) {
        buf[--pos] = '0';
    }
    while (n != 0 && pos != 0) {
        buf[--pos] = (char)('0' + (n % 10));
        n /= 10;
    }
    if (value < 0 && pos != 0) {
        buf[--pos] = '-';
    }
    (void)write(STDERR_FILENO, &buf[pos], sizeof(buf) - pos);
}

static void carrick_native_write_hex(uint64_t value) {
    static const char digits[] = "0123456789abcdef";
    char buf[16];
    for (int i = 15; i >= 0; i--) {
        buf[i] = digits[value & 0xf];
        value >>= 4;
    }
    (void)write(STDERR_FILENO, buf, sizeof(buf));
}

static void carrick_native_fatal_signal_handler(int sig, siginfo_t *info, void *uap) {
    carrick_native_enter_host_x18_abi();
    carrick_native_write_literal("native Darwin fatal signal ");
    carrick_native_write_decimal(sig);
    if (uap != 0) {
        ucontext_t *uc = (ucontext_t *)uap;
        if (uc->uc_mcontext != 0) {
            carrick_native_write_literal(" pc=0x");
            carrick_native_write_hex(uc->uc_mcontext->__ss.__pc);
            carrick_native_write_literal(" sp=0x");
            carrick_native_write_hex(uc->uc_mcontext->__ss.__sp);
            carrick_native_write_literal(" lr=0x");
            carrick_native_write_hex(uc->uc_mcontext->__ss.__lr);
            carrick_native_write_literal(" x0=0x");
            carrick_native_write_hex(uc->uc_mcontext->__ss.__x[0]);
            carrick_native_write_literal(" esr=0x");
            carrick_native_write_hex(uc->uc_mcontext->__es.__esr);
            carrick_native_write_literal(" far=0x");
            carrick_native_write_hex(uc->uc_mcontext->__es.__far);
        }
    }
    if (info != 0) {
        carrick_native_write_literal(" addr=0x");
        carrick_native_write_hex((uintptr_t)info->si_addr);
    }
    carrick_native_write_literal(" tpidr=0x");
    carrick_native_write_hex(carrick_native_read_tpidr_el0());
    carrick_native_write_literal(" saved_host_tpidr=0x");
    carrick_native_write_hex(carrick_native_host_tpidr_el0);
    carrick_native_write_literal(" image_base=0x");
    carrick_native_write_hex((uintptr_t)_dyld_get_image_header(0));
    carrick_native_write_literal("\n");
    _exit(128 + sig);
}

static bool carrick_native_executable_range_catalog_contains(
    const struct carrick_native_executable_range_catalog *catalog,
    uintptr_t pc) {
    if (catalog == 0) {
        return false;
    }
    const struct carrick_native_executable_range_node *node =
        atomic_load_explicit(&catalog->head, memory_order_acquire);
    while (node != 0) {
        if (pc >= node->start && pc < node->end) {
            return true;
        }
        node = node->next;
    }
    return false;
}

enum carrick_native_dsr_kick_transition {
    CARRICK_NATIVE_DSR_KICK_RETURN_COMMON = 1,
    CARRICK_NATIVE_DSR_KICK_PRESERVE_EXIT = 2,
    CARRICK_NATIVE_DSR_KICK_AT_ENTRY = 3,
    CARRICK_NATIVE_DSR_KICK_CAPTURE = 4,
};

static enum carrick_native_dsr_kick_transition
carrick_native_dsr_classify_kick(
    const struct carrick_native_dsr_signal_context *context,
    uintptr_t interrupted_pc) {
    uintptr_t common_start = (uintptr_t)carrick_dsr_exit_common_start;
    uintptr_t common_end = (uintptr_t)carrick_dsr_exit_common_end;
    if (context->exit_status != 0 &&
        interrupted_pc >= common_start && interrupted_pc < common_end) {
        return CARRICK_NATIVE_DSR_KICK_RETURN_COMMON;
    }
    if (context->entry_in_progress == 2 ||
        context->exit_status == 4 || context->exit_status == 5) {
        return CARRICK_NATIVE_DSR_KICK_PRESERVE_EXIT;
    }
    if (context->entry_in_progress == 1 ||
        (context->entry_in_progress == 0 &&
         (interrupted_pc < context->cache_start ||
          interrupted_pc >= context->cache_end) &&
         !carrick_native_executable_range_catalog_contains(
             context->executable_range_catalog,
             interrupted_pc))) {
        return CARRICK_NATIVE_DSR_KICK_AT_ENTRY;
    }
    return CARRICK_NATIVE_DSR_KICK_CAPTURE;
}

/* Test seam for the exact production kick-transition classifier. The capture
   arm writes only the fields needed to model a first asynchronous kick; live
   signal tests cover the full mcontext snapshot. */
uint32_t carrick_native_dsr_test_apply_kick_transition(
    void *opaque,
    uintptr_t interrupted_pc) {
    struct carrick_native_dsr_signal_context *context = opaque;
    enum carrick_native_dsr_kick_transition transition =
        carrick_native_dsr_classify_kick(context, interrupted_pc);
    if (transition == CARRICK_NATIVE_DSR_KICK_AT_ENTRY) {
        context->exit_target = context->snapshot.pc;
        context->exit_source = 0;
        context->exit_status = 8;
    } else if (transition == CARRICK_NATIVE_DSR_KICK_CAPTURE) {
        context->snapshot.pc = interrupted_pc;
        context->exit_target = interrupted_pc;
        context->exit_source = interrupted_pc;
        context->exit_status = 5;
    }
    return (uint32_t)transition;
}

static void carrick_native_dsr_signal_handler(int sig, siginfo_t *info, void *uap) {
    int32_t event_kind = CARRICK_NATIVE_EVENT_SIGNAL;
    if (sig == SIGPIPE) {
        bool requested = carrick_native_kick_state_take(
            carrick_native_bound_kick_state);
        if (carrick_native_active_dsr_context == 0) {
            if (requested) {
                carrick_native_dsr_deferred_kick = 1;
            }
            return;
        }
        // A coalesced or stale SIGPIPE can arrive after another path consumed
        // the pending bit. Returning directly to DSR code is unsafe because
        // Darwin's signal return does not reliably preserve custom x18. Route
        // every SIGPIPE observed while DSR is active through a typed kick exit;
        // Rust will simply find no pending guest signal and resume cleanly.
        if (!requested && carrick_native_active_dsr_context == 0) {
            return;
        }
        if (uap == 0) {
            return;
        }
        event_kind = CARRICK_NATIVE_EVENT_KICK;
    } else if ((sig != SIGTRAP && sig != SIGSEGV && sig != SIGBUS) ||
               carrick_native_active_dsr_context == 0 || uap == 0) {
        carrick_native_fatal_signal_handler(sig, info, uap);
    }

    ucontext_t *uc = (ucontext_t *)uap;
    if (uc->uc_mcontext == 0) {
        _exit(128 + sig);
    }

    if (carrick_native_active_dsr_context != 0) {
        struct carrick_native_dsr_signal_context *context =
            carrick_native_active_dsr_context;
        uintptr_t interrupted_pc = uc->uc_mcontext->__ss.__pc;
        enum carrick_native_dsr_kick_transition kick_transition =
            event_kind == CARRICK_NATIVE_EVENT_KICK
                ? carrick_native_dsr_classify_kick(context, interrupted_pc)
                : ((context->exit_status == 4 || context->exit_status == 5)
                       ? CARRICK_NATIVE_DSR_KICK_PRESERVE_EXIT
                       : CARRICK_NATIVE_DSR_KICK_CAPTURE);
        // An emitted exit publishes its typed status before branching into the
        // stable context-save gateway. A kick in that short window is already
        // at a host boundary: replacing the published exit with a Kick would
        // report the gateway PC as translated guest code and discard an
        // in-flight syscall. The common gateway only stores guest registers
        // until its final host transition, so return to it once with further
        // kick delivery blocked and its physical context register reasserted.
        // carrick_native_dsr_enter_host_abi performs the normal idempotent mask
        // transition before Rust observes the queued Linux signal.
        if (kick_transition == CARRICK_NATIVE_DSR_KICK_RETURN_COMMON) {
            if (sigaddset(&uc->uc_sigmask, SIGPIPE) != 0) {
                _exit(128 + sig);
            }
            uc->uc_mcontext->__ss.__x[28] = (uintptr_t)context;
            return;
        }
        // Preserve the first interrupted cache PC and register snapshot. If
        // the recovery gateway itself faults, overwriting them would turn the
        // useful guest fault into an unmappable gateway address.
        if (kick_transition == CARRICK_NATIVE_DSR_KICK_PRESERVE_EXIT) {
            // Either the stable gateway already captured every guest register,
            // or a preceding asynchronous fault/kick captured the authoritative
            // cache PC and register snapshot. Abandon this later host frame
            // through the signal exit below without relabeling that cache PC as
            // a KickAtEntry guest resume address.
        } else if (kick_transition == CARRICK_NATIVE_DSR_KICK_AT_ENTRY) {
            // The kick became deliverable while the gateway was still inside
            // pthread_sigmask, or a stale active-context window exposed a host
            // PC while phase zero claimed translated execution. No translated
            // instruction at that PC can be authoritative: DSR executes only
            // inside the current range or another process-catalogued
            // executable mapping.
            // Preserve the original guest snapshot rather than replacing it
            // with host registers.
            context->exit_target = context->snapshot.pc;
            context->exit_source = 0;
            context->exit_status = 8;
        } else if (kick_transition == CARRICK_NATIVE_DSR_KICK_CAPTURE) {
            carrick_native_snapshot_mcontext(
                &context->snapshot,
                uc->uc_mcontext,
                true);
            context->snapshot.event_kind = event_kind;
            context->snapshot.signal = sig;
            context->snapshot.signal_code = info != 0 ? info->si_code : 0;
            context->snapshot.fault_address =
                info != 0 ? (uintptr_t)info->si_addr : 0;
            // Guest x18 is virtualized, so the ordinary snapshot deliberately
            // preserves its guest value.  Retain the interrupted physical x18
            // separately for diagnosing faults at the inline-cache branch.
            context->exit_link = uc->uc_mcontext->__ss.__x[18];
            context->physical_reserved =
                uc->uc_mcontext->__ss.__x[CARRICK_NATIVE_DSR_RESERVED_SCRATCH];
            context->exit_has_link = context->entry_in_progress;
            context->exit_target = uc->uc_mcontext->__ss.__pc;
            context->exit_source = uc->uc_mcontext->__ss.__pc;
            context->exit_status = event_kind == CARRICK_NATIVE_EVENT_KICK ? 5 : 4;
        }
        // The gateway exit runs with physical x28 as its context pointer. A
        // fault can arrive precisely because translated execution corrupted
        // that invariant, so do not rely on the interrupted x28 while
        // redirecting to the common exit stub.
        uintptr_t recovery_sp = context->host_sp - 16;
        *(uintptr_t *)recovery_sp = (uintptr_t)context;
        uc->uc_mcontext->__ss.__sp = recovery_sp;
        uc->uc_mcontext->__ss.__pc = (uintptr_t)carrick_dsr_exit_signal;
        return;
    }

    carrick_native_fatal_signal_handler(sig, info, uap);
}

int carrick_native_unblock_transport_signals(void) {
    sigset_t transport;
    if (sigemptyset(&transport) != 0 ||
        sigaddset(&transport, SIGTRAP) != 0 ||
        sigaddset(&transport, SIGSEGV) != 0 ||
        sigaddset(&transport, SIGBUS) != 0 ||
        sigaddset(&transport, SIGILL) != 0) {
        return -1;
    }
    int rc = pthread_sigmask(SIG_UNBLOCK, &transport, 0);
    if (rc != 0) {
        errno = rc;
        return -1;
    }
    return 0;
}

static int carrick_native_block_kick_signal(void) {
    sigset_t kick;
    if (sigemptyset(&kick) != 0 || sigaddset(&kick, SIGPIPE) != 0) {
        return -1;
    }
    int rc = pthread_sigmask(SIG_BLOCK, &kick, 0);
    if (rc != 0) {
        errno = rc;
        return -1;
    }
    return 0;
}

static int carrick_native_unblock_kick_signal(void) {
    sigset_t kick;
    if (sigemptyset(&kick) != 0 || sigaddset(&kick, SIGPIPE) != 0) {
        return -1;
    }
    int rc = pthread_sigmask(SIG_UNBLOCK, &kick, 0);
    if (rc != 0) {
        errno = rc;
        return -1;
    }
    return 0;
}

int carrick_native_install_dsr_signal_handlers(void) {
    if (carrick_native_init_custom_x18() != 0) {
        return -1;
    }
    if (carrick_native_unblock_transport_signals() != 0) {
        return -1;
    }
    if (carrick_native_block_kick_signal() != 0) {
        return -1;
    }
    carrick_native_dsr_deferred_kick = 0;
    carrick_native_dsr_kick_unblocked = false;
    carrick_native_host_tpidr_el0 = carrick_native_read_tpidr_el0();
    stack_t current_stack;
    memset(&current_stack, 0, sizeof(current_stack));
    if (sigaltstack(0, &current_stack) != 0) {
        return -1;
    }
    if ((current_stack.ss_flags & SS_ONSTACK) == 0) {
        stack_t stack;
        memset(&stack, 0, sizeof(stack));
        stack.ss_sp = carrick_native_signal_stack;
        stack.ss_size = sizeof(carrick_native_signal_stack);
        if (sigaltstack(&stack, 0) != 0) {
            return -1;
        }
    }

    struct sigaction action;
    memset(&action, 0, sizeof(action));
    action.sa_sigaction = carrick_native_dsr_signal_handler;
    action.sa_flags = SA_SIGINFO | SA_ONSTACK;
    sigfillset(&action.sa_mask);
    if (sigaction(SIGTRAP, &action, 0) != 0) {
        return -1;
    }

    memset(&action, 0, sizeof(action));
    action.sa_sigaction = carrick_native_dsr_signal_handler;
    action.sa_flags = SA_SIGINFO | SA_ONSTACK;
    sigfillset(&action.sa_mask);
    if (sigaction(SIGSEGV, &action, 0) != 0) {
        return -1;
    }
    if (sigaction(SIGBUS, &action, 0) != 0) {
        return -1;
    }
    if (sigaction(SIGPIPE, &action, 0) != 0) {
        return -1;
    }
    action.sa_sigaction = carrick_native_fatal_signal_handler;
    if (sigaction(SIGILL, &action, 0) != 0) {
        return -1;
    }
    return 0;
}

/* XNU preserves userspace x18 across exception/syscall return only for the
   custom-x18 task ABI. Carrick cannot trust a Mach-O SDK stamp or entitlement
   claim by itself: prove the actual running task policy with the cheapest
   possible kernel round trip. Keep this as a complete assembler leaf so the
   Darwin C compiler never has to model its reserved x18 as an inline clobber. */
__asm__(
    ".text\n"
    ".p2align 2\n"
    "_carrick_native_direct_physical_x18_probe:\n"
    "mov x9, x18\n"
    "movz x10, #0x1515\n"
    "movk x10, #0x1616, lsl #16\n"
    "movk x10, #0x1717, lsl #32\n"
    "movk x10, #0x1818, lsl #48\n"
    "mov x18, x10\n"
    "mov x16, #20\n"
    "svc #0x80\n"
    "cmp x18, x10\n"
    "cset w0, eq\n"
    "mov x18, x9\n"
    "ret\n");

int carrick_native_direct_physical_x18_supported(void) {
    int cached = atomic_load_explicit(
        &carrick_native_direct_physical_x18_state, memory_order_acquire);
    if (cached >= 0) {
        return cached;
    }
    int supported = carrick_native_init_custom_x18() == 0
                        ? carrick_native_direct_physical_x18_probe()
                        : 0;
    int expected = -1;
    (void)atomic_compare_exchange_strong_explicit(
        &carrick_native_direct_physical_x18_state,
        &expected,
        supported,
        memory_order_release,
        memory_order_acquire);
    return atomic_load_explicit(
        &carrick_native_direct_physical_x18_state, memory_order_acquire);
}

int carrick_native_direct_enter_guest_x18_abi(void) {
    return carrick_native_enter_guest_x18_abi();
}

void carrick_native_direct_enter_host_x18_abi(void) {
    carrick_native_enter_host_x18_abi();
}

void carrick_native_clear_icache(void *start, size_t len) {
    sys_icache_invalidate(start, len);
}
#else
int carrick_native_install_dsr_signal_handlers(void) { return -1; }
int carrick_native_direct_physical_x18_supported(void) { return 0; }
int carrick_native_direct_enter_guest_x18_abi(void) { return -1; }
void carrick_native_direct_enter_host_x18_abi(void) {}
int carrick_native_direct_register_range(uintptr_t start, uintptr_t end) {
    (void)start; (void)end; return -1;
}
void carrick_native_direct_forget_range(uintptr_t start, uintptr_t end) {
    (void)start; (void)end;
}
int carrick_native_direct_range_is_pristine(uintptr_t start, uintptr_t end) {
    (void)start; (void)end; return 0;
}
int carrick_native_direct_enable_shadow(uintptr_t start, uintptr_t end) {
    (void)start; (void)end; return -1;
}
int carrick_native_direct_range_shadowed(uintptr_t address) {
    (void)address; return 0;
}
const uint64_t *carrick_native_direct_shadow_generation(
    uintptr_t pc,
    uint64_t *expected) {
    (void)pc; (void)expected; return 0;
}
int carrick_native_direct_publish_dynamic_code(uintptr_t start, uintptr_t end) {
    (void)start; (void)end; return 0;
}
int carrick_native_direct_publication_for_pc(
    uintptr_t pc,
    uintptr_t *published_start,
    uintptr_t *published_end,
    uint64_t *published_sequence,
    uint64_t *mapping_generation,
    uint64_t *write_epoch) {
    (void)pc; (void)published_start; (void)published_end;
    (void)published_sequence; (void)mapping_generation; (void)write_epoch;
    return 0;
}
int carrick_native_direct_publication_still_current(
    uintptr_t pc,
    uintptr_t published_start,
    uintptr_t published_end,
    uint64_t published_sequence,
    uint64_t mapping_generation,
    uint64_t write_epoch,
    int require_write_epoch) {
    (void)pc; (void)published_start; (void)published_end;
    (void)published_sequence; (void)mapping_generation; (void)write_epoch;
    (void)require_write_epoch;
    return 0;
}
int carrick_native_direct_begin_dynamic_write(uintptr_t address) {
    (void)address; return 0;
}
int carrick_native_direct_register_exception_route(
    uintptr_t site,
    uintptr_t entry,
    uintptr_t return_pc,
    uintptr_t resume_pc) {
    (void)site; (void)entry; (void)return_pc; (void)resume_pc; return 0;
}
void carrick_native_clear_icache(void *start, size_t len) {
    (void)start;
    (void)len;
}
#endif
