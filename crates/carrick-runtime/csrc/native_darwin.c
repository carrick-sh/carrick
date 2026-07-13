#ifndef _XOPEN_SOURCE
#define _XOPEN_SOURCE 700
#endif
#ifndef _DARWIN_C_SOURCE
#define _DARWIN_C_SOURCE
#endif
#include <dlfcn.h>
#include <errno.h>
#include <libkern/OSCacheControl.h>
#include <mach-o/dyld.h>
#include <pthread.h>
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
};

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
_Static_assert(sizeof(struct carrick_native_dsr_signal_context) == 1200,
               "DSR signal context size");

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

static void carrick_native_snapshot_mcontext(
    struct carrick_native_ucontext_snapshot *out,
    const struct __darwin_mcontext64 *mc,
    bool preserve_virtual_registers) {
    for (int i = 0; i < 29; i++) {
        if (!preserve_virtual_registers || (i != 18 && i != 28)) {
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
        uintptr_t common_start = (uintptr_t)carrick_dsr_exit_common_start;
        uintptr_t common_end = (uintptr_t)carrick_dsr_exit_common_end;
        // An emitted exit publishes its typed status before branching into the
        // stable context-save gateway. A kick in that short window is already
        // at a host boundary: replacing the published exit with a Kick would
        // report the gateway PC as translated guest code and discard an
        // in-flight syscall. The common gateway only stores guest registers
        // until its final host transition, so return to it once with further
        // kick delivery blocked and its physical context register reasserted.
        // carrick_native_dsr_enter_host_abi performs the normal idempotent mask
        // transition before Rust observes the queued Linux signal.
        if (event_kind == CARRICK_NATIVE_EVENT_KICK &&
            context->exit_status != 0 &&
            interrupted_pc >= common_start && interrupted_pc < common_end) {
            if (sigaddset(&uc->uc_sigmask, SIGPIPE) != 0) {
                _exit(128 + sig);
            }
            uc->uc_mcontext->__ss.__x[28] = (uintptr_t)context;
            return;
        }
        // Preserve the first interrupted cache PC and register snapshot. If
        // the recovery gateway itself faults, overwriting them would turn the
        // useful guest fault into an unmappable gateway address.
        if (event_kind == CARRICK_NATIVE_EVENT_KICK &&
            context->entry_in_progress == 2) {
            // The stable gateway already captured every guest register and
            // published a typed exit, then a kick interrupted the host-mask
            // transition itself.  Abandon that host frame through the signal
            // exit below without replacing the completed guest exit with the
            // host library PC.
        } else if (event_kind == CARRICK_NATIVE_EVENT_KICK &&
                   (context->entry_in_progress == 1 ||
                    (context->entry_in_progress == 0 &&
                     (interrupted_pc < context->cache_start ||
                      interrupted_pc >= context->cache_end)))) {
            // The kick became deliverable while the gateway was still inside
            // pthread_sigmask, or a stale active-context window exposed a host
            // PC while phase zero claimed translated execution. No translated
            // instruction at that PC can be authoritative: DSR executes only
            // inside the MAP_JIT cache, whose bounds are carried in-context.
            // Preserve the original guest snapshot rather than replacing it
            // with host registers.
            context->exit_target = context->snapshot.pc;
            context->exit_source = 0;
            context->exit_status = 8;
        } else if (context->exit_status != 4 && context->exit_status != 5) {
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

void carrick_native_clear_icache(void *start, size_t len) {
    sys_icache_invalidate(start, len);
}
#else
int carrick_native_install_dsr_signal_handlers(void) { return -1; }
void carrick_native_clear_icache(void *start, size_t len) {
    (void)start;
    (void)len;
}
#endif
