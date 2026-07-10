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
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <sys/mman.h>
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
    int32_t signal;
    int32_t signal_code;
    uint64_t fault_address;
    uint64_t esr;
    uint64_t far;
};

#if defined(__aarch64__)
static _Thread_local sigjmp_buf carrick_native_env;
static _Thread_local sigjmp_buf carrick_native_return_env;
static _Thread_local volatile sig_atomic_t carrick_native_env_ready;
static _Thread_local ucontext_t carrick_native_uc;
static _Thread_local ucontext_t *carrick_native_pending_uc;
static _Thread_local unsigned char carrick_native_signal_stack[64 * 1024]
    __attribute__((aligned(16)));
static _Thread_local uint64_t carrick_native_host_tpidr_el0;
static _Thread_local int32_t carrick_native_last_signal;
static _Thread_local int32_t carrick_native_last_signal_code;
static _Thread_local uint64_t carrick_native_last_fault_address;

typedef void (*carrick_native_update_tpidr_fn)(uint64_t, uint64_t);
_Static_assert(sizeof(carrick_native_update_tpidr_fn) == sizeof(uint64_t),
               "native Darwin updater pointer must fit x1");

static carrick_native_update_tpidr_fn carrick_native_update_tpidr;
static uint64_t carrick_native_update_tpidr_address;
static pthread_once_t carrick_native_update_tpidr_once = PTHREAD_ONCE_INIT;
static int carrick_native_update_tpidr_errno;

#define CARRICK_NATIVE_CUSTOM_X18_BIT UINT64_C(0x0001000000000000)
#define CARRICK_NATIVE_TPIDR_BASE_MASK UINT64_C(0xfffffffffff00000)

#define CARRICK_NATIVE_RESUME_BUCKET_SIZE (UINT64_C(1) << 27)
#define CARRICK_NATIVE_MAX_RESUME_PAGES 256
#define CARRICK_NATIVE_RESUME_CACHE_SIZE 16384
#define CARRICK_NATIVE_RESUME_PAD_SIZE 40

struct carrick_native_resume_page {
    uint64_t bucket;
    uint8_t *base;
    size_t used;
};

struct carrick_native_resume_entry {
    uint64_t target;
    void *pad;
};

static _Thread_local struct carrick_native_resume_page
    carrick_native_resume_pages[CARRICK_NATIVE_MAX_RESUME_PAGES];
static _Thread_local struct carrick_native_resume_entry
    carrick_native_resume_cache[CARRICK_NATIVE_RESUME_CACHE_SIZE];
static _Thread_local size_t carrick_native_resume_page_count;
static _Thread_local size_t carrick_native_page_size;

static struct __darwin_mcontext64 *carrick_native_mcontext(void) {
    return carrick_native_uc.uc_mcontext;
}

__attribute__((always_inline)) static inline void carrick_native_copy_mcontext(
    struct __darwin_mcontext64 *destination,
    const struct __darwin_mcontext64 *source) {
    __builtin_memcpy_inline(
        destination,
        source,
        sizeof(*destination));
}

static uint64_t carrick_native_read_tpidr_el0(void) {
    uint64_t value;
    __asm__ volatile("mrs %0, TPIDR_EL0" : "=r"(value));
    return value;
}

__attribute__((noreturn)) static void carrick_native_branch_mcontext(
    void *state,
    void *neon,
    void *pad);

static void carrick_native_write_tpidr_el0(uint64_t value) {
    __asm__ volatile("msr TPIDR_EL0, %0" : : "r"(value) : "memory");
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

static uint32_t carrick_native_ldr_x_unsigned(
    uint32_t destination,
    uint32_t base,
    uint32_t byte_offset) {
    return UINT32_C(0xf9400000) | ((byte_offset / 8) << 10) | (base << 5) |
           destination;
}

static size_t carrick_native_resume_hash(uint64_t target) {
    uint64_t mixed = (target >> 2) ^ (target >> 19) ^ (target >> 37);
    return (size_t)mixed & (CARRICK_NATIVE_RESUME_CACHE_SIZE - 1);
}

static struct carrick_native_resume_entry *
carrick_native_find_resume_entry(uint64_t target, bool *found) {
    size_t index = carrick_native_resume_hash(target);
    for (size_t probe = 0; probe < CARRICK_NATIVE_RESUME_CACHE_SIZE; probe++) {
        struct carrick_native_resume_entry *entry =
            &carrick_native_resume_cache[(index + probe) &
                                         (CARRICK_NATIVE_RESUME_CACHE_SIZE - 1)];
        if (entry->target == target) {
            *found = true;
            return entry;
        }
        if (entry->target == 0) {
            *found = false;
            return entry;
        }
    }
    errno = ENOSPC;
    return 0;
}

static struct carrick_native_resume_page *
carrick_native_find_resume_page(uint64_t target) {
    for (size_t i = 0; i < carrick_native_resume_page_count; i++) {
        struct carrick_native_resume_page *page = &carrick_native_resume_pages[i];
        if (page->used + CARRICK_NATIVE_RESUME_PAD_SIZE > carrick_native_page_size) {
            continue;
        }
        uint64_t branch_address =
            (uint64_t)(uintptr_t)(page->base + page->used + 28);
        int64_t branch_delta = (int64_t)target - (int64_t)branch_address;
        if ((branch_delta & 3) == 0 && branch_delta >= -INT64_C(134217728) &&
            branch_delta <= INT64_C(134217724)) {
            return page;
        }
    }
    return 0;
}

void carrick_native_reset_resume_pads(void) {
    memset(carrick_native_resume_pages, 0, sizeof(carrick_native_resume_pages));
    memset(carrick_native_resume_cache, 0, sizeof(carrick_native_resume_cache));
    carrick_native_resume_page_count = 0;
    carrick_native_page_size = 0;
}

int carrick_native_register_resume_page(
    uint64_t bucket,
    void *base,
    size_t page_size) {
    if (base == 0 || page_size == 0 || (page_size & (page_size - 1)) != 0 ||
        ((uint64_t)(uintptr_t)base & (page_size - 1)) != 0 ||
        ((uint64_t)(uintptr_t)base & ~(CARRICK_NATIVE_RESUME_BUCKET_SIZE - 1)) != bucket ||
        carrick_native_resume_page_count >= CARRICK_NATIVE_MAX_RESUME_PAGES) {
        errno = EINVAL;
        return -1;
    }
    if (carrick_native_page_size != 0 && carrick_native_page_size != page_size) {
        errno = EINVAL;
        return -1;
    }
    carrick_native_page_size = page_size;
    struct carrick_native_resume_page *page =
        &carrick_native_resume_pages[carrick_native_resume_page_count++];
    page->bucket = bucket;
    page->base = (uint8_t *)base;
    page->used = 0;
    return 0;
}

static struct carrick_native_resume_page *
carrick_native_allocate_resume_page(uint64_t bucket) {
    if (carrick_native_resume_page_count >= CARRICK_NATIVE_MAX_RESUME_PAGES) {
        errno = ENOSPC;
        return 0;
    }
    if (carrick_native_page_size == 0) {
        long page_size = sysconf(_SC_PAGESIZE);
        if (page_size <= 0) {
            errno = EINVAL;
            return 0;
        }
        carrick_native_page_size = (size_t)page_size;
    }

    uint64_t bucket_end = bucket + CARRICK_NATIVE_RESUME_BUCKET_SIZE;
    uint64_t center = bucket + CARRICK_NATIVE_RESUME_BUCKET_SIZE / 2;
    center &= ~((uint64_t)carrick_native_page_size - 1);
    size_t slots = CARRICK_NATIVE_RESUME_BUCKET_SIZE / carrick_native_page_size;
    for (size_t step = 0; step < slots; step++) {
        int64_t distance = (int64_t)((step + 1) / 2);
        int64_t direction = (step & 1) == 0 ? -1 : 1;
        uint64_t candidate = center;
        if (step != 0) {
            int64_t delta = direction * distance * (int64_t)carrick_native_page_size;
            candidate = (uint64_t)((int64_t)center + delta);
        }
        if (candidate < bucket || candidate + carrick_native_page_size > bucket_end) {
            continue;
        }
        void *mapped = mmap(
            (void *)(uintptr_t)candidate,
            carrick_native_page_size,
            PROT_READ | PROT_WRITE,
            MAP_ANON | MAP_PRIVATE | MAP_NORESERVE,
            -1,
            0);
        if (mapped == MAP_FAILED) {
            continue;
        }
        uint64_t mapped_address = (uint64_t)(uintptr_t)mapped;
        if (mapped_address < bucket ||
            mapped_address + carrick_native_page_size > bucket_end) {
            (void)munmap(mapped, carrick_native_page_size);
            continue;
        }
        struct carrick_native_resume_page *page =
            &carrick_native_resume_pages[carrick_native_resume_page_count++];
        page->bucket = bucket;
        page->base = (uint8_t *)mapped;
        page->used = 0;
        return page;
    }
    errno = ENOMEM;
    return 0;
}

static void *carrick_native_prepare_resume_pad(uint64_t target) {
    if (target == 0 || (target & 3) != 0) {
        errno = EINVAL;
        return 0;
    }
    bool found = false;
    struct carrick_native_resume_entry *cache_entry =
        carrick_native_find_resume_entry(target, &found);
    if (cache_entry == 0 || found) {
        return cache_entry == 0 ? 0 : cache_entry->pad;
    }

    uint64_t bucket = target & ~(CARRICK_NATIVE_RESUME_BUCKET_SIZE - 1);
    struct carrick_native_resume_page *page = carrick_native_find_resume_page(target);
    bool new_page = page == 0;
    if (new_page) {
        page = carrick_native_allocate_resume_page(bucket);
        if (page == 0) {
            return 0;
        }
    } else if (mprotect(page->base, carrick_native_page_size,
                        PROT_READ | PROT_WRITE) != 0) {
        return 0;
    }

    uint8_t *pad = page->base + page->used;
    uint32_t *instructions = (uint32_t *)pad;
    uint64_t branch_address = (uint64_t)(uintptr_t)(pad + 28);
    int64_t branch_delta = (int64_t)target - (int64_t)branch_address;
    if ((branch_delta & 3) != 0 || branch_delta < -INT64_C(134217728) ||
        branch_delta > INT64_C(134217724)) {
        errno = ERANGE;
        if (!new_page) {
            (void)mprotect(page->base, carrick_native_page_size,
                           PROT_READ | PROT_EXEC);
        }
        return 0;
    }

    instructions[0] = UINT32_C(0x58000111); /* ldr x17, pad+32 */
    instructions[1] = carrick_native_ldr_x_unsigned(16, 17, 128);
    instructions[2] = carrick_native_ldr_x_unsigned(18, 17, 144);
    instructions[3] = carrick_native_ldr_x_unsigned(9, 17, 248);
    instructions[4] = UINT32_C(0x9100013f); /* mov sp, x9 */
    instructions[5] = carrick_native_ldr_x_unsigned(9, 17, 72);
    instructions[6] = carrick_native_ldr_x_unsigned(17, 17, 136);
    instructions[7] = UINT32_C(0x14000000) |
                      ((uint32_t)(branch_delta >> 2) & UINT32_C(0x03ffffff));
    void *state = &carrick_native_uc.__mcontext_data.__ss;
    memcpy(pad + 32, &state, sizeof(state));
    sys_icache_invalidate(pad, CARRICK_NATIVE_RESUME_PAD_SIZE);
    if (mprotect(page->base, carrick_native_page_size, PROT_READ | PROT_EXEC) != 0) {
        return 0;
    }

    page->used += CARRICK_NATIVE_RESUME_PAD_SIZE;
    cache_entry->target = target;
    cache_entry->pad = pad;
    return pad;
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

static void carrick_native_trap_handler(int sig, siginfo_t *info, void *uap) {
    if ((sig != SIGTRAP && sig != SIGSEGV && sig != SIGBUS) ||
        !carrick_native_env_ready || uap == 0) {
        carrick_native_fatal_signal_handler(sig, info, uap);
    }

    ucontext_t *uc = (ucontext_t *)uap;
    if (uc->uc_mcontext == 0) {
        _exit(128 + sig);
    }

    carrick_native_copy_mcontext(
        &carrick_native_uc.__mcontext_data,
        uc->uc_mcontext);
    carrick_native_enter_host_x18_abi();
    carrick_native_write_tpidr_el0(carrick_native_host_tpidr_el0);
    carrick_native_last_signal = sig;
    carrick_native_last_signal_code = info != 0 ? info->si_code : 0;
    carrick_native_last_fault_address = info != 0 ? (uintptr_t)info->si_addr : 0;
    carrick_native_uc.uc_mcontext = &carrick_native_uc.__mcontext_data;
    carrick_native_pending_uc = uc;
    carrick_native_env_ready = 0;
    if (sigsetjmp(carrick_native_return_env, 1) == 0) {
        siglongjmp(carrick_native_env, 1);
    }

    ucontext_t *pending = carrick_native_pending_uc;
    if (pending == 0 || pending->uc_mcontext == 0) {
        _exit(128 + sig);
    }
    carrick_native_copy_mcontext(
        pending->uc_mcontext,
        &carrick_native_uc.__mcontext_data);
    carrick_native_pending_uc = 0;
    if (carrick_native_enter_guest_x18_abi() != 0) {
        _exit(128 + sig);
    }
}

int carrick_native_install_trap_handler(void) {
    if (carrick_native_init_custom_x18() != 0) {
        return -1;
    }
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
    action.sa_sigaction = carrick_native_trap_handler;
    action.sa_flags = SA_SIGINFO | SA_ONSTACK;
    sigfillset(&action.sa_mask);
    if (sigaction(SIGTRAP, &action, 0) != 0) {
        return -1;
    }

    memset(&action, 0, sizeof(action));
    action.sa_sigaction = carrick_native_trap_handler;
    action.sa_flags = SA_SIGINFO | SA_ONSTACK;
    sigfillset(&action.sa_mask);
    if (sigaction(SIGSEGV, &action, 0) != 0) {
        return -1;
    }
    if (sigaction(SIGBUS, &action, 0) != 0) {
        return -1;
    }
    action.sa_sigaction = carrick_native_fatal_signal_handler;
    if (sigaction(SIGILL, &action, 0) != 0) {
        return -1;
    }
    return 0;
}

int carrick_native_seed_ucontext(
    const struct carrick_native_ucontext_snapshot *snapshot) {
    if (snapshot == 0) {
        errno = EINVAL;
        return -1;
    }

    memset(&carrick_native_uc, 0, sizeof(carrick_native_uc));
    carrick_native_uc.uc_mcontext = &carrick_native_uc.__mcontext_data;
    struct __darwin_mcontext64 *mc = carrick_native_mcontext();
    if (mc == 0) {
        errno = EINVAL;
        return -1;
    }
    for (int i = 0; i < 29; i++) {
        mc->__ss.__x[i] = snapshot->x[i];
    }
    mc->__ss.__fp = snapshot->x[29];
    mc->__ss.__lr = snapshot->x[30];
    mc->__ss.__sp = snapshot->sp;
    mc->__ss.__pc = snapshot->pc;
    mc->__ss.__cpsr = (uint32_t)snapshot->pstate;
    memcpy(mc->__ns.__v, snapshot->v, sizeof(snapshot->v));
    mc->__ns.__fpsr = snapshot->fpsr;
    mc->__ns.__fpcr = snapshot->fpcr;
    carrick_native_last_signal = snapshot->signal;
    carrick_native_last_signal_code = snapshot->signal_code;
    carrick_native_last_fault_address = snapshot->fault_address;
    carrick_native_pending_uc = 0;
    carrick_native_env_ready = 0;
    return 0;
}

__attribute__((noreturn)) static void carrick_native_branch(uint64_t entry, uint64_t sp) {
    __asm__ volatile(
        "mov sp, %1\n"
        "br %0\n"
        :
        : "r"(entry), "r"(sp)
        : "memory");
    __builtin_unreachable();
}

__attribute__((naked, noreturn)) static void carrick_native_branch_mcontext(
    void *state,
    void *neon,
    void *pad) {
    __asm__ volatile(
        "mov x16, x0\n"
        "mov x17, x1\n"
        "mov x18, x2\n"
        "ldp q0,  q1,  [x17, #0]\n"
        "ldp q2,  q3,  [x17, #32]\n"
        "ldp q4,  q5,  [x17, #64]\n"
        "ldp q6,  q7,  [x17, #96]\n"
        "ldp q8,  q9,  [x17, #128]\n"
        "ldp q10, q11, [x17, #160]\n"
        "ldp q12, q13, [x17, #192]\n"
        "ldp q14, q15, [x17, #224]\n"
        "ldp q16, q17, [x17, #256]\n"
        "ldp q18, q19, [x17, #288]\n"
        "ldp q20, q21, [x17, #320]\n"
        "ldp q22, q23, [x17, #352]\n"
        "ldp q24, q25, [x17, #384]\n"
        "ldp q26, q27, [x17, #416]\n"
        "ldp q28, q29, [x17, #448]\n"
        "ldp q30, q31, [x17, #480]\n"
        "ldr w9, [x17, #512]\n"
        "msr FPSR, x9\n"
        "ldr w9, [x17, #516]\n"
        "msr FPCR, x9\n"
        "ldr w9, [x16, #264]\n"
        "msr NZCV, x9\n"
        "mov x17, x18\n"
        "ldr x0,  [x16, #0]\n"
        "ldr x1,  [x16, #8]\n"
        "ldr x2,  [x16, #16]\n"
        "ldr x3,  [x16, #24]\n"
        "ldr x4,  [x16, #32]\n"
        "ldr x5,  [x16, #40]\n"
        "ldr x6,  [x16, #48]\n"
        "ldr x7,  [x16, #56]\n"
        "ldr x8,  [x16, #64]\n"
        "ldr x10, [x16, #80]\n"
        "ldr x11, [x16, #88]\n"
        "ldr x12, [x16, #96]\n"
        "ldr x13, [x16, #104]\n"
        "ldr x14, [x16, #112]\n"
        "ldr x15, [x16, #120]\n"
        "ldr x19, [x16, #152]\n"
        "ldr x20, [x16, #160]\n"
        "ldr x21, [x16, #168]\n"
        "ldr x22, [x16, #176]\n"
        "ldr x23, [x16, #184]\n"
        "ldr x24, [x16, #192]\n"
        "ldr x25, [x16, #200]\n"
        "ldr x26, [x16, #208]\n"
        "ldr x27, [x16, #216]\n"
        "ldr x28, [x16, #224]\n"
        "ldr x29, [x16, #232]\n"
        "ldr x30, [x16, #240]\n"
        "br x17\n");
}

int carrick_native_enter(uint64_t entry, uint64_t sp) {
    if (sigsetjmp(carrick_native_env, 1) == 0) {
        carrick_native_env_ready = 1;
        carrick_native_host_tpidr_el0 = carrick_native_read_tpidr_el0();
        if (carrick_native_enter_guest_x18_abi() != 0) {
            carrick_native_env_ready = 0;
            return -1;
        }
        carrick_native_branch(entry, sp);
    }
    carrick_native_env_ready = 0;
    return 1;
}

int carrick_native_resume(void) {
    struct __darwin_mcontext64 *mc = carrick_native_mcontext();
    if (mc == 0 || carrick_native_pending_uc == 0) {
        errno = EINVAL;
        return -1;
    }
    if (sigsetjmp(carrick_native_env, 1) == 0) {
        carrick_native_env_ready = 1;
        siglongjmp(carrick_native_return_env, 1);
    }
    carrick_native_env_ready = 0;
    return 1;
}

int carrick_native_resume_detached_context(void) {
    struct __darwin_mcontext64 *mc = carrick_native_mcontext();
    if (mc == 0) {
        return -1;
    }
    void *pad = carrick_native_prepare_resume_pad(mc->__ss.__pc);
    if (pad == 0) {
        return -1;
    }
    if (sigsetjmp(carrick_native_env, 1) == 0) {
        carrick_native_env_ready = 1;
        carrick_native_pending_uc = 0;
        if (carrick_native_enter_guest_x18_abi() != 0) {
            carrick_native_env_ready = 0;
            return -1;
        }
        carrick_native_branch_mcontext(&mc->__ss, &mc->__ns, pad);
    }
    carrick_native_env_ready = 0;
    return 1;
}

int carrick_native_snapshot_ucontext(struct carrick_native_ucontext_snapshot *out) {
    if (out == 0) {
        return -1;
    }
    memset(out, 0, sizeof(*out));
    struct __darwin_mcontext64 *mc = carrick_native_mcontext();
    if (mc == 0) {
        return -1;
    }
    for (int i = 0; i < 29; i++) {
        out->x[i] = mc->__ss.__x[i];
    }
    out->x[29] = mc->__ss.__fp;
    out->x[30] = mc->__ss.__lr;
    out->sp = mc->__ss.__sp;
    out->pc = mc->__ss.__pc;
    out->pstate = mc->__ss.__cpsr;
    memcpy(out->v, mc->__ns.__v, sizeof(out->v));
    out->fpsr = mc->__ns.__fpsr;
    out->fpcr = mc->__ns.__fpcr;
    out->signal = carrick_native_last_signal;
    out->signal_code = carrick_native_last_signal_code;
    out->fault_address = carrick_native_last_fault_address;
    out->esr = mc->__es.__esr;
    out->far = mc->__es.__far;
    return 0;
}

void carrick_native_set_return(uint64_t value) {
    struct __darwin_mcontext64 *mc = carrick_native_mcontext();
    if (mc != 0) {
        mc->__ss.__x[0] = value;
    }
}

void carrick_native_set_pc(uint64_t pc) {
    struct __darwin_mcontext64 *mc = carrick_native_mcontext();
    if (mc != 0) {
        mc->__ss.__pc = pc;
    }
}

void carrick_native_set_sp(uint64_t sp) {
    struct __darwin_mcontext64 *mc = carrick_native_mcontext();
    if (mc != 0) {
        mc->__ss.__sp = sp;
    }
}

void carrick_native_set_register(uint32_t index, uint64_t value) {
    struct __darwin_mcontext64 *mc = carrick_native_mcontext();
    if (mc == 0) {
        return;
    }
    if (index < 29) {
        mc->__ss.__x[index] = value;
    } else if (index == 29) {
        mc->__ss.__fp = value;
    } else if (index == 30) {
        mc->__ss.__lr = value;
    }
}

void carrick_native_set_vector(uint32_t index, const uint8_t value[16]) {
    struct __darwin_mcontext64 *mc = carrick_native_mcontext();
    if (mc != 0 && index < 32 && value != 0) {
        memcpy(&mc->__ns.__v[index], value, 16);
    }
}

void carrick_native_clear_icache(void *start, size_t len) {
    sys_icache_invalidate(start, len);
}
#else
int carrick_native_install_trap_handler(void) { return -1; }
int carrick_native_seed_ucontext(
    const struct carrick_native_ucontext_snapshot *snapshot) {
    (void)snapshot;
    return -1;
}
int carrick_native_enter(uint64_t entry, uint64_t sp) {
    (void)entry;
    (void)sp;
    return -1;
}
int carrick_native_resume(void) { return -1; }
int carrick_native_resume_detached_context(void) { return -1; }
int carrick_native_snapshot_ucontext(struct carrick_native_ucontext_snapshot *out) {
    (void)out;
    return -1;
}
void carrick_native_set_return(uint64_t value) { (void)value; }
void carrick_native_set_pc(uint64_t pc) { (void)pc; }
void carrick_native_set_sp(uint64_t sp) { (void)sp; }
void carrick_native_set_register(uint32_t index, uint64_t value) {
    (void)index;
    (void)value;
}
void carrick_native_set_vector(uint32_t index, const uint8_t value[16]) {
    (void)index;
    (void)value;
}
void carrick_native_clear_icache(void *start, size_t len) {
    (void)start;
    (void)len;
}
#endif
