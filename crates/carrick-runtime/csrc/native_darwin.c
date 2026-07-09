#ifndef _XOPEN_SOURCE
#define _XOPEN_SOURCE 700
#endif

#include <libkern/OSCacheControl.h>
#include <mach-o/dyld.h>
#include <setjmp.h>
#include <signal.h>
#include <stdint.h>
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
    int32_t signal;
    int32_t signal_code;
    uint64_t fault_address;
    uint64_t esr;
    uint64_t far;
};

#if defined(__aarch64__)
static sigjmp_buf carrick_native_env;
static sigjmp_buf carrick_native_signal_env;
static volatile sig_atomic_t carrick_native_env_ready;
static volatile sig_atomic_t carrick_native_signal_env_ready;
static ucontext_t carrick_native_uc;
static ucontext_t *carrick_native_signal_uc;
static unsigned char carrick_native_signal_stack[64 * 1024] __attribute__((aligned(16)));
static uint64_t carrick_native_host_tpidr_el0;
static int32_t carrick_native_last_signal;
static int32_t carrick_native_last_signal_code;
static uint64_t carrick_native_last_fault_address;

static struct __darwin_mcontext64 *carrick_native_mcontext(void) {
    return carrick_native_uc.uc_mcontext;
}

static uint64_t carrick_native_read_tpidr_el0(void) {
    uint64_t value;
    __asm__ volatile("mrs %0, TPIDR_EL0" : "=r"(value));
    return value;
}

__attribute__((noreturn)) static void carrick_native_branch_thread_state64(void *state);

static void carrick_native_write_tpidr_el0(uint64_t value) {
    __asm__ volatile("msr TPIDR_EL0, %0" : : "r"(value) : "memory");
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

    carrick_native_write_tpidr_el0(carrick_native_host_tpidr_el0);
    carrick_native_last_signal = sig;
    carrick_native_last_signal_code = info != 0 ? info->si_code : 0;
    carrick_native_last_fault_address = info != 0 ? (uintptr_t)info->si_addr : 0;
    carrick_native_signal_uc = uc;
    carrick_native_uc = *uc;
    carrick_native_uc.__mcontext_data = *uc->uc_mcontext;
    carrick_native_uc.uc_mcontext = &carrick_native_uc.__mcontext_data;
    if (sigsetjmp(carrick_native_signal_env, 1) != 0) {
        if (carrick_native_signal_uc == 0 || carrick_native_signal_uc->uc_mcontext == 0) {
            _exit(128 + sig);
        }
        *carrick_native_signal_uc->uc_mcontext = carrick_native_uc.__mcontext_data;
        carrick_native_signal_env_ready = 0;
        return;
    }
    carrick_native_signal_env_ready = 1;
    carrick_native_env_ready = 0;
    siglongjmp(carrick_native_env, 1);
}

int carrick_native_install_trap_handler(void) {
    stack_t stack;
    memset(&stack, 0, sizeof(stack));
    stack.ss_sp = carrick_native_signal_stack;
    stack.ss_size = sizeof(carrick_native_signal_stack);
    if (sigaltstack(&stack, 0) != 0) {
        return -1;
    }

    struct sigaction action;
    memset(&action, 0, sizeof(action));
    action.sa_sigaction = carrick_native_trap_handler;
    action.sa_flags = SA_SIGINFO | SA_ONSTACK;
    sigemptyset(&action.sa_mask);
    if (sigaction(SIGTRAP, &action, 0) != 0) {
        return -1;
    }

    memset(&action, 0, sizeof(action));
    action.sa_sigaction = carrick_native_trap_handler;
    action.sa_flags = SA_SIGINFO | SA_ONSTACK;
    sigemptyset(&action.sa_mask);
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

__attribute__((noreturn)) static void carrick_native_branch(uint64_t entry, uint64_t sp) {
    __asm__ volatile(
        "mov sp, %1\n"
        "br %0\n"
        :
        : "r"(entry), "r"(sp)
        : "memory");
    __builtin_unreachable();
}

__attribute__((noreturn)) static void carrick_native_branch_thread_state64(void *state) {
    __asm__ volatile(
        "mov x16, %0\n"
        "ldr x17, [x16, #248]\n"
        "mov sp, x17\n"
        "ldr x0,  [x16, #0]\n"
        "ldr x1,  [x16, #8]\n"
        "ldr x2,  [x16, #16]\n"
        "ldr x3,  [x16, #24]\n"
        "ldr x4,  [x16, #32]\n"
        "ldr x5,  [x16, #40]\n"
        "ldr x6,  [x16, #48]\n"
        "ldr x7,  [x16, #56]\n"
        "ldr x8,  [x16, #64]\n"
        "ldr x9,  [x16, #72]\n"
        "ldr x10, [x16, #80]\n"
        "ldr x11, [x16, #88]\n"
        "ldr x12, [x16, #96]\n"
        "ldr x13, [x16, #104]\n"
        "ldr x14, [x16, #112]\n"
        "ldr x15, [x16, #120]\n"
        "ldr x17, [x16, #136]\n"
        "ldr x18, [x16, #144]\n"
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
        "ldr x16, [x16, #256]\n"
        "br x16\n"
        :
        : "r"(state)
        : "memory");
    __builtin_unreachable();
}

int carrick_native_enter(uint64_t entry, uint64_t sp) {
    if (sigsetjmp(carrick_native_env, 1) == 0) {
        carrick_native_env_ready = 1;
        carrick_native_host_tpidr_el0 = carrick_native_read_tpidr_el0();
        carrick_native_branch(entry, sp);
    }
    carrick_native_env_ready = 0;
    return 1;
}

int carrick_native_resume(void) {
    if (!carrick_native_signal_env_ready) {
        return -1;
    }
    if (sigsetjmp(carrick_native_env, 1) == 0) {
        carrick_native_env_ready = 1;
        siglongjmp(carrick_native_signal_env, 1);
    }
    carrick_native_env_ready = 0;
    return 1;
}

int carrick_native_resume_detached_context(void) {
    if (carrick_native_mcontext() == 0) {
        return -1;
    }
    if (sigsetjmp(carrick_native_env, 1) == 0) {
        carrick_native_env_ready = 1;
        carrick_native_signal_env_ready = 0;
        carrick_native_branch_thread_state64(&carrick_native_uc.__mcontext_data.__ss);
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
