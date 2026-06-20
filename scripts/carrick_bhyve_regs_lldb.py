"""bhyve_regs.py — read guest VMCS registers per vCPU via libvmmapi FFI.

lldb19's Rust expression evaluator cannot call Rust methods, so guest VMCS state
(RIP/RSP/FS base) is unreachable via `expr engine.vcpu.get_fs_base()`. But lldb
CAN call C functions, exactly like scripts/carrick_bhyve_lldb.py calls
vm_map_gpa. This adds `bhyve-regs [maxvcpu]`, which for each vCPU id calls
vm_vcpu_open + vm_get_register (RIP/RSP/RBP/R12) + vm_get_desc (FS base) and
prints them — so a clone-thread that jumped to RIP=0 is identified, with its
stack pointer and TLS base, without any Rust introspection.
"""

import lldb

_CTX = None


def _bp_capture_ctx(frame, bp_loc, internal_dict):
    global _CTX
    if _CTX is None:
        v = frame.FindVariable("ctx")
        if v and v.IsValid():
            _CTX = v.GetValueAsUnsigned()
            print("[bhyve-regs] captured vmctx = 0x%x" % _CTX)
    return False


X86_PML4_GPA = 0x200000
PTE_ADDR_MASK = 0x000FFFFFFFFFF000


def _read_gpa(exe_ctx, gpa, n):
    frame = exe_ctx.GetFrame()
    expr = "(unsigned long)(unsigned char *)vm_map_gpa((struct vmctx*)0x%xULL, 0x%xULL, %d)" % (
        _CTX, gpa, n)
    host = _u64(exe_ctx, expr)
    if not host:
        return None
    err = lldb.SBError()
    data = exe_ctx.GetProcess().ReadMemory(host, n, err)
    return data if err.Success() else None


def _read_gpa_u64(exe_ctx, gpa):
    d = _read_gpa(exe_ctx, gpa, 8)
    return int.from_bytes(d, "little") if d else None


def _walk(exe_ctx, va):
    """4-level page-table walk from the shared PML4 -> GPA, or None."""
    gpa = X86_PML4_GPA
    shifts = [39, 30, 21, 12]
    for lvl, sh in enumerate(shifts):
        idx = (va >> sh) & 0x1FF
        ent = _read_gpa_u64(exe_ctx, gpa + idx * 8)
        if ent is None or not (ent & 1):
            return None
        if lvl < 3 and (ent & 0x80):  # 1G/2M large page
            base = ent & PTE_ADDR_MASK
            mask = (1 << sh) - 1
            return (base & ~mask) | (va & mask)
        gpa = ent & PTE_ADDR_MASK
    return gpa | (va & 0xFFF)


def _u64(exe_ctx, expr, dbg=False):
    frame = exe_ctx.GetFrame()
    val = frame.EvaluateExpression(expr)
    if not val or not val.IsValid() or val.GetError().Fail():
        if dbg and val:
            print("[bhyve-regs] expr failed: %s -> %s" % (expr, val.GetError()))
        return None
    return val.GetValueAsUnsigned()


def cmd_bhyve_regs(debugger, command, exe_ctx, result, internal_dict):
    if _CTX is None:
        result.AppendMessage("no vmctx captured yet — run past a vm_map_gpa call first")
        return
    args = command.split()
    maxv = int(args[0]) if args else 6
    # FreeBSD 15 libvmmapi: struct vcpu *vm_vcpu_open(struct vmctx*, int);
    #   int vm_get_register(struct vcpu*, int reg, uint64_t *ret);
    #   int vm_get_desc(struct vcpu*, int reg, uint64_t *base, uint32_t *lim, uint32_t *acc);
    # reg ordinals: RBP=6 RSP=19 RIP=20 R12=11 FS=26
    for vid in range(maxv):
        base = ("(struct vcpu*)vm_vcpu_open((struct vmctx*)0x%xULL, %d)" % (_CTX, vid))
        vptr = _u64(exe_ctx, "(unsigned long)(%s)" % base, dbg=(vid == 0))
        if not vptr:
            result.AppendMessage("vcpu %d: vm_vcpu_open -> NULL" % vid)
            continue
        vc = "(struct vcpu*)0x%xULL" % vptr
        rip = _u64(exe_ctx, "({uint64_t r=0; vm_get_register(%s,20,&r); r;})" % vc, dbg=(vid == 0))
        if rip is None:
            result.AppendMessage("vcpu %d: vm_get_register failed" % vid)
            continue
        rsp = _u64(exe_ctx, "({uint64_t r=0; vm_get_register(%s,19,&r); r;})" % vc)
        rbp = _u64(exe_ctx, "({uint64_t r=0; vm_get_register(%s,6,&r); r;})" % vc)
        r12 = _u64(exe_ctx, "({uint64_t r=0; vm_get_register(%s,11,&r); r;})" % vc)
        fsb = _u64(exe_ctx, "({uint64_t b=0; uint32_t l=0,a=0; vm_get_desc(%s,26,&b,&l,&a); b;})" % vc)
        result.AppendMessage(
            "vcpu %d: rip=0x%x rsp=0x%x rbp=0x%x r12=0x%x fs_base=0x%x"
            % (vid, rip, rsp or 0, rbp or 0, r12 or 0, fsb or 0)
        )
        # Full GPR dump for a child that jumped to RIP=0 — which registers
        # survived the clone vs got lost (RDX = the libc clone3 child fn ptr).
        if rip == 0:
            names = [("rax", 0), ("rbx", 1), ("rcx", 2), ("rdx", 3), ("rsi", 4),
                     ("rdi", 5), ("r8", 7), ("r9", 8), ("r10", 9), ("r11", 10)]
            parts = []
            for nm, ordn in names:
                v = _u64(exe_ctx, "({uint64_t r=0; vm_get_register(%s,%d,&r); r;})" % (vc, ordn))
                parts.append("%s=0x%x" % (nm, v or 0))
            result.AppendMessage("    GPRs: " + " ".join(parts))
        # A clone thread that jumped to RIP=0: the CALL that did it pushed its
        # return address at [RSP]. Dump the stack top + the bytes the child was
        # about to execute (resolve RSP and a few candidate code VAs).
        if rip == 0 and rsp:
            for off in range(0, 64, 8):
                gpa = _walk(exe_ctx, rsp + off)
                v = _read_gpa_u64(exe_ctx, gpa) if gpa else None
                result.AppendMessage(
                    "    [rsp+0x%02x = va 0x%x -> gpa %s] = 0x%x"
                    % (off, rsp + off, ("0x%x" % gpa) if gpa else "??", v or 0)
                )


def __lldb_init_module(debugger, internal_dict):
    target = debugger.GetSelectedTarget()
    if target:
        bp = target.BreakpointCreateByName("vm_map_gpa")
        bp.SetScriptCallbackFunction("bhyve_regs._bp_capture_ctx")
    debugger.HandleCommand("command script add -f bhyve_regs.cmd_bhyve_regs bhyve-regs")
    print("[bhyve-regs] loaded: bhyve-regs [maxvcpu]")
