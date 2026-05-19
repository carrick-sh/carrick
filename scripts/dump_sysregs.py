"""LLDB Python helper: dump sys regs right before vcpu.run() via HVF C API.

Use:
    (lldb) command script import /tmp/dump_sysregs.py
    (lldb) dump-sysregs <vcpu_handle>

where <vcpu_handle> is the hv_vcpu_t value (usually 0 for single vCPU).
"""

import lldb

# (lo32, hi32) packed into the encoding HVF uses for sys regs. We just
# care about the names — actual encodings are defined in <Hypervisor/hv_arm64.h>.
SYS_REG_NAMES = {
    "SCTLR_EL1":  0xc080,  # arm64 op0=3 op1=0 CRn=1 CRm=0 op2=0  -> HV encoding differs; rely on framework constants
    "TTBR0_EL1":  0xc100,
    "TCR_EL1":    0xc102,
    "MAIR_EL1":   0xc510,
    "VBAR_EL1":   0xc600,
    "ELR_EL1":    0xc201,
    "SPSR_EL1":   0xc200,
    "ESR_EL1":    0xc290,
    "FAR_EL1":    0xc300,
}

# Apple's hv_sys_reg_t values per <Hypervisor/hv_arm64.h>. These are
# the actual HVF-defined enum values (verified by sym dump).
HV_SYS_REG = {
    "HV_SYS_REG_DBGBVR0_EL1": 0x8004,
    "HV_SYS_REG_SCTLR_EL1":   0xc080,
    "HV_SYS_REG_TTBR0_EL1":   0xc100,
    "HV_SYS_REG_TTBR1_EL1":   0xc101,
    "HV_SYS_REG_TCR_EL1":     0xc102,
    "HV_SYS_REG_MAIR_EL1":    0xc510,
    "HV_SYS_REG_VBAR_EL1":    0xc600,
    "HV_SYS_REG_ELR_EL1":     0xc201,
    "HV_SYS_REG_SPSR_EL1":    0xc200,
    "HV_SYS_REG_ESR_EL1":     0xc290,
    "HV_SYS_REG_FAR_EL1":     0xc300,
    "HV_SYS_REG_CPACR_EL1":   0xc082,
    "HV_SYS_REG_CPSR_alias":  0,  # not a real sys reg
}


def dump_sysregs(debugger, command, result, internal_dict):
    args = command.split()
    if not args:
        result.SetError("usage: dump-sysregs <vcpu_handle_decimal>")
        return
    try:
        vcpu = int(args[0], 0)
    except ValueError:
        result.SetError(f"invalid vcpu handle: {args[0]}")
        return

    ci = debugger.GetCommandInterpreter()
    res = lldb.SBCommandReturnObject()

    result.AppendMessage(f"--- sys regs for vCPU {vcpu} ---")
    for name, reg in HV_SYS_REG.items():
        if reg == 0:
            continue
        expr = (
            f"uint64_t __v = 0xdead; "
            f"int __rc = (int)hv_vcpu_get_sys_reg({vcpu}, (unsigned){reg}, &__v); "
            f"(void)__rc; __v"
        )
        ci.HandleCommand(f"expression --language c++ -- {expr}", res)
        if res.Succeeded():
            out = res.GetOutput().strip()
            # Output format is `(unsigned long) $0 = 18446...`
            val = out.rsplit("=", 1)[-1].strip()
            result.AppendMessage(f"  {name:32s} = {val}")
        else:
            result.AppendMessage(f"  {name:32s} ERR: {res.GetError().strip()}")


def __lldb_init_module(debugger, internal_dict):
    debugger.HandleCommand("command script add -f dump_sysregs.dump_sysregs dump-sysregs")
    print("dump-sysregs command installed")
