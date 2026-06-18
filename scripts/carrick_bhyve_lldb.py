"""carrick_bhyve_lldb.py — lldb plugin for inspecting the carrick bhyve x86_64 guest.

Load into a PYTHON-ENABLED lldb. FreeBSD's base /usr/bin/lldb is Lua-only (no
Python), so the providers and this plugin cannot load there; install the ports
build (`pkg install llvm19`) and use `/usr/local/bin/lldb19`, which is the same
LLVM version, side-by-side, with Python 3.11.

It reads GUEST-PHYSICAL memory through the libvmmapi `vm_map_gpa` FFI via an
inferior call, so it needs no Rust struct introspection — it works against an
optimized release carrick. A breakpoint on `vm_map_gpa` captures the
`struct vmctx *` on the first hit and auto-continues; every command then maps any
GPA on demand.

Commands:
  bhyve-gpa  <gpa> [len]        hexdump len bytes (default 64) at guest-physical <gpa>
  bhyve-walk <va>  [pml4_gpa]   walk the guest x86-64 page tables (root default 0x200000)
                                for <va>, printing each level + the final GPA
  bhyve-ctx                     show the captured vmctx pointer

Typical session (lldb19):
  command script import scripts/carrick_bhyve_lldb.py
  breakpoint set --name vm_run          # stop once the guest starts (all materialized)
  run -- ... carrick run ... /bin/echo HELLO
  bhyve-walk 0xfffffefffa               # argv[1] VA -> GPA
  bhyve-gpa  <that GPA> 16              # what the guest actually reads there
"""

import lldb

# Captured once from the first vm_map_gpa call (struct vmctx *).
_CTX = None

X86_PML4_GPA = 0x200000          # CR3 root the bring-up programs (guest_setup_x86.rs)
PTE_ADDR_MASK = 0x000FFFFFFFFFF000  # bits 51:12 — physical frame of a PTE


def _bp_capture_ctx(frame, bp_loc, internal_dict):
    """Breakpoint callback on vm_map_gpa: grab the vmctx once, never stop."""
    global _CTX
    if _CTX is None:
        v = frame.FindVariable("ctx")
        if v and v.IsValid():
            _CTX = v.GetValueAsUnsigned()
            print("[carrick-bhyve] captured vmctx = 0x%x" % _CTX)
    return False  # auto-continue


def _map_gpa(frame, gpa, n):
    """Return the HOST address backing guest-physical [gpa, gpa+n) via vm_map_gpa."""
    if _CTX is None:
        return None
    expr = ("(unsigned char *)vm_map_gpa((struct vmctx *)0x%xULL, 0x%xULL, %d)"
            % (_CTX, gpa, n))
    val = frame.EvaluateExpression(expr)
    if not val or not val.IsValid() or val.GetError().Fail():
        return None
    host = val.GetValueAsUnsigned()
    return host or None


def _read(exe_ctx, gpa, n):
    frame = exe_ctx.GetFrame()
    host = _map_gpa(frame, gpa, n)
    if not host:
        return None
    err = lldb.SBError()
    data = exe_ctx.GetProcess().ReadMemory(host, n, err)
    return data if err.Success() else None


def _read_u64(exe_ctx, gpa):
    data = _read(exe_ctx, gpa, 8)
    return int.from_bytes(data, "little") if data else None


def cmd_bhyve_gpa(debugger, command, exe_ctx, result, internal_dict):
    if _CTX is None:
        result.AppendMessage("no vmctx captured yet — run past a vm_map_gpa call first")
        return
    args = command.split()
    if not args:
        result.AppendMessage("usage: bhyve-gpa <gpa> [len]")
        return
    gpa = int(args[0], 0)
    n = int(args[1], 0) if len(args) > 1 else 64
    data = _read(exe_ctx, gpa, n)
    if data is None:
        result.AppendMessage("vm_map_gpa/read failed for gpa 0x%x" % gpa)
        return
    for off in range(0, len(data), 16):
        row = data[off:off + 16]
        hexs = " ".join("%02x" % b for b in row)
        asci = "".join(chr(b) if 32 <= b < 127 else "." for b in row)
        result.AppendMessage("0x%010x  %-47s  %s" % (gpa + off, hexs, asci))


def cmd_bhyve_walk(debugger, command, exe_ctx, result, internal_dict):
    if _CTX is None:
        result.AppendMessage("no vmctx captured yet — run past a vm_map_gpa call first")
        return
    args = command.split()
    if not args:
        result.AppendMessage("usage: bhyve-walk <va> [pml4_root_gpa]")
        return
    va = int(args[0], 0)
    root = int(args[1], 0) if len(args) > 1 else X86_PML4_GPA
    names = ("PML4", "PDPT", "PD", "PT")
    shifts = (39, 30, 21, 12)
    gpa = root
    for lvl in range(4):
        idx = (va >> shifts[lvl]) & 0x1FF
        entry = _read_u64(exe_ctx, gpa + idx * 8)
        if entry is None:
            result.AppendMessage("%s[%d]: read failed at table gpa 0x%x"
                                 % (names[lvl], idx, gpa))
            return
        present = entry & 1
        large = lvl in (1, 2) and (entry & 0x80)
        result.AppendMessage(
            "%-4s[%3d] @0x%010x = 0x%016x  P=%d W=%d U=%d%s"
            % (names[lvl], idx, gpa + idx * 8, entry, present,
               (entry >> 1) & 1, (entry >> 2) & 1, "  LARGE" if large else ""))
        if not present:
            result.AppendMessage("  => VA 0x%x UNMAPPED at %s" % (va, names[lvl]))
            return
        if large:
            off_mask = (1 << shifts[lvl]) - 1
            final = (entry & PTE_ADDR_MASK & ~off_mask) + (va & off_mask)
            result.AppendMessage("  => VA 0x%x -> GPA 0x%x (large page)" % (va, final))
            return
        gpa = entry & PTE_ADDR_MASK
    final = gpa + (va & 0xFFF)
    result.AppendMessage("  => VA 0x%x -> GPA 0x%x" % (va, final))


def cmd_bhyve_ctx(debugger, command, exe_ctx, result, internal_dict):
    result.AppendMessage("vmctx = %s" % ("0x%x" % _CTX if _CTX else "<not captured>"))


def __lldb_init_module(debugger, internal_dict):
    target = debugger.GetSelectedTarget()
    if target and target.IsValid():
        bp = target.BreakpointCreateByName("vm_map_gpa")
        bp.SetScriptCallbackFunction("carrick_bhyve_lldb._bp_capture_ctx")
    for fn, name in (("cmd_bhyve_gpa", "bhyve-gpa"),
                     ("cmd_bhyve_walk", "bhyve-walk"),
                     ("cmd_bhyve_ctx", "bhyve-ctx")):
        debugger.HandleCommand("command script add -f carrick_bhyve_lldb.%s %s" % (fn, name))
    print("[carrick-bhyve] loaded: bhyve-gpa, bhyve-walk, bhyve-ctx "
          "(vmctx auto-captured at vm_map_gpa)")
