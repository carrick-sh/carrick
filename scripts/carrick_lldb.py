"""carrick lldb plugin — bridges macOS-host lldb to Linux-guest semantics.

Loading
-------

From an lldb session:

    (lldb) command script import /path/to/carrick/scripts/carrick_lldb.py
    (lldb) carrick load-state /tmp/carrick-debug-state.json

Or from the project's `scripts/carrick.lldb`, which `command script imports`
this file automatically.

Commands
--------

    carrick load-state <path>           # remember a debug-state JSON
    carrick info                         # show the active state's summary
    carrick mappings                     # list guest mappings + perms
    carrick decode-esr <hex>             # ARMv8 ESR_EL1 decoder
    carrick gva <addr>                   # resolve guest VA to region/segment
    carrick where                        # one-line situational dump

The plugin caches the state file path between calls so you only have to
`load-state` once per session. Run `carrick info` to confirm it stuck.
"""

from __future__ import annotations

import json
import os
import re
import shlex
from typing import Any, Optional

import lldb


_STATE: Optional[dict] = None
_STATE_PATH: Optional[str] = None


# ----- helpers -------------------------------------------------------------

def _parse_int(text: str) -> int:
    text = text.strip()
    if text.startswith(("0x", "0X")):
        return int(text, 16)
    if text.startswith(("0b", "0B")):
        return int(text, 2)
    return int(text, 10)


def _fmt_hex(n: int) -> str:
    return f"0x{n:x}"


def _read_state_file(path: str, result: lldb.SBCommandReturnObject) -> Optional[dict]:
    try:
        with open(path, "r") as fh:
            return json.load(fh)
    except FileNotFoundError:
        result.SetError(f"no such file: {path}")
        return None
    except json.JSONDecodeError as exc:
        result.SetError(f"failed to parse {path}: {exc}")
        return None


def _ensure_state(result: lldb.SBCommandReturnObject) -> Optional[dict]:
    global _STATE, _STATE_PATH
    if _STATE is not None:
        return _STATE
    candidate = os.environ.get("CARRICK_DEBUG_STATE_PATH")
    if not candidate:
        for default in ("/tmp/carrick-debug-state.json", "./carrick-debug-state.json"):
            if os.path.exists(default):
                candidate = default
                break
    if candidate and os.path.exists(candidate):
        state = _read_state_file(candidate, result)
        if state is None:
            return None
        _STATE = state
        _STATE_PATH = candidate
        result.AppendMessage(f"(loaded carrick state from {candidate})")
        return state
    result.SetError(
        "no carrick debug state loaded; use `carrick load-state <path>` "
        "after `carrick run --debug-state-path <path>`"
    )
    return None


def _classify_region(region: dict) -> str:
    perms = []
    perms.append("r" if region.get("read") else "-")
    perms.append("w" if region.get("write") else "-")
    perms.append("x" if region.get("execute") else "-")
    return "".join(perms)


def _region_label(region: dict, state: dict) -> str:
    start = region["start"]
    if state.get("el0_trampoline_entry") == start:
        return "EL0 trampoline"
    if state.get("el1_vectors_base") == start:
        return "EL1 vectors"
    if state.get("stage1_page_tables_base") == start:
        return "stage-1 page tables"
    if start == 0x40_0000_0000:
        return "Linux heap arena"
    if start == 0x60_0000_0000:
        return "Linux mmap arena"
    if start == 0x80_0000_0000:
        return "interpreter image (ld-musl) text+data"
    if start == 0x1_0000_0000:
        return "PIE executable image"
    if start >= 0xff_0000_0000:
        return "Linux stack"
    return "(unclassified)"


# ----- ESR_EL1 decoder ----------------------------------------------------

_EC_NAMES = {
    0x00: "Unknown",
    0x01: "WFI/WFE trap",
    0x07: "Trapped SIMD/FP (CPACR_EL1.FPEN)",
    0x15: "SVC (AArch64)",
    0x16: "HVC (AArch64)",
    0x18: "MSR/MRS trap",
    0x20: "Instruction Abort from a lower EL",
    0x21: "Instruction Abort from current EL",
    0x22: "PC alignment fault",
    0x24: "Data Abort from a lower EL",
    0x25: "Data Abort from current EL",
    0x26: "SP alignment fault",
    0x2c: "Trapped FP exception",
    0x2f: "SError interrupt",
}

_DFSC_NAMES = {
    0x00: "Address size fault, level 0",
    0x01: "Address size fault, level 1",
    0x02: "Address size fault, level 2",
    0x03: "Address size fault, level 3",
    0x04: "Translation fault, level 0",
    0x05: "Translation fault, level 1",
    0x06: "Translation fault, level 2",
    0x07: "Translation fault, level 3",
    0x09: "Access flag fault, level 1",
    0x0a: "Access flag fault, level 2",
    0x0b: "Access flag fault, level 3",
    0x0d: "Permission fault, level 1",
    0x0e: "Permission fault, level 2",
    0x0f: "Permission fault, level 3",
    0x10: "Synchronous External abort",
    0x21: "Alignment fault",
    0x30: "TLB conflict abort",
    0x34: "IMPLEMENTATION DEFINED (Lockdown)",
    0x35: "External abort on TT walk, level 1",
    0x36: "External abort on TT walk, level 2",
    0x37: "External abort on TT walk, level 3",
}


def _decode_esr(value: int) -> str:
    ec = (value >> 26) & 0x3f
    il = (value >> 25) & 1
    iss = value & 0x01_FF_FF_FF
    out = [
        f"ESR_EL1 = 0x{value:x}",
        f"  EC  = 0x{ec:02x} ({_EC_NAMES.get(ec, '(other)')})",
        f"  IL  = {il}  ({'32-bit' if il else '16-bit'} instruction syndrome)",
        f"  ISS = 0x{iss:x}",
    ]
    if ec in (0x20, 0x21, 0x24, 0x25):
        dfsc = iss & 0x3f
        wnr = (iss >> 6) & 1
        s1ptw = (iss >> 7) & 1
        ea = (iss >> 9) & 1
        isv = (iss >> 24) & 1
        out.append(f"    DFSC = 0x{dfsc:02x} ({_DFSC_NAMES.get(dfsc, '(other)')})")
        out.append(f"    WnR  = {wnr}  ({'write' if wnr else 'read'})")
        out.append(f"    S1PTW = {s1ptw}")
        out.append(f"    EA (external abort) = {ea}")
        out.append(f"    ISV (syndrome valid) = {isv}")
    return "\n".join(out)


# ----- command implementations --------------------------------------------

def cmd_load_state(debugger, command, exe_ctx, result, internal_dict):
    """carrick load-state <path>"""
    args = shlex.split(command)
    if len(args) != 1:
        result.SetError("usage: carrick load-state <path>")
        return
    state = _read_state_file(args[0], result)
    if state is None:
        return
    global _STATE, _STATE_PATH
    _STATE = state
    _STATE_PATH = args[0]
    n_regions = len(state.get("regions", []))
    result.AppendMessage(
        f"loaded carrick state from {args[0]}: {n_regions} regions, "
        f"entry={_fmt_hex(state.get('entry', 0))}"
    )


def cmd_info(debugger, command, exe_ctx, result, internal_dict):
    """carrick info"""
    state = _ensure_state(result)
    if state is None:
        return
    lines = [
        f"state file: {_STATE_PATH or '(builtin default)'}",
        f"entry:           {_fmt_hex(state.get('entry', 0))}",
        f"initial SP:      {_fmt_hex(state.get('initial_stack_pointer') or 0)}",
        f"EL0 trampoline:  {_fmt_hex(state.get('el0_trampoline_entry') or 0)}",
        f"EL1 vectors:     {_fmt_hex(state.get('el1_vectors_base') or 0)}",
        f"stage-1 PT base: {_fmt_hex(state.get('stage1_page_tables_base') or 0)}",
        f"regions:         {len(state.get('regions', []))}",
    ]
    result.AppendMessage("\n".join(lines))


def cmd_mappings(debugger, command, exe_ctx, result, internal_dict):
    """carrick mappings"""
    state = _ensure_state(result)
    if state is None:
        return
    rows = []
    for region in sorted(state.get("regions", []), key=lambda r: r["start"]):
        start, end = region["start"], region["end"]
        size = end - start
        perms = _classify_region(region)
        label = _region_label(region, state)
        rows.append(
            f"{_fmt_hex(start):>14}  -  {_fmt_hex(end):<14}  "
            f"{perms}  {size:>10} bytes  {label}"
        )
    result.AppendMessage("\n".join(rows))


def cmd_decode_esr(debugger, command, exe_ctx, result, internal_dict):
    """carrick decode-esr <hex>"""
    args = shlex.split(command)
    if len(args) != 1:
        result.SetError("usage: carrick decode-esr <syndrome>")
        return
    try:
        value = _parse_int(args[0])
    except ValueError as exc:
        result.SetError(f"can't parse {args[0]!r}: {exc}")
        return
    result.AppendMessage(_decode_esr(value))


def cmd_gva(debugger, command, exe_ctx, result, internal_dict):
    """carrick gva <addr>"""
    state = _ensure_state(result)
    if state is None:
        return
    args = shlex.split(command)
    if len(args) != 1:
        result.SetError("usage: carrick gva <addr>")
        return
    try:
        addr = _parse_int(args[0])
    except ValueError as exc:
        result.SetError(f"can't parse {args[0]!r}: {exc}")
        return
    for region in state.get("regions", []):
        if region["start"] <= addr < region["end"]:
            offset = addr - region["start"]
            label = _region_label(region, state)
            result.AppendMessage(
                f"{_fmt_hex(addr)} → {label}\n"
                f"  region:  {_fmt_hex(region['start'])} .. {_fmt_hex(region['end'])}\n"
                f"  offset:  {_fmt_hex(offset)} ({offset} bytes into region)\n"
                f"  perms:   {_classify_region(region)}"
            )
            return
    result.AppendMessage(
        f"{_fmt_hex(addr)} not in any tracked carrick region (would fault stage-2)"
    )


def cmd_where(debugger, command, exe_ctx, result, internal_dict):
    """carrick where — read live vCPU regs + classify"""
    state = _ensure_state(result)
    if state is None:
        return
    process = exe_ctx.GetProcess()
    if not process or not process.IsValid():
        result.SetError("no process is being debugged")
        return
    thread = process.GetSelectedThread()
    frame = thread.GetSelectedFrame() if thread else None
    if not frame or not frame.IsValid():
        result.SetError("no active frame")
        return

    # Read the host-side PC/X0/X1/X8 — these are what the trap loop has when
    # we hit a breakpoint inside `run_until_syscall` or `complete_syscall`.
    interp = debugger.GetCommandInterpreter()
    capture = lldb.SBCommandReturnObject()
    interp.HandleCommand("register read pc x0 x1 x8", capture)
    result.AppendMessage(capture.GetOutput() or "(no register output)")
    result.AppendMessage("---")
    result.AppendMessage(
        "tip: this is the *host* lldb's view. For guest vCPU state set "
        "`CARRICK_TRACE_REGS=1` before running carrick and watch the trap "
        "stream on stderr."
    )


# ----- event ring (carrick_runtime::event_ring) ---------------------------
#
# Reads the lock-free in-memory diagnostic ring from a LIVE carrick process or a
# CORE file — the durable, non-perturbing way to see the fork/socket/epoll event
# history of a hung guest process (e.g. the forkserver-from-forkserver deadlock).
# Mirrors the Rust decode in `crates/carrick-runtime/src/event_ring.rs`.

_EVENTRING_N = 8192  # must match event_ring::N

# kind -> (name, formatter(a, b, c))
_EVENTRING_KINDS = {
    1: ("BIND", lambda a, b, c: f"gfd={a} hfd={b} pathhash={c & 0xffffffff:#010x}"),
    2: ("LISTEN", lambda a, b, c: f"hfd={a}"),
    3: ("CONNECT", lambda a, b, c: f"hfd={a} rc={b} pathhash={c & 0xffffffff:#010x}"),
    4: ("ACCEPT", lambda a, b, c: f"listener_hfd={a} ret={b}"),
    5: ("EPADD", lambda a, b, c: f"kq={a} hfd={b} events={c & 0xffffffff:#x}"),
    6: ("EPWAIT", lambda a, b, c: f"kq={a} ready={b} timeout={c}"),
    7: ("FORK", lambda a, b, c: f"child_pid={a}"),
    8: ("EXEC", lambda a, b, c: f"path_present={a}"),
}


def _signed32(x: int) -> int:
    x &= 0xFFFFFFFF
    return x - (1 << 32) if x & 0x8000_0000 else x


def _static_load_addr(target, fullname: str) -> Optional[int]:
    """Load address of a Rust static (e.g. carrick_runtime::event_ring::RING),
    via DWARF globals first then the symbol table — works for live + core.

    Rust mangles statics with a trailing `::h<hash>`, so the demangled symbol is
    `carrick_runtime::event_ring::RING::h0382...`; we match by name COMPONENTS
    (module + base both present) rather than by exact string."""
    module_name = fullname.split("::")[-2]  # "event_ring"
    base = fullname.split("::")[-1]  # "RING" / "IDX"

    var_list = target.FindGlobalVariables(base, 50)
    for i in range(var_list.GetSize()):
        var = var_list.GetValueAtIndex(i)
        name = var.GetName() or ""
        parts = name.split("::")
        if module_name in parts and base in parts:
            addr = var.GetLoadAddress()
            if addr != lldb.LLDB_INVALID_ADDRESS:
                return addr

    for module in target.modules:
        for sym in module:
            name = sym.GetName() or ""
            if "event_ring" not in name:
                continue
            parts = name.split("::")
            if module_name in parts and base in parts:
                addr = sym.GetStartAddress().GetLoadAddress(target)
                if addr != lldb.LLDB_INVALID_ADDRESS:
                    return addr
    return None


def cmd_eventring(debugger, command, exe_ctx, result, internal_dict):
    """carrick eventring — decode the in-memory event ring (live or core)"""
    target = exe_ctx.GetTarget() or debugger.GetSelectedTarget()
    if not target or not target.IsValid():
        result.SetError("no target; `lldb <binary>` (attach) or `lldb -c <core> <binary>`")
        return
    process = exe_ctx.GetProcess() or target.GetProcess()
    if not process or not process.IsValid():
        result.SetError(
            "no process/core loaded. Attach to a live carrick (`lldb -p <pid>`) "
            "or load a core (`lldb -c <core> target/release/carrick`)."
        )
        return
    idx_addr = _static_load_addr(target, "carrick_runtime::event_ring::IDX")
    ring_addr = _static_load_addr(target, "carrick_runtime::event_ring::RING")
    if idx_addr is None or ring_addr is None:
        result.SetError(
            "event_ring RING/IDX symbols not found — the binary must retain "
            "symbols (release keeps them unless explicitly stripped)."
        )
        return
    err = lldb.SBError()
    raw_idx = process.ReadMemory(idx_addr, 8, err)
    if not err.Success():
        result.SetError(f"read IDX @ {_fmt_hex(idx_addr)} failed: {err.GetCString()}")
        return
    total = int.from_bytes(raw_idx, "little")
    count = min(total, _EVENTRING_N)
    start = total - count
    # Bulk-read the whole ring once (128 KiB) so a core read is one round-trip.
    raw_ring = process.ReadMemory(ring_addr, _EVENTRING_N * 16, err)
    if not err.Success():
        result.SetError(f"read RING @ {_fmt_hex(ring_addr)} failed: {err.GetCString()}")
        return
    pid = process.GetProcessID()
    out = [f"# carrick event ring  pid={pid}  total={total}  showing={count}"]
    for k in range(count):
        gi = start + k
        off = (gi % _EVENTRING_N) * 16
        lo = int.from_bytes(raw_ring[off : off + 8], "little")
        hi = int.from_bytes(raw_ring[off + 8 : off + 16], "little")
        a = _signed32(lo & 0xFFFFFFFF)
        b = _signed32(lo >> 32)
        c = _signed32(hi & 0xFFFFFFFF)
        kind = (hi >> 32) & 0xFF
        spec = _EVENTRING_KINDS.get(kind)
        if spec is None:
            continue  # torn/empty slot
        name, fmt = spec
        out.append(f"{gi:6} {name:8} {fmt(a, b, c)}")
    result.AppendMessage("\n".join(out))


# ----- the top-level `carrick` multiplex command --------------------------

_SUBCOMMANDS = {
    "load-state": cmd_load_state,
    "info": cmd_info,
    "mappings": cmd_mappings,
    "decode-esr": cmd_decode_esr,
    "gva": cmd_gva,
    "where": cmd_where,
    "eventring": cmd_eventring,
}


def cmd_carrick(debugger, command, exe_ctx, result, internal_dict):
    """carrick <subcommand> [args...]"""
    parts = command.split(maxsplit=1)
    if not parts:
        result.AppendMessage(
            "subcommands: " + ", ".join(sorted(_SUBCOMMANDS.keys()))
        )
        return
    sub, rest = parts[0], (parts[1] if len(parts) > 1 else "")
    handler = _SUBCOMMANDS.get(sub)
    if not handler:
        result.SetError(
            f"unknown subcommand `{sub}`. "
            f"known: {', '.join(sorted(_SUBCOMMANDS.keys()))}"
        )
        return
    handler(debugger, rest, exe_ctx, result, internal_dict)


# ----- module init --------------------------------------------------------

def __lldb_init_module(debugger, internal_dict):
    debugger.HandleCommand(
        "command script add -f carrick_lldb.cmd_carrick -h "
        "'carrick <subcommand> [args] — guest-aware helpers' carrick"
    )
    print(
        "carrick_lldb: registered `carrick` command. "
        "Run `carrick info` (after `carrick load-state <path>`) to verify."
    )
