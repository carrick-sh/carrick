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
    carrick guest-processes              # summarize guest PID/TID host threads
    carrick guest-threads [pid]          # list guest threads, optionally by PID
    carrick eventring [count|start:count]# decode ring (default: last 128)
    carrick mach-exceptions              # correlate DSR Mach exception ports

The plugin caches the state file path between calls so you only have to
`load-state` once per session. Run `carrick info` to confirm it stuck.
"""

from __future__ import annotations

import json
import os
import re
import shlex
import ctypes
from typing import Any, Optional

import lldb  # type: ignore[import-not-found]  # provided by LLDB at plugin load


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


_GUEST_PROCESS_THREAD_RE = re.compile(r"^guest-pid-(\d+)-tid-(\d+)$")
_GUEST_PROCESS_LEADER_RE = re.compile(r"^guest-pid-(\d+)$")
_GUEST_LEGACY_THREAD_RE = re.compile(r"^guest-tid-(\d+)$")


def _guest_thread_identity(name: Optional[str]) -> Optional[tuple[Optional[int], int]]:
    """Decode the stable guest identity carried by a Carrick host-thread name."""
    if not name:
        return None
    try:
        match = _GUEST_PROCESS_THREAD_RE.fullmatch(name)
        if match:
            return int(match.group(1)), int(match.group(2))
        match = _GUEST_PROCESS_LEADER_RE.fullmatch(name)
        if match:
            pid = int(match.group(1))
            return pid, pid
        match = _GUEST_LEGACY_THREAD_RE.fullmatch(name)
        if match:
            return None, int(match.group(1))
    except (IndexError, ValueError):
        return None
    return None


def _guest_threads(process) -> list[dict[str, Any]]:
    rows = []
    for index in range(process.GetNumThreads()):
        thread = process.GetThreadAtIndex(index)
        identity = _guest_thread_identity(thread.GetName())
        if identity is None:
            continue
        guest_pid, guest_tid = identity
        frame = thread.GetFrameAtIndex(0) if thread.GetNumFrames() else None
        top = "(no frames)"
        if frame is not None and frame.IsValid():
            top = frame.GetDisplayFunctionName() or frame.GetFunctionName() or "(unknown)"
        rows.append(
            {
                "guest_pid": guest_pid,
                "guest_tid": guest_tid,
                "host_tid": thread.GetThreadID(),
                "lldb_index": thread.GetIndexID(),
                "name": thread.GetName() or "(unnamed)",
                "top": top,
            }
        )
    return rows


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
_EVENTRING_SLOT_BYTES = 24  # generation + lo + hi (three u64 cells)
_EVENTRING_DEFAULT_COUNT = 128


def _eventring_complete_generation(logical_index: int) -> int:
    return ((logical_index // _EVENTRING_N) * 2) + 2


def _eventring_slot_error(logical_index: int, before: int, after: int) -> Optional[str]:
    expected = _eventring_complete_generation(logical_index)
    if before > expected:
        return f"OVERWRITTEN expected_gen={expected} observed_gen={before}"
    if before == expected - 1:
        return f"BUSY generation={before}"
    if before != expected:
        return f"GAP expected_gen={expected} observed_gen={before}"
    if after != before:
        return f"TORN before_gen={before} after_gen={after}"
    return None


def _format_hvpatch_wait(pid: int, tid: int, detail: int) -> str:
    packed = detail & 0xFFFFFFFF
    wait_class = {
        1: "fds",
        2: "select",
        3: "poll",
        4: "proc-exit",
        5: "proc-state",
        6: "child",
        7: "futex",
    }.get(packed & 0xFF, "unknown")
    phase = {
        1: "begin",
        2: "ready",
        3: "timed-out",
        4: "interrupted",
        5: "errno",
    }.get((packed >> 8) & 0xFF, "unknown")
    return f"pid={pid} tid={tid} wait={wait_class} phase={phase} fds={packed >> 16}"


def _format_hvpatch_wait_correlation(pid: int, tid: int, detail: int) -> str:
    packed = detail & 0xFFFFFFFF
    wait_class = {
        1: "fds",
        2: "select",
        3: "poll",
        4: "proc-exit",
        5: "proc-state",
        6: "child",
        7: "futex",
    }.get((packed >> 24) & 0xF, "unknown")
    phase = {
        1: "begin",
        2: "ready",
        3: "timed-out",
        4: "interrupted",
        5: "errno",
    }.get((packed >> 28) & 0xF, "unknown")
    return (
        f"pid={pid} tid={tid} id={packed & 0xFFFFFF:#08x} "
        f"wait={wait_class} phase={phase}"
    )


def _format_hvpatch_wait_register(label: str, low: int, high: int, wait_id: int) -> str:
    value = (low & 0xFFFFFFFF) | ((high & 0xFFFFFFFF) << 32)
    return f"id={wait_id & 0xFFFFFF:#08x} {label}={value:#018x}"

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
    9: ("FDOPEN", lambda a, b, c: f"gfd={a} hfd={b} minfd={c}"),
    10: ("FDCLOSE", lambda a, b, c: f"gfd={a} hfd={b}"),
    11: ("ACCEPTER", lambda a, b, c: f"listener_hfd={a} accepted_hfd={b} errno={c}"),
    12: ("EPWFD", lambda a, b, c: f"fd={a} events={b:#x} timeout={c}"),
    13: ("EPMASK", lambda a, b, c: f"origin={a} raw={b:#x} last={c:#x}"),
    14: ("EPMASKFD", lambda a, b, c: f"origin={a} gfd={b} hfd={c}"),
    15: ("EPEDGE", lambda a, b, c: f"gfd={a} edge={b:#x} count={c}"),
    16: (
        "DSRFAULT",
        lambda a, b, c: f"pc={((a & 0xffffffff) | ((b & 0xffffffff) << 32)):#018x} signal={c}",
    ),
    17: (
        "DSRFAULT",
        lambda a, b, c: f"address={((a & 0xffffffff) | ((b & 0xffffffff) << 32)):#018x} esr={c & 0xffffffff:#010x}",
    ),
    18: (
        "DSRFAULT",
        lambda a, b, c: f"sp={((a & 0xffffffff) | ((b & 0xffffffff) << 32)):#018x}",
    ),
    19: (
        "DSRFAULT",
        lambda a, b, c: f"lr={((a & 0xffffffff) | ((b & 0xffffffff) << 32)):#018x}",
    ),
    20: (
        "NSREJECT",
        lambda a, b, c: f"pathhash={a & 0xffffffff:#010x} reasonhash={b & 0xffffffff:#010x} pid={c}",
    ),
    21: ("EFDWRITE", lambda a, b, c: f"hfd={a} before={b & 0xffffffff} after={c & 0xffffffff}"),
    22: ("EFDREAD", lambda a, b, c: f"hfd={a} before={b & 0xffffffff} after={c & 0xffffffff}"),
    23: (
        "FUTEXWAIT",
        lambda a, b, c: f"addr={((a & 0xffffffff) | ((b & 0xffffffff) << 32)):#018x} tid={c}",
    ),
    24: (
        "FUTEXWAKE",
        lambda a, b, c: f"addr={((a & 0xffffffff) | ((b & 0xffffffff) << 32)):#018x} woken={c}",
    ),
    25: (
        "FUTEXEND",
        lambda a, b, c: (
            f"addr={((a & 0xffffffff) | ((b & 0xffffffff) << 32)):#018x} "
            f"outcome={('woken', 'interrupted', 'timed-out')[c] if 0 <= c < 3 else 'unknown'}"
        ),
    ),
    26: (
        "HVPTHREAD",
        lambda a, b, c: (
            f"pid={a} tid={b} phase="
            f"{('unknown', 'cleanup-start', 'registry-removed', 'kicker-unregistered', 'signal-forgotten', 'dispatcher-forgotten', 'vcpu-destroyed', 'loop-return')[c] if 0 <= c < 8 else 'unknown'}"
        ),
    ),
    27: ("HVPWAIT", _format_hvpatch_wait),
    28: ("HVPWAITX", _format_hvpatch_wait_correlation),
    29: ("HVPWAITPC", lambda a, b, c: _format_hvpatch_wait_register("pc", a, b, c)),
    30: ("HVPWAITSP", lambda a, b, c: _format_hvpatch_wait_register("sp", a, b, c)),
    31: ("HVPWAITLR", lambda a, b, c: _format_hvpatch_wait_register("lr", a, b, c)),
    32: (
        "HVPWAITFD",
        lambda a, b, c: f"id={a & 0xFFFFFF:#08x} fd={b} events={c & 0xffffffff:#x}",
    ),
    33: (
        "HVPPEXIT",
        lambda a, b, c: f"pid={a} tid={b} exit={c} publication=begin",
    ),
    34: (
        "HVPPEXIT",
        lambda a, b, c: f"pid={a} tid={b} exit={c} publication=complete",
    ),
    35: (
        "HVPWAITTARGET",
        lambda a, b, c: f"id={a & 0xFFFFFF:#08x} target_pid={b}",
    ),
    36: (
        "EPREADY",
        lambda a, b, c: f"epfd={a} gfd={b} events={c & 0xffffffff:#x}",
    ),
    37: (
        "EPSTALE",
        lambda a, b, c: (
            f"gfd={a} observed_gen={b & 0xffffffff} "
            f"live_gen={c & 0xffffffff if c >= 0 else 'none'}"
        ),
    ),
    38: ("FDOWNER", lambda a, b, c: f"pid={a} tid={b} gfd={c}"),
    39: ("FDREF", lambda a, b, c: f"pid={a} gfd={b} refs_before={c}"),
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


def _selected_process(debugger, exe_ctx, result):
    target = exe_ctx.GetTarget() or debugger.GetSelectedTarget()
    if not target or not target.IsValid():
        result.SetError("no target; `lldb <binary>` (attach) or `lldb -c <core> <binary>`")
        return None
    process = exe_ctx.GetProcess() or target.GetProcess()
    if not process or not process.IsValid():
        result.SetError(
            "no process/core loaded. Attach to a live carrick (`lldb -p <pid>`) "
            "or load a core (`lldb -c <core> target/release/carrick`)."
        )
        return None
    return process


def cmd_guest_processes(debugger, command, exe_ctx, result, internal_dict):
    """carrick guest-processes — summarize guest processes in a live target/core."""
    if command.strip():
        result.SetError("usage: carrick guest-processes")
        return
    process = _selected_process(debugger, exe_ctx, result)
    if process is None:
        return
    rows = _guest_threads(process)
    grouped: dict[int, list[dict[str, Any]]] = {}
    legacy = []
    for row in rows:
        guest_pid = row["guest_pid"]
        if guest_pid is None:
            legacy.append(row)
        else:
            grouped.setdefault(guest_pid, []).append(row)
    lines = [
        f"# carrick guest processes host_pid={process.GetProcessID()} "
        f"processes={len(grouped)} threads={len(rows)} legacy_unowned={len(legacy)}"
    ]
    for guest_pid, threads in sorted(grouped.items()):
        tids = ",".join(str(row["guest_tid"]) for row in sorted(threads, key=lambda r: r["guest_tid"]))
        tops = sorted({row["top"] for row in threads})
        lines.append(
            f"pid={guest_pid:<6} threads={len(threads):<3} tids={tids} "
            f"top={'; '.join(tops)}"
        )
    if legacy:
        tids = ",".join(str(row["guest_tid"]) for row in legacy)
        lines.append(f"legacy-unowned tids={tids}")
    if not rows:
        lines.append(
            "(no guest threads found; use a binary with process-aware thread names "
            "or attach after guest startup)"
        )
    result.AppendMessage("\n".join(lines))


def cmd_guest_threads(debugger, command, exe_ctx, result, internal_dict):
    """carrick guest-threads [pid] — list guest threads in a live target/core."""
    args = shlex.split(command)
    if len(args) > 1:
        result.SetError("usage: carrick guest-threads [pid]")
        return
    guest_pid_filter = None
    if args:
        try:
            guest_pid_filter = _parse_int(args[0])
        except ValueError as exc:
            result.SetError(f"can't parse guest pid {args[0]!r}: {exc}")
            return
        if guest_pid_filter <= 0:
            result.SetError("guest pid must be positive")
            return
    process = _selected_process(debugger, exe_ctx, result)
    if process is None:
        return
    rows = _guest_threads(process)
    if guest_pid_filter is not None:
        rows = [row for row in rows if row["guest_pid"] == guest_pid_filter]
    lines = [
        f"# carrick guest threads host_pid={process.GetProcessID()} "
        f"guest_pid={guest_pid_filter if guest_pid_filter is not None else '*'} "
        f"count={len(rows)}"
    ]
    for row in sorted(rows, key=lambda r: ((r["guest_pid"] or -1), r["guest_tid"])):
        pid_text = str(row["guest_pid"]) if row["guest_pid"] is not None else "?"
        lines.append(
            f"pid={pid_text:<6} tid={row['guest_tid']:<6} "
            f"lldb=#{row['lldb_index']:<3} host_tid={_fmt_hex(row['host_tid'])} "
            f"top={row['top']}"
        )
    if not rows:
        lines.append("(no matching guest threads)")
    result.AppendMessage("\n".join(lines))


def cmd_eventring(debugger, command, exe_ctx, result, internal_dict):
    """carrick eventring [COUNT|START:COUNT] — decode the event ring."""
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
    requested = _EVENTRING_DEFAULT_COUNT
    requested_start = None
    argument = command.strip()
    if argument:
        try:
            if ":" in argument:
                start_text, count_text = argument.split(":", 1)
                requested_start = int(start_text, 10)
                requested = int(count_text, 10)
            else:
                requested = int(argument, 10)
        except ValueError:
            result.SetError("usage: carrick eventring [positive-count|start:positive-count]")
            return
        if requested <= 0 or requested_start is not None and requested_start < 0:
            result.SetError("eventring count must be positive")
            return
    oldest = max(0, total - _EVENTRING_N)
    if requested_start is None:
        count = min(total, _EVENTRING_N, requested)
        start = total - count
    else:
        start = max(requested_start, oldest)
        count = min(requested, max(0, total - start))
    # Two bulk snapshots validate slot generations around payload reads. A core
    # is stable; a live target can change between reads and is reported TORN.
    ring_bytes = _EVENTRING_N * _EVENTRING_SLOT_BYTES
    raw_ring = process.ReadMemory(ring_addr, ring_bytes, err)
    if not err.Success():
        result.SetError(f"read RING @ {_fmt_hex(ring_addr)} failed: {err.GetCString()}")
        return
    second_err = lldb.SBError()
    raw_ring_after = process.ReadMemory(ring_addr, ring_bytes, second_err)
    if not second_err.Success():
        result.SetError(
            f"second RING read @ {_fmt_hex(ring_addr)} failed: {second_err.GetCString()}"
        )
        return
    pid = process.GetProcessID()
    out = [
        f"# carrick event ring  pid={pid}  total={total}  "
        f"showing={count}  start={start}  oldest={oldest}"
    ]
    errors = 0
    for k in range(count):
        gi = start + k
        off = (gi % _EVENTRING_N) * _EVENTRING_SLOT_BYTES
        before = int.from_bytes(raw_ring[off : off + 8], "little")
        lo = int.from_bytes(raw_ring[off + 8 : off + 16], "little")
        hi = int.from_bytes(raw_ring[off + 16 : off + 24], "little")
        after = int.from_bytes(raw_ring_after[off : off + 8], "little")
        slot_error = _eventring_slot_error(gi, before, after)
        if slot_error is not None:
            errors += 1
            out.append(f"{gi:6} ERROR    {slot_error}")
            continue
        a = _signed32(lo & 0xFFFFFFFF)
        b = _signed32(lo >> 32)
        c = _signed32(hi & 0xFFFFFFFF)
        kind = (hi >> 32) & 0xFF
        spec = _EVENTRING_KINDS.get(kind)
        if spec is None:
            errors += 1
            out.append(f"{gi:6} ERROR    UNKNOWN kind={kind}")
            continue
        name, fmt = spec
        out.append(f"{gi:6} {name:8} {fmt(a, b, c)}")
    out[0] += f"  errors={errors}"
    result.AppendMessage("\n".join(out))


# ----- native DSR Mach exception registrations ----------------------------

def _c_global_load_addr(target, name: str) -> Optional[int]:
    """Return the load address of a C global, including file-local statics."""
    variables = target.FindGlobalVariables(name, 50)
    for i in range(variables.GetSize()):
        variable = variables.GetValueAtIndex(i)
        if variable.GetName() != name:
            continue
        addr = variable.GetLoadAddress()
        if addr != lldb.LLDB_INVALID_ADDRESS:
            return addr
    for module in target.modules:
        for symbol in module:
            if symbol.GetName() != name:
                continue
            addr = symbol.GetStartAddress().GetLoadAddress(target)
            if addr != lldb.LLDB_INVALID_ADDRESS:
                return addr
    return None


def _registration_field(value, name: str, signed: bool = False) -> int:
    field = value.GetChildMemberWithName(name)
    if not field or not field.IsValid():
        raise RuntimeError(f"registration field `{name}` is unavailable")
    return field.GetValueAsSigned() if signed else field.GetValueAsUnsigned()


def cmd_mach_exceptions(debugger, command, exe_ctx, result, internal_dict):
    """carrick mach-exceptions — inspect native DSR exception-port routing.

    This is a live-process diagnostic. It reads Carrick's registration list
    without running the inferior, then uses the debugger process's privileged
    task port to ask XNU which receive rights are members of Carrick's port
    set. The kernel query is observational but requires a sudo/root LLDB attach.
    """
    if command.strip():
        result.SetError("usage: carrick mach-exceptions")
        return
    target = exe_ctx.GetTarget() or debugger.GetSelectedTarget()
    process = exe_ctx.GetProcess() or (target.GetProcess() if target else None)
    if not target or not target.IsValid() or not process or not process.IsValid():
        result.SetError("no live carrick process is attached")
        return

    set_addr = _c_global_load_addr(
        target, "carrick_native_direct_exception_port_set"
    )
    registrations_addr = _c_global_load_addr(
        target, "carrick_native_direct_exception_registrations"
    )
    if set_addr is None or registrations_addr is None:
        result.SetError(
            "native DSR Mach exception globals are unavailable; use an unstripped "
            "Carrick binary built with debug information"
        )
        return

    err = lldb.SBError()
    port_set = process.ReadUnsignedFromMemory(set_addr, 4, err)
    if not err.Success():
        result.SetError(
            f"read port set @ {_fmt_hex(set_addr)} failed: {err.GetCString()}"
        )
        return
    head = process.ReadPointerFromMemory(registrations_addr, err)
    if not err.Success():
        result.SetError(
            f"read registrations @ {_fmt_hex(registrations_addr)} failed: "
            f"{err.GetCString()}"
        )
        return

    registration_type = target.FindFirstType(
        "carrick_native_direct_exception_registration"
    )
    if not registration_type or not registration_type.IsValid():
        result.SetError("native DSR Mach exception registration type is unavailable")
        return
    slots_type = target.FindFirstType("carrick_native_direct_slots")
    if not slots_type or not slots_type.IsValid():
        result.SetError("native DSR direct-slot type is unavailable")
        return

    registrations = []
    address = head
    seen = set()
    while address and address not in seen and len(registrations) < 64:
        seen.add(address)
        value = target.CreateValueFromAddress(
            "registration", target.ResolveLoadAddress(address), registration_type
        )
        if not value or not value.IsValid():
            result.SetError(f"cannot decode registration @ {_fmt_hex(address)}")
            return
        try:
            slots_address = _registration_field(value, "slots")
            slots = target.CreateValueFromAddress(
                "slots", target.ResolveLoadAddress(slots_address), slots_type
            )
            telemetry = slots.GetChildMemberWithName("exception_telemetry")
            if not telemetry or not telemetry.IsValid():
                raise RuntimeError("direct-slot exception telemetry is unavailable")
            registration = {
                "address": address,
                "next": _registration_field(value, "next"),
                "slots": slots_address,
                "exception_port": _registration_field(value, "exception_port"),
                "thread_port": _registration_field(value, "thread_port"),
                "fault_pc": _registration_field(value, "fault_pc"),
                "fault_address": _registration_field(value, "fault_address"),
                "recovery_pending": _registration_field(
                    value, "recovery_pending", signed=True
                ),
                "exception_entries": _registration_field(
                    telemetry, "exception_entries"
                ),
                "recovery_services": _registration_field(
                    telemetry, "recovery_services"
                ),
                "bad_access_entries": _registration_field(
                    telemetry, "bad_access_entries"
                ),
                "breakpoint_entries": _registration_field(
                    telemetry, "breakpoint_entries"
                ),
                "execute_switches": _registration_field(
                    telemetry, "execute_switches"
                ),
                "write_switches": _registration_field(
                    telemetry, "write_switches"
                ),
                "failures": _registration_field(telemetry, "failures"),
                "last_status": _registration_field(telemetry, "last_status"),
            }
        except RuntimeError as exc:
            result.SetError(str(exc))
            return
        registrations.append(registration)
        address = registration["next"]
    if address:
        result.SetError("registration list is cyclic or exceeds 64 entries")
        return

    # These are public libSystem/Mach calls made by the debugger process, not
    # by the stopped inferior. mach_port_get_set_status's first argument is a
    # task port, so `port_set` is interpreted in Carrick's IPC namespace.
    libsystem = ctypes.CDLL(None)
    mach_task_self = ctypes.c_uint.in_dll(libsystem, "mach_task_self_").value
    task_for_pid = libsystem.task_for_pid
    task_for_pid.argtypes = [ctypes.c_uint, ctypes.c_int, ctypes.POINTER(ctypes.c_uint)]
    task_for_pid.restype = ctypes.c_int
    get_set_status = libsystem.mach_port_get_set_status
    get_set_status.argtypes = [
        ctypes.c_uint,
        ctypes.c_uint,
        ctypes.POINTER(ctypes.POINTER(ctypes.c_uint)),
        ctypes.POINTER(ctypes.c_uint),
    ]
    get_set_status.restype = ctypes.c_int
    extract_right = libsystem.mach_port_extract_right
    extract_right.argtypes = [
        ctypes.c_uint,
        ctypes.c_uint,
        ctypes.c_uint,
        ctypes.POINTER(ctypes.c_uint),
        ctypes.POINTER(ctypes.c_uint),
    ]
    extract_right.restype = ctypes.c_int
    get_exception_ports = libsystem.thread_get_exception_ports
    get_exception_ports.argtypes = [
        ctypes.c_uint,
        ctypes.c_uint,
        ctypes.POINTER(ctypes.c_uint),
        ctypes.POINTER(ctypes.c_uint),
        ctypes.POINTER(ctypes.c_uint),
        ctypes.POINTER(ctypes.c_int),
        ctypes.POINTER(ctypes.c_int),
    ]
    get_exception_ports.restype = ctypes.c_int
    thread_info = libsystem.thread_info
    thread_info.argtypes = [
        ctypes.c_uint,
        ctypes.c_int,
        ctypes.POINTER(ctypes.c_int),
        ctypes.POINTER(ctypes.c_uint),
    ]
    thread_info.restype = ctypes.c_int
    get_port_attributes = libsystem.mach_port_get_attributes
    get_port_attributes.argtypes = [
        ctypes.c_uint,
        ctypes.c_uint,
        ctypes.c_int,
        ctypes.POINTER(ctypes.c_uint),
        ctypes.POINTER(ctypes.c_uint),
    ]
    get_port_attributes.restype = ctypes.c_int

    task = ctypes.c_uint(0)
    kr = task_for_pid(mach_task_self, process.GetProcessID(), ctypes.byref(task))
    if kr != 0:
        result.SetError(
            f"task_for_pid({process.GetProcessID()}) failed: {_fmt_hex(kr)}; "
            "attach from sudo/root LLDB"
        )
        return

    members_ptr = ctypes.POINTER(ctypes.c_uint)()
    member_count = ctypes.c_uint(0)
    mach_port_deallocate = libsystem.mach_port_deallocate
    mach_port_deallocate.argtypes = [ctypes.c_uint, ctypes.c_uint]
    mach_port_deallocate.restype = ctypes.c_int
    try:
        kr = get_set_status(
            task.value, port_set, ctypes.byref(members_ptr), ctypes.byref(member_count)
        )
        if kr != 0:
            result.SetError(
                f"mach_port_get_set_status(set={_fmt_hex(port_set)}) failed: "
                f"{_fmt_hex(kr)}"
            )
            return
        members = {members_ptr[i] for i in range(member_count.value)}

        # Port names are task-local. Extract one send right for both the
        # registered exception receive right and registered thread right into
        # LLDB's task. thread_get_exception_ports then returns handler send
        # rights in that same namespace, where identical kernel ports coalesce
        # to the same name and can be compared directly.
        copy_send = 19  # MACH_MSG_TYPE_COPY_SEND
        exception_mask = (1 << 1) | (1 << 2) | (1 << 6)
        bindings = []
        for registration in registrations:
            receive_status = (ctypes.c_uint * 10)()
            receive_status_count = ctypes.c_uint(10)
            status_kr = get_port_attributes(
                task.value,
                registration["exception_port"],
                2,  # MACH_PORT_RECEIVE_STATUS
                receive_status,
                ctypes.byref(receive_status_count),
            )
            exception_right = ctypes.c_uint(0)
            exception_type = ctypes.c_uint(0)
            thread_right = ctypes.c_uint(0)
            thread_type = ctypes.c_uint(0)
            exception_kr = extract_right(
                task.value,
                registration["exception_port"],
                copy_send,
                ctypes.byref(exception_right),
                ctypes.byref(exception_type),
            )
            thread_kr = extract_right(
                task.value,
                registration["thread_port"],
                copy_send,
                ctypes.byref(thread_right),
                ctypes.byref(thread_type),
            )
            query_kr = -1
            matched_mask = 0
            masks = (ctypes.c_uint * 32)()
            handlers = (ctypes.c_uint * 32)()
            behaviors = (ctypes.c_int * 32)()
            flavors = (ctypes.c_int * 32)()
            count = ctypes.c_uint(32)
            thread_id = 0
            run_state = 0
            suspend_count = 0
            if exception_kr == 0 and thread_kr == 0:
                identifier_words = (ctypes.c_int * 6)()
                identifier_count = ctypes.c_uint(6)
                identifier_kr = thread_info(
                    thread_right.value,
                    4,  # THREAD_IDENTIFIER_INFO
                    identifier_words,
                    ctypes.byref(identifier_count),
                )
                if identifier_kr == 0:
                    identifier_bytes = bytes(identifier_words)
                    thread_id = int.from_bytes(identifier_bytes[0:8], "little")
                basic_words = (ctypes.c_int * 10)()
                basic_count = ctypes.c_uint(10)
                basic_kr = thread_info(
                    thread_right.value,
                    3,  # THREAD_BASIC_INFO
                    basic_words,
                    ctypes.byref(basic_count),
                )
                if basic_kr == 0:
                    run_state = basic_words[6]
                    suspend_count = basic_words[8]
                query_kr = get_exception_ports(
                    thread_right.value,
                    exception_mask,
                    masks,
                    ctypes.byref(count),
                    handlers,
                    behaviors,
                    flavors,
                )
                if query_kr == 0:
                    for i in range(count.value):
                        if handlers[i] == exception_right.value:
                            matched_mask |= masks[i] & exception_mask
            bindings.append(
                {
                    "status_kr": status_kr,
                    "pset_count": receive_status[0] if status_kr == 0 else 0,
                    "sequence": receive_status[1] if status_kr == 0 else 0,
                    "queue_limit": receive_status[3] if status_kr == 0 else 0,
                    "message_count": receive_status[4] if status_kr == 0 else 0,
                    "exception_kr": exception_kr,
                    "thread_kr": thread_kr,
                    "query_kr": query_kr,
                    "matched_mask": matched_mask,
                    "thread_id": thread_id,
                    "run_state": run_state,
                    "suspend_count": suspend_count,
                }
            )
            if query_kr == 0:
                for i in range(count.value):
                    if handlers[i]:
                        mach_port_deallocate(mach_task_self, handlers[i])
            if thread_right.value:
                mach_port_deallocate(mach_task_self, thread_right.value)
            if exception_right.value:
                mach_port_deallocate(mach_task_self, exception_right.value)
    finally:
        if bool(members_ptr):
            vm_deallocate = libsystem.vm_deallocate
            vm_deallocate.argtypes = [ctypes.c_uint, ctypes.c_uint64, ctypes.c_uint64]
            vm_deallocate.restype = ctypes.c_int
            vm_deallocate(
                mach_task_self,
                ctypes.cast(members_ptr, ctypes.c_void_p).value,
                member_count.value * ctypes.sizeof(ctypes.c_uint),
            )
        mach_port_deallocate(mach_task_self, task.value)

    lines = [
        f"# native DSR Mach exceptions pid={process.GetProcessID()} "
        f"set={_fmt_hex(port_set)} members={len(members)} "
        f"registrations={len(registrations)}"
    ]
    for index, registration in enumerate(registrations):
        exception_port = registration["exception_port"]
        member = "member" if exception_port in members else "MISSING"
        binding = bindings[index]
        if (
            binding["exception_kr"] == 0
            and binding["thread_kr"] == 0
            and binding["query_kr"] == 0
        ):
            bound = (
                "bound"
                if binding["matched_mask"] == exception_mask
                else f"BIND-MISSING({_fmt_hex(binding['matched_mask'])})"
            )
        else:
            bound = (
                f"BIND-ERROR(e={_fmt_hex(binding['exception_kr'])},"
                f"t={_fmt_hex(binding['thread_kr'])},"
                f"q={_fmt_hex(binding['query_kr'])})"
            )
        lines.append(
            f"{index:2} reg={_fmt_hex(registration['address'])} "
            f"slots={_fmt_hex(registration['slots'])} "
            f"eport={_fmt_hex(exception_port)} {member:7} "
            f"tport={_fmt_hex(registration['thread_port'])} "
            f"tid={_fmt_hex(binding['thread_id'])} "
            f"run={binding['run_state']} suspend={binding['suspend_count']} "
            f"{bound} "
            f"queue={binding['message_count']}/{binding['queue_limit']} "
            f"seq={binding['sequence']} psets={binding['pset_count']} "
            f"pending={registration['recovery_pending']} "
            f"fault_pc={_fmt_hex(registration['fault_pc'])} "
            f"fault_addr={_fmt_hex(registration['fault_address'])} "
            f"entries={registration['exception_entries']} "
            f"services={registration['recovery_services']} "
            f"bad_access={registration['bad_access_entries']} "
            f"brk={registration['breakpoint_entries']} "
            f"x={registration['execute_switches']} "
            f"w={registration['write_switches']} "
            f"fail={registration['failures']} "
            f"status={registration['last_status']}"
        )
    extra = sorted(members - {r["exception_port"] for r in registrations})
    if extra:
        lines.append("unregistered members: " + ", ".join(map(_fmt_hex, extra)))
    result.AppendMessage("\n".join(lines))


# ----- the top-level `carrick` multiplex command --------------------------

_SUBCOMMANDS = {
    "load-state": cmd_load_state,
    "info": cmd_info,
    "mappings": cmd_mappings,
    "decode-esr": cmd_decode_esr,
    "gva": cmd_gva,
    "where": cmd_where,
    "guest-processes": cmd_guest_processes,
    "guest-threads": cmd_guest_threads,
    "eventring": cmd_eventring,
    "mach-exceptions": cmd_mach_exceptions,
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
