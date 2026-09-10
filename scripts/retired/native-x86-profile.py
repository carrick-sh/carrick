#!/usr/bin/env python3.11
"""Safely profile an already-running FreeBSD/amd64 Carrick native process.

The profiler uses only kernel DTrace providers selected by a numeric PID. It
never grabs the tracee (`dtrace -p`), enables pid-provider probes, or patches
Carrick USDT sites; those fasttrap paths are unsafe to detach from a continuing
native process. Host stacks cannot be unwound while DSR owns RSP, so the tool
samples RIP directly and reads the current guest PC from the versioned gateway
layout reported by the matching Carrick binary.
"""

from __future__ import annotations

import argparse
from collections import Counter
from dataclasses import asdict, dataclass
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
from typing import Iterable

SCHEMA = "carrick.native-x86-profile.v1"
LAYOUT_SCHEMA = "carrick.native-x86-profiler-layout.v1"
PROTOCOL = "NXPROF1"


class ProfileError(RuntimeError):
    pass


@dataclass(frozen=True)
class Mapping:
    start: int
    end: int
    permissions: str
    path: str

    def contains(self, address: int) -> bool:
        return self.start <= address < self.end


@dataclass(frozen=True)
class Layout:
    version: int
    context_register: str
    context_size: int
    exit_resume_offset: int


@dataclass(frozen=True)
class Symbol:
    object: str
    address: str
    relative_address: str
    symbol: str


@dataclass
class Capture:
    syscalls: Counter[str]
    host_pcs: Counter[int]
    guest_pcs: Counter[int]
    memcpy_callers: Counter[int]
    memcpy_sizes: Counter[int]
    new_children: Counter[int]


def run_text(argv: list[str], *, timeout: int = 10) -> str:
    result = subprocess.run(argv, text=True, capture_output=True, timeout=timeout, check=False)
    if result.returncode != 0:
        detail = result.stderr.strip() or result.stdout.strip()
        raise ProfileError(f"{' '.join(argv)} failed ({result.returncode}): {detail}")
    return result.stdout


def process_executable(pid: int) -> Path:
    lines = run_text(["procstat", "-b", str(pid)]).splitlines()
    for line in lines[1:]:
        fields = line.split(maxsplit=3)
        if len(fields) == 4 and fields[0] == str(pid):
            return Path(fields[3])
    raise ProfileError(f"procstat did not report an executable for pid {pid}")


def live_executable_handle(pid: int, reported: Path) -> Path:
    # FreeBSD linprocfs is a magic handle to the vnode the process actually
    # executes. Unlike the reported pathname it still names the old inode when
    # a developer rebuilds `target/release/carrick` during a long run, so the
    # queried layout and symbols cannot silently come from a newer binary.
    candidate = Path("/compat/linux/proc") / str(pid) / "exe"
    try:
        if candidate.is_file():
            return candidate
    except OSError:
        pass
    return reported


def parse_procstat_mappings(text: str, pid: int) -> list[Mapping]:
    mappings: list[Mapping] = []
    for line in text.splitlines():
        fields = line.split(maxsplit=10)
        if len(fields) < 10 or fields[0] != str(pid):
            continue
        try:
            start = int(fields[1], 16)
            end = int(fields[2], 16)
        except ValueError:
            continue
        path = fields[10] if len(fields) == 11 else ""
        mappings.append(Mapping(start, end, fields[3], path))
    if not mappings:
        raise ProfileError(f"procstat returned no mappings for pid {pid}")
    return mappings


def process_mappings(pid: int) -> list[Mapping]:
    return parse_procstat_mappings(run_text(["procstat", "-v", str(pid)]), pid)


def parse_process_tree(text: str, root_pid: int) -> list[int]:
    children: dict[int, list[int]] = {}
    for line in text.splitlines():
        fields = line.split()
        if len(fields) != 2:
            continue
        try:
            pid, parent = (int(field, 10) for field in fields)
        except ValueError:
            continue
        children.setdefault(parent, []).append(pid)
    found = [root_pid]
    cursor = 0
    while cursor < len(found):
        found.extend(sorted(children.get(found[cursor], [])))
        cursor += 1
    return found


def process_tree(root_pid: int) -> list[int]:
    # FreeBSD ps requires a separate `-o` for each headerless column; GNU's
    # comma form prints only one column here and silently loses ancestry.
    return parse_process_tree(
        run_text(["ps", "-axo", "pid=", "-o", "ppid="]), root_pid
    )


def initial_tree_mappings(pids: Iterable[int], root_pid: int) -> list[Mapping]:
    combined: dict[tuple[int, int, str, str], Mapping] = {}
    for pid in pids:
        try:
            mappings = process_mappings(pid)
        except ProfileError:
            if pid == root_pid:
                raise
            continue
        for mapping in mappings:
            combined[(mapping.start, mapping.end, mapping.permissions, mapping.path)] = mapping
    return list(combined.values())


def jit_mappings(mappings: Iterable[Mapping]) -> list[Mapping]:
    found = [
        mapping
        for mapping in mappings
        if "x" in mapping.permissions and mapping.path.startswith("posixshm@")
    ]
    if not found:
        raise ProfileError("no executable POSIX-SHM native JIT mapping found")
    return found


def load_layout(carrick: Path) -> Layout:
    try:
        raw = json.loads(run_text([str(carrick), "debug", "native-x86-layout"]))
    except (json.JSONDecodeError, OSError) as error:
        raise ProfileError(f"failed to read native-x86 layout from {carrick}: {error}") from error
    if raw.get("schema") != LAYOUT_SCHEMA or raw.get("version") != 1:
        raise ProfileError(f"unsupported native-x86 profiler layout: {raw!r}")
    if raw.get("context_register") != "R_R15":
        raise ProfileError(f"unsupported DSR context register: {raw.get('context_register')!r}")
    try:
        layout = Layout(
            version=int(raw["version"]),
            context_register=str(raw["context_register"]),
            context_size=int(raw["context_size"]),
            exit_resume_offset=int(raw["exit_resume_offset"]),
        )
    except (KeyError, TypeError, ValueError) as error:
        raise ProfileError(f"malformed native-x86 profiler layout: {raw!r}") from error
    if not (0 <= layout.exit_resume_offset <= layout.context_size - 8):
        raise ProfileError(f"exit-resume offset falls outside context: {layout}")
    return layout


def object_base(mappings: Iterable[Mapping], path: str) -> int:
    starts = [mapping.start for mapping in mappings if mapping.path == path]
    if not starts:
        raise ProfileError(f"no mapping found for object {path}")
    return min(starts)


def find_libc(mappings: Iterable[Mapping]) -> str | None:
    candidates = sorted(
        {
            mapping.path
            for mapping in mappings
            if mapping.path and Path(mapping.path).name.startswith("libc.so")
        }
    )
    return candidates[0] if candidates else None


def elf_function(path: str, name: str) -> tuple[int, int] | None:
    output = run_text(["readelf", "-Ws", path])
    for line in output.splitlines():
        fields = line.split()
        if len(fields) < 8 or fields[3] != "FUNC":
            continue
        symbol_name = fields[-1].split("@", 1)[0]
        if symbol_name != name:
            continue
        try:
            return int(fields[1], 16), int(fields[2], 10)
        except ValueError:
            continue
    return None


def disjunction(ranges: Iterable[tuple[int, int]], expression: str) -> str:
    terms = [f"({expression} >= {start:#x} && {expression} < {end:#x})" for start, end in ranges]
    if not terms:
        return "0"
    return " || ".join(terms)


def build_d_script(
    pids: list[int],
    seconds: int,
    frequency: int,
    layout: Layout,
    jit: list[Mapping],
    memcpy_range: tuple[int, int] | None,
) -> str:
    if not pids:
        raise ProfileError("profile needs at least one pid")
    tracked_init = "\n".join(f"    tracked[{pid}] = 1;" for pid in sorted(set(pids)))
    jit_predicate = disjunction(((mapping.start, mapping.end) for mapping in jit), "uregs[R_RIP]")
    memcpy_clause = ""
    memcpy_output = ""
    memcpy_trunc = ""
    if memcpy_range is not None:
        memcpy_start, memcpy_end = memcpy_range
        memcpy_clause = f"""
profile-{frequency}
/tracked[pid] && uregs[R_RIP] >= {memcpy_start:#x} && uregs[R_RIP] < {memcpy_end:#x}/
{{
    this->retp = (uint64_t *)copyin(uregs[R_RSP], 8);
    @memcpy_caller[*this->retp] = count();
    @memcpy_size[uregs[R_RDX]] = count();
}}
"""
        memcpy_output = f"""
    printa(\"{PROTOCOL}|memcpy-caller|pc=%#x|count=%@d\\n\", @memcpy_caller);
    printa(\"{PROTOCOL}|memcpy-size|bytes=%d|count=%@d\\n\", @memcpy_size);"""
        memcpy_trunc = """
    trunc(@memcpy_caller);
    trunc(@memcpy_size);"""
    return f"""#pragma D option quiet
#pragma D option aggsize=16m

BEGIN
{{
{tracked_init}
}}

proc:::create
/tracked[pid]/
{{
    /* FreeBSD proc provider: args[0] is the child struct proc *. */
    tracked[args[0]->p_pid] = 1;
    @new_child[args[0]->p_pid] = count();
}}

proc:::exit
/tracked[pid]/
{{
    tracked[pid] = 0;
}}

syscall:freebsd::entry
/tracked[pid]/
{{
    @syscall[probefunc] = count();
}}

profile-{frequency}
/tracked[pid]/
{{
    @host_pc[uregs[R_RIP]] = count();
}}

profile-{frequency}
/tracked[pid] && ({jit_predicate})/
{{
    this->pcp = (uint64_t *)copyin(uregs[{layout.context_register}] + {layout.exit_resume_offset}, 8);
    @guest_pc[*this->pcp] = count();
}}
{memcpy_clause}
tick-{seconds}s
{{
    printa("{PROTOCOL}|syscall|name=%s|count=%@d\\n", @syscall);
    printa("{PROTOCOL}|new-child|pid=%d|count=%@d\\n", @new_child);
    printa("{PROTOCOL}|host-pc|pc=%#x|count=%@d\\n", @host_pc);
    printa("{PROTOCOL}|guest-pc|pc=%#x|count=%@d\\n", @guest_pc);{memcpy_output}
    trunc(@syscall);
    trunc(@new_child);
    trunc(@host_pc);
    trunc(@guest_pc);{memcpy_trunc}
    exit(0);
}}
"""


def parse_capture(text: str) -> Capture:
    capture = Capture(Counter(), Counter(), Counter(), Counter(), Counter(), Counter())
    for line in text.splitlines():
        if not line.startswith(f"{PROTOCOL}|"):
            continue
        fields = line.strip().split("|")
        if len(fields) != 4:
            raise ProfileError(f"malformed profiler record: {line!r}")
        kind = fields[1]
        key_name, key_value = fields[2].split("=", 1)
        count_name, count_value = fields[3].split("=", 1)
        if count_name != "count":
            raise ProfileError(f"malformed count record: {line!r}")
        count = int(count_value, 10)
        if kind == "syscall" and key_name == "name":
            capture.syscalls[key_value] += count
        elif kind == "new-child" and key_name == "pid":
            capture.new_children[int(key_value, 10)] += count
        elif kind in {"host-pc", "guest-pc", "memcpy-caller"} and key_name == "pc":
            destination = {
                "host-pc": capture.host_pcs,
                "guest-pc": capture.guest_pcs,
                "memcpy-caller": capture.memcpy_callers,
            }[kind]
            destination[int(key_value, 16)] += count
        elif kind == "memcpy-size" and key_name == "bytes":
            capture.memcpy_sizes[int(key_value, 10)] += count
        else:
            raise ProfileError(f"unknown profiler record: {line!r}")
    return capture


def mapping_for_pc(mappings: Iterable[Mapping], pc: int) -> Mapping | None:
    return next((mapping for mapping in mappings if mapping.contains(pc)), None)


def symbolize(path: str, relative_pc: int) -> str:
    if not path or not Path(path).is_file():
        return "??"
    result = subprocess.run(
        ["addr2line", "-Cfipe", path, hex(relative_pc)],
        text=True,
        capture_output=True,
        check=False,
    )
    if result.returncode != 0:
        return "??"
    lines = [line.strip() for line in result.stdout.splitlines() if line.strip()]
    return " <- ".join(lines) if lines else "??"


def symbol_for_pc(
    mappings: list[Mapping], pc: int, object_overrides: dict[str, str] | None = None
) -> Symbol:
    mapping = mapping_for_pc(mappings, pc)
    if mapping is None:
        return Symbol("[unmapped]", hex(pc), hex(pc), "??")
    if mapping.path.startswith("posixshm@"):
        return Symbol("[native-jit]", hex(pc), hex(pc - mapping.start), "translated guest code")
    if not mapping.path:
        return Symbol("[anonymous]", hex(pc), hex(pc - mapping.start), "??")
    base = object_base(mappings, mapping.path)
    relative = pc - base
    symbol_path = (object_overrides or {}).get(mapping.path, mapping.path)
    return Symbol(mapping.path, hex(pc), hex(relative), symbolize(symbol_path, relative))


def aggregate_symbols(
    mappings: list[Mapping],
    pcs: Counter[int],
    max_pcs: int = 256,
    object_overrides: dict[str, str] | None = None,
) -> list[dict[str, object]]:
    aggregated: Counter[tuple[str, str]] = Counter()
    representatives: dict[tuple[str, str], Symbol] = {}
    for pc, count in pcs.most_common(max_pcs):
        symbol = symbol_for_pc(mappings, pc, object_overrides)
        symbol_key = symbol.symbol
        if symbol_key == "??":
            symbol_key = f"?? at {symbol.relative_address}"
        key = (symbol.object, symbol_key)
        aggregated[key] += count
        representatives.setdefault(key, symbol)
    return [
        {
            "count": count,
            "object": key[0],
            "address": representatives[key].address,
            "relative_address": representatives[key].relative_address,
            "symbol": key[1],
        }
        for key, count in aggregated.most_common()
    ]


def guest_symbols(
    guest_elf: Path | None, pcs: Counter[int], limit: int = 256
) -> list[dict[str, object]]:
    rows: list[dict[str, object]] = []
    for pc, count in pcs.most_common(limit):
        rows.append(
            {
                "count": count,
                "pc": hex(pc),
                "symbol": symbolize(str(guest_elf), pc) if guest_elf is not None else None,
            }
        )
    return rows


def same_mappings(before: list[Mapping], after: list[Mapping]) -> bool:
    before_exec = {(item.start, item.end, item.permissions, item.path) for item in before if "x" in item.permissions}
    after_exec = {(item.start, item.end, item.permissions, item.path) for item in after if "x" in item.permissions}
    return before_exec == after_exec


def process_alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
        return True
    except ProcessLookupError:
        return False
    except PermissionError:
        return True


def capture_profile(args: argparse.Namespace) -> dict[str, object]:
    if not sys.platform.startswith("freebsd"):
        raise ProfileError("native-x86 live profiling is supported only on FreeBSD")
    if os.geteuid() != 0:
        raise ProfileError("DTrace requires root; rerun this script with sudo")
    pid = args.pid
    profiled_pids = [pid] if args.no_tree else process_tree(pid)
    executable = process_executable(pid).resolve()
    live_executable = live_executable_handle(pid, executable)
    carrick = args.carrick.resolve() if args.carrick else live_executable
    if args.carrick is not None and not carrick.samefile(live_executable):
        raise ProfileError(
            f"--carrick {carrick} does not match pid {pid} live executable {live_executable}"
        )
    root_mappings_before = process_mappings(pid)
    profile_mappings = initial_tree_mappings(profiled_pids, pid)
    jit = jit_mappings(profile_mappings)
    layout = load_layout(carrick)

    memcpy_range: tuple[int, int] | None = None
    libc = find_libc(root_mappings_before)
    if libc is not None:
        function = elf_function(libc, "memcpy")
        if function is not None:
            value, size = function
            base = object_base(root_mappings_before, libc)
            memcpy_range = (base + value, base + value + size)

    program = build_d_script(
        profiled_pids, args.seconds, args.frequency, layout, jit, memcpy_range
    )
    with tempfile.NamedTemporaryFile("w", prefix="carrick-native-x86-profile-", suffix=".d") as script:
        script.write(program)
        script.flush()
        result = subprocess.run(
            ["dtrace", "-q", "-s", script.name],
            text=True,
            capture_output=True,
            timeout=args.seconds + 15,
            check=False,
        )
    if result.returncode != 0:
        raise ProfileError(f"dtrace failed ({result.returncode}): {result.stderr.strip()}")
    capture = parse_capture(result.stdout)
    alive = process_alive(pid)
    try:
        mappings_after = process_mappings(pid) if alive else []
    except ProfileError:
        mappings_after = []
        alive = process_alive(pid)
    stable = alive and bool(mappings_after) and same_mappings(
        root_mappings_before, mappings_after
    )
    final_profiled_pids = process_tree(pid) if alive else []
    guest_pc_complete = not capture.new_children and set(final_profiled_pids).issubset(
        profiled_pids
    )
    dtrace_warnings = [line for line in result.stderr.splitlines() if line.strip()]

    symbol_budget = max(args.limit * 8, 128)
    object_overrides = {str(executable): str(live_executable)}
    host_rows = aggregate_symbols(
        profile_mappings, capture.host_pcs, symbol_budget, object_overrides
    )
    memcpy_rows = aggregate_symbols(
        profile_mappings, capture.memcpy_callers, symbol_budget, object_overrides
    )
    total_samples = sum(capture.host_pcs.values())
    object_counts: Counter[str] = Counter()
    for pc, count in capture.host_pcs.items():
        mapping = mapping_for_pc(profile_mappings, pc)
        if mapping is None:
            obj = "[unmapped]"
        elif mapping.path.startswith("posixshm@"):
            obj = "[native-jit]"
        else:
            obj = mapping.path or "[anonymous]"
        object_counts[obj] += count

    return {
        "schema": SCHEMA,
        "pid": pid,
        "initial_profiled_pids": profiled_pids,
        "final_profiled_pids": final_profiled_pids,
        "follows_descendants": not args.no_tree,
        "guest_pc_complete": guest_pc_complete,
        "new_children": sorted(capture.new_children),
        "executable": str(executable),
        "layout_binary": str(carrick),
        "seconds": args.seconds,
        "frequency_hz": args.frequency,
        "tracee_alive": alive,
        "executable_mappings_stable": stable,
        "dtrace_clean": not dtrace_warnings,
        "layout": asdict(layout),
        "jit_ranges": [[hex(item.start), hex(item.end)] for item in jit],
        "dtrace_warnings": dtrace_warnings,
        "sample_count": total_samples,
        "samples_by_object": [
            {"object": obj, "count": count} for obj, count in object_counts.most_common()
        ],
        "host_hotspots": host_rows,
        "guest_hotspots": guest_symbols(args.guest_elf, capture.guest_pcs, symbol_budget),
        "syscalls": [{"name": name, "count": count} for name, count in capture.syscalls.most_common()],
        "memcpy_callers": memcpy_rows,
        "memcpy_sizes": [
            {"bytes": size, "count": count} for size, count in capture.memcpy_sizes.most_common()
        ],
    }


def print_text(report: dict[str, object], limit: int) -> None:
    print(
        f"native-x86 profile pid={report['pid']} duration={report['seconds']}s "
        f"samples={report['sample_count']} alive={report['tracee_alive']} "
        f"mappings_stable={report['executable_mappings_stable']} "
        f"dtrace_clean={report['dtrace_clean']} "
        f"guest_pc_complete={report['guest_pc_complete']}"
    )
    print("\nSamples by object")
    for row in report["samples_by_object"][:limit]:
        print(f"  {row['count']:>8}  {row['object']}")
    print("\nHost hotspots")
    for row in report["host_hotspots"][:limit]:
        print(
            f"  {row['count']:>8}  {row['object']}+{row['relative_address']}  {row['symbol']}"
        )
    print("\nGuest hotspots")
    for row in report["guest_hotspots"][:limit]:
        symbol = f"  {row['symbol']}" if row["symbol"] else ""
        print(f"  {row['count']:>8}  {row['pc']}{symbol}")
    print("\nHost syscalls")
    for row in report["syscalls"][:limit]:
        print(f"  {row['count']:>8}  {row['name']}")
    print("\nmemcpy callers")
    for row in report["memcpy_callers"][:limit]:
        print(
            f"  {row['count']:>8}  {row['object']}+{row['relative_address']}  {row['symbol']}"
        )
    print("\nmemcpy sampled sizes")
    for row in report["memcpy_sizes"][:limit]:
        print(f"  {row['count']:>8}  {row['bytes']} bytes")
    warnings = report["dtrace_warnings"]
    if warnings:
        print("\nDTrace warnings", file=sys.stderr)
        for warning in warnings[:limit]:
            print(f"  {warning}", file=sys.stderr)


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("pid", type=int)
    parser.add_argument("--seconds", type=int, default=5)
    parser.add_argument("--frequency", type=int, default=997)
    parser.add_argument("--carrick", type=Path)
    parser.add_argument("--guest-elf", type=Path)
    parser.add_argument(
        "--no-tree",
        action="store_true",
        help="profile only PID instead of its existing and newly-forked descendants",
    )
    parser.add_argument("--limit", type=int, default=15)
    parser.add_argument("--json", action="store_true", dest="as_json")
    args = parser.parse_args(argv)
    if args.pid <= 0:
        parser.error("PID must be positive")
    if not (1 <= args.seconds <= 300):
        parser.error("--seconds must be between 1 and 300")
    if not (1 <= args.frequency <= 10_000):
        parser.error("--frequency must be between 1 and 10000")
    if not (1 <= args.limit <= 1000):
        parser.error("--limit must be between 1 and 1000")
    if args.guest_elf is not None:
        args.guest_elf = args.guest_elf.resolve()
        if not args.guest_elf.is_file():
            parser.error(f"--guest-elf is not a file: {args.guest_elf}")
    return args


def main(argv: list[str]) -> int:
    args = parse_args(argv)
    try:
        report = capture_profile(args)
    except (ProfileError, OSError, subprocess.TimeoutExpired) as error:
        print(f"error: {error}", file=sys.stderr)
        return 2
    if args.as_json:
        print(json.dumps(report, sort_keys=True))
    else:
        print_text(report, args.limit)
    if (
        not report["tracee_alive"]
        or not report["executable_mappings_stable"]
        or not report["dtrace_clean"]
    ):
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
