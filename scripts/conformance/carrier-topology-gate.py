#!/usr/bin/env python3
"""Fail-closed dynamic proof of Carrick's one-carrier host topology.

Every arm is launched by ``carrick trace`` with the durable
``carrier-topology-lineage.d`` program.  The kernel ``proc`` provider is the
birth/exit authority; process-title and ``ps`` observations are used only for
scoped cleanup and T/Z rejection, never to discover or count births.
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass, field
import hashlib
import json
import os
from pathlib import Path
import pty
import signal
import socket
import subprocess
import threading
import time
from typing import Any
from urllib.parse import quote


ROOT = Path(__file__).resolve().parents[2]
DEFAULT_BINARY = ROOT / "target/release/carrick"
DEFAULT_IMAGE = "ubuntu:24.04"
LINEAGE_SCRIPT = ROOT / "scripts/dtrace/carrier-topology-lineage.d"
API_CARRIER_COUNT = 2
ZOMBIE_GRACE_SECONDS = 1.0
ARM_BIRTHS = {
    "foreground-private": 0,
    "tty": 0,
    "logical-fork-storm": 0,
    "detached": 1,
    "docker-api": API_CARRIER_COUNT,
}


class TopologyError(RuntimeError):
    pass


@dataclass
class LineageLedger:
    target: int
    births: list[tuple[int, int]] = field(default_factory=list)
    exec_names: dict[int, str] = field(default_factory=dict)
    exited: set[int] = field(default_factory=set)

    @property
    def all_pids(self) -> set[int]:
        return {self.target, *(child for _, child in self.births)}


def _fields(line: str) -> tuple[str, dict[str, str]]:
    parts = line.strip().split("|")
    if len(parts) < 2 or parts[0] != "CTOP1":
        raise TopologyError(f"malformed topology record: {line!r}")
    values: dict[str, str] = {}
    for item in parts[2:]:
        if "=" not in item:
            raise TopologyError(f"malformed topology field: {item!r}")
        key, value = item.split("=", 1)
        if not key or key in values:
            raise TopologyError(f"duplicate/empty topology field: {item!r}")
        values[key] = value
    return parts[1], values


def _integer(values: dict[str, str], key: str) -> int:
    try:
        return int(values[key])
    except (KeyError, ValueError) as error:
        raise TopologyError(f"missing or invalid integer field {key}") from error


def parse_lineage(text: str) -> LineageLedger:
    records = [line for line in text.splitlines() if line.startswith("CTOP1|")]
    begins = [line for line in records if line.startswith("CTOP1|BEGIN|")]
    summaries = [line for line in records if line.startswith("CTOP1|SUMMARY|")]
    if len(begins) != 1:
        raise TopologyError(f"expected exactly one BEGIN record, observed {len(begins)}")
    if len(summaries) != 1:
        raise TopologyError(f"expected exactly one summary record, observed {len(summaries)}")
    if any(line.startswith("CTOP1|ERROR|") for line in records):
        raise TopologyError("DTrace error record invalidates topology capture")
    if any(line.startswith("CTOP1|TRUNCATED|") for line in records):
        raise TopologyError("DTrace tick bound truncated topology capture")

    _, begin = _fields(begins[0])
    target = _integer(begin, "target")
    ledger = LineageLedger(target=target)
    event_records: list[tuple[int, str, dict[str, str]]] = []
    summary_values: dict[str, str] | None = None
    for line in records:
        kind, values = _fields(line)
        if kind == "BEGIN":
            continue
        if kind in {"CREATE", "EXEC", "EXIT"}:
            event_records.append((_integer(values, "time_ns"), kind, values))
        elif kind == "SUMMARY":
            summary_values = values
        elif kind in {"ERROR", "TRUNCATED"}:
            raise TopologyError(f"invalid terminal record {kind}")
        else:
            raise TopologyError(f"unknown topology record kind {kind}")
    event_records.sort(key=lambda event: event[0])

    live = {target}
    created: set[int] = set()
    for _event_time_ns, kind, values in event_records:
        if _event_time_ns <= 0:
            raise TopologyError("topology timestamp must be positive")
        if kind == "CREATE":
            parent = _integer(values, "parent")
            child = _integer(values, "child")
            if parent not in live:
                raise TopologyError(f"child {child} was created by untracked/dead parent {parent}")
            if child in live or child in created:
                raise TopologyError(f"duplicate child PID {child}")
            ledger.births.append((parent, child))
            created.add(child)
            live.add(child)
        elif kind == "EXEC":
            pid = _integer(values, "pid")
            name = values.get("name", "")
            if pid not in live or pid == target or not name:
                raise TopologyError(f"invalid EXEC identity for pid {pid}")
            if pid in ledger.exec_names:
                raise TopologyError(f"multiple successful execs for child {pid}")
            ledger.exec_names[pid] = name
        elif kind == "EXIT":
            pid = _integer(values, "pid")
            if pid not in live:
                raise TopologyError(f"untracked or duplicate exit for pid {pid}")
            live.remove(pid)
            ledger.exited.add(pid)

    assert summary_values is not None
    if _integer(summary_values, "target") != target:
        raise TopologyError("summary target does not match BEGIN")
    summary_births = _integer(summary_values, "births")
    summary_exits = _integer(summary_values, "exits")
    summary_live = _integer(summary_values, "live")
    summary_complete = _integer(summary_values, "complete")
    summary_errors = _integer(summary_values, "errors")
    if summary_errors != 0:
        raise TopologyError(f"DTrace summary reports {summary_errors} error(s)")
    if summary_births != len(ledger.births):
        raise TopologyError("summary birth count does not close against CREATE records")
    if summary_exits != len(ledger.exited):
        raise TopologyError("summary exit count does not close against EXIT records")
    if live or summary_live != 0 or summary_complete != 1:
        missing = sorted(live)
        raise TopologyError(f"tracked PID(s) did not exit: {missing}")
    if ledger.exited != ledger.all_pids:
        raise TopologyError(
            f"birth-to-exit coverage mismatch: expected {sorted(ledger.all_pids)}, "
            f"observed {sorted(ledger.exited)}"
        )
    return ledger


def validate_birth_policy(
    ledger: LineageLedger, expected_births: int, carrier_exec_name: str
) -> None:
    observed = len(ledger.births)
    if observed != expected_births:
        raise TopologyError(f"expected {expected_births} birth(s), observed {observed}")
    for _, child in ledger.births:
        observed_name = ledger.exec_names.get(child)
        if observed_name != carrier_exec_name:
            raise TopologyError(
                f"birth {child} is non-carrier or lacks exec proof: {observed_name!r}"
            )


def parse_ps_states(text: str) -> dict[int, str]:
    rows: dict[int, str] = {}
    for raw in text.splitlines():
        parts = raw.strip().split(None, 1)
        if len(parts) != 2:
            continue
        try:
            rows[int(parts[0])] = parts[1]
        except ValueError:
            continue
    return rows


def reject_stopped_or_zombie(states: dict[int, str], tracked: set[int]) -> None:
    bad = {pid: states[pid] for pid in tracked & states.keys() if states[pid][:1] in {"T", "Z"}}
    if bad:
        raise TopologyError(f"tracked topology entered forbidden T/Z state: {bad}")


def advance_live_state_census(
    states: dict[int, str],
    tracked: set[int],
    pending_zombies: dict[int, float],
    now: float,
    zombie_grace: float = ZOMBIE_GRACE_SECONDS,
) -> dict[int, float]:
    """Reject stopped or persistently-zombie PIDs still live in the DTrace ledger.

    ``proc:::exit`` fires before the exiting process is reaped. Consequently a
    normal child can appear as ``Z`` to one ``ps`` sample before the EXIT record
    becomes visible in the trace stream. Keep that publication/reap window
    bounded per PID, and let the next DTrace-live census prune the row as soon as
    EXIT is visible. A stopped process has no corresponding terminal race and
    remains an immediate failure.
    """

    stopped = {
        pid: states[pid]
        for pid in tracked & states.keys()
        if states[pid][:1] == "T"
    }
    if stopped:
        raise TopologyError(f"tracked topology entered forbidden T state: {stopped}")

    zombies = {
        pid: states[pid]
        for pid in tracked & states.keys()
        if states[pid][:1] == "Z"
    }
    next_pending = {
        pid: first_seen
        for pid, first_seen in pending_zombies.items()
        if pid in zombies
    }
    for pid in zombies:
        next_pending.setdefault(pid, now)
    overdue = {
        pid: zombies[pid]
        for pid, first_seen in next_pending.items()
        if now - first_seen >= zombie_grace
    }
    if overdue:
        raise TopologyError(
            f"tracked topology retained Z state past {zombie_grace:.3f}s grace: {overdue}"
        )
    return next_pending


def classify_terminal_states(
    states: dict[int, str], tracked: set[int], proven_exited: set[int]
) -> set[int]:
    """Return DTrace-proven terminal zombies; reject all other T/Z states."""

    stopped = {
        pid: states[pid]
        for pid in tracked & states.keys()
        if states[pid][:1] == "T"
    }
    unproven_zombies = {
        pid: states[pid]
        for pid in tracked & states.keys()
        if states[pid][:1] == "Z" and pid not in proven_exited
    }
    if stopped or unproven_zombies:
        raise TopologyError(
            "terminal topology contains stopped or unproven-zombie PID(s): "
            f"T={stopped} Z={unproven_zombies}"
        )
    return {
        pid
        for pid in tracked & states.keys()
        if states[pid][:1] == "Z" and pid in proven_exited
    }


def validate_source_binding(
    head: str, tree: str, dirty: bool, marker: dict[str, Any]
) -> None:
    if dirty:
        raise TopologyError("tracked source is dirty; refusing topology qualification")
    if marker.get("state") != "clean":
        raise TopologyError("build-embedded source marker is not clean")
    if marker.get("head") != head or marker.get("tree") != tree:
        raise TopologyError(
            "build-embedded source HEAD/tree does not match clean tracked source"
        )


def trace_command(
    binary: Path, script: Path, trace_out: Path, command: list[str]
) -> list[str]:
    return [
        str(binary),
        "trace",
        "--script",
        str(script),
        "--trace-out",
        str(trace_out),
        "--",
        *command,
    ]


def _run(args: list[str], *, cwd: Path = ROOT) -> subprocess.CompletedProcess[str]:
    return subprocess.run(args, cwd=cwd, check=True, text=True, capture_output=True)


def source_identity() -> tuple[str, str, bool]:
    head = _run(["git", "rev-parse", "HEAD"]).stdout.strip()
    tree = _run(["git", "rev-parse", "HEAD^{tree}"]).stdout.strip()
    dirty = bool(
        _run(["git", "status", "--porcelain", "--untracked-files=no"]).stdout.strip()
    )
    return head, tree, dirty


def artifact_receipt(binary: Path) -> dict[str, Any]:
    if not binary.is_file() or not os.access(binary, os.X_OK):
        raise TopologyError(f"signed binary is missing or not executable: {binary}")
    head, tree, dirty = source_identity()
    marker_output = _run([str(binary), "__build-source-marker"]).stdout
    try:
        marker = json.loads(marker_output)
    except json.JSONDecodeError as error:
        raise TopologyError("binary emitted an invalid build-source marker") from error
    validate_source_binding(head, tree, dirty, marker)
    entitlements = _run(
        ["codesign", "-d", "--entitlements", ":-", str(binary)]
    ).stdout
    if "com.apple.security.hypervisor" not in entitlements or "<true/>" not in entitlements:
        raise TopologyError("binary lacks the Hypervisor.framework entitlement")
    load_commands = _run(["otool", "-l", str(binary)]).stdout
    if "__dof_carrick" not in load_commands:
        raise TopologyError("binary lacks __dof_carrick; DTrace proof would be empty")
    signature = subprocess.run(
        ["codesign", "-dvvv", str(binary)], text=True, capture_output=True
    ).stderr
    cdhash = next(
        (line.split("=", 1)[1] for line in signature.splitlines() if line.startswith("CDHash=")),
        None,
    )
    if not cdhash:
        raise TopologyError("codesign did not report a CDHash")
    uuid = _run(["xcrun", "dwarfdump", "--uuid", str(binary)]).stdout.strip()
    return {
        "source_head": head,
        "source_tree": tree,
        "build_source_marker": marker,
        "binary": str(binary.resolve()),
        "sha256": hashlib.sha256(binary.read_bytes()).hexdigest(),
        "cdhash": cdhash,
        "lc_uuid": uuid,
        "hypervisor_entitlement": True,
        "dof_carrick": True,
    }


def _partial_live_pids(path: Path) -> set[int]:
    if not path.exists():
        return set()
    live: set[int] = set()
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        if line.startswith("CTOP1|BEGIN|"):
            _, values = _fields(line)
            live.add(_integer(values, "target"))
        elif line.startswith("CTOP1|CREATE|"):
            _, values = _fields(line)
            live.add(_integer(values, "child"))
        elif line.startswith("CTOP1|EXIT|"):
            _, values = _fields(line)
            live.discard(_integer(values, "pid"))
    return live


def _partial_all_pids(path: Path) -> set[int]:
    if not path.exists():
        return set()
    owned: set[int] = set()
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        if line.startswith("CTOP1|BEGIN|"):
            _, values = _fields(line)
            owned.add(_integer(values, "target"))
        elif line.startswith("CTOP1|CREATE|"):
            _, values = _fields(line)
            owned.add(_integer(values, "child"))
    return owned


def _pid_states(pids: set[int]) -> dict[int, str]:
    if not pids:
        return {}
    result = subprocess.run(
        [
            "ps",
            "-p",
            ",".join(str(pid) for pid in sorted(pids)),
            "-o",
            "pid=",
            "-o",
            "state=",
        ],
        text=True,
        capture_output=True,
    )
    return parse_ps_states(result.stdout)


def _partial_target_pid(path: Path) -> int | None:
    if not path.exists():
        return None
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        if line.startswith("CTOP1|BEGIN|"):
            _, values = _fields(line)
            return _integer(values, "target")
    return None


class StateMonitor:
    def __init__(self, trace_path: Path):
        self.trace_path = trace_path
        self.stop_event = threading.Event()
        self.violations: list[str] = []
        self.samples = 0
        self.max_live = 0
        self.live_sizes: set[int] = set()
        self.pending_zombies: dict[int, float] = {}
        self.zombie_samples = 0
        self.thread = threading.Thread(target=self._run, name="topology-state-monitor")

    def start(self) -> None:
        self.thread.start()

    def stop(self) -> None:
        self.stop_event.set()
        self.thread.join(timeout=2)

    def _run(self) -> None:
        while not self.stop_event.wait(0.02):
            try:
                live = _partial_live_pids(self.trace_path)
                self.max_live = max(self.max_live, len(live))
                if not live:
                    self.pending_zombies.clear()
                    continue
                result = subprocess.run(
                    ["ps", "-p", ",".join(str(pid) for pid in sorted(live)), "-o", "pid=", "-o", "state="],
                    text=True,
                    capture_output=True,
                )
                states = parse_ps_states(result.stdout)
                self.pending_zombies = advance_live_state_census(
                    states,
                    live,
                    self.pending_zombies,
                    time.monotonic(),
                )
                if self.pending_zombies:
                    self.zombie_samples += 1
                self.samples += 1
                self.live_sizes.add(len(live))
            except Exception as error:  # preserved and failed by the arm owner
                self.violations.append(str(error))
                return


def _drain_pty(master: int, sink: list[bytes]) -> None:
    while True:
        try:
            chunk = os.read(master, 4096)
        except OSError:
            return
        if not chunk:
            return
        sink.append(chunk)


def _wait_trace(
    process: subprocess.Popen[Any], monitor: StateMonitor, timeout: float, pty_master: int | None
) -> tuple[str, str]:
    try:
        if pty_master is None:
            stdout, stderr = process.communicate(timeout=timeout)
            return stdout or "", stderr or ""
        process.wait(timeout=timeout)
        return "", ""
    except subprocess.TimeoutExpired as error:
        raise TopologyError(f"trace process exceeded {timeout}s arm bound") from error
    finally:
        monitor.stop()
        if pty_master is not None:
            os.close(pty_master)


def _launch_trace(
    binary: Path,
    trace_path: Path,
    run_id: str,
    command: list[str],
    tty: bool = False,
) -> tuple[subprocess.Popen[Any], StateMonitor, int | None]:
    env = os.environ.copy()
    env["CARRICK_RUN_ID"] = run_id
    argv = trace_command(binary, LINEAGE_SCRIPT, trace_path, command)
    if tty:
        master, slave = pty.openpty()
        process = subprocess.Popen(argv, env=env, stdin=slave, stdout=slave, stderr=slave)
        os.close(slave)
        sink: list[bytes] = []
        threading.Thread(target=_drain_pty, args=(master, sink), daemon=True).start()
        pty_master: int | None = master
    else:
        process = subprocess.Popen(argv, env=env, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        pty_master = None
    monitor = StateMonitor(trace_path)
    monitor.start()
    return process, monitor, pty_master


def _decode_chunked(body: bytes) -> bytes:
    result = bytearray()
    while body:
        line, separator, body = body.partition(b"\r\n")
        if not separator:
            raise TopologyError("malformed chunked API response")
        size = int(line.split(b";", 1)[0], 16)
        if size == 0:
            return bytes(result)
        if len(body) < size + 2 or body[size : size + 2] != b"\r\n":
            raise TopologyError("truncated chunked API response")
        result.extend(body[:size])
        body = body[size + 2 :]
    raise TopologyError("chunked API response omitted terminal chunk")


def api_request(
    socket_path: Path,
    method: str,
    path: str,
    body: bytes = b"",
    content_type: str = "application/json",
) -> tuple[int, dict[str, str], bytes]:
    client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    client.settimeout(10)
    client.connect(str(socket_path))
    request = (
        f"{method} {path} HTTP/1.1\r\nHost: carrick\r\nConnection: close\r\n"
        f"Content-Type: {content_type}\r\nContent-Length: {len(body)}\r\n\r\n"
    ).encode() + body
    client.sendall(request)
    chunks = []
    while True:
        chunk = client.recv(65536)
        if not chunk:
            break
        chunks.append(chunk)
    client.close()
    raw = b"".join(chunks)
    head, separator, response_body = raw.partition(b"\r\n\r\n")
    if not separator:
        raise TopologyError("API response omitted header terminator")
    lines = head.decode("latin1").split("\r\n")
    try:
        status = int(lines[0].split()[1])
    except (IndexError, ValueError) as error:
        raise TopologyError("API response status is malformed") from error
    headers = {
        key.strip().lower(): value.strip()
        for line in lines[1:]
        if ":" in line
        for key, value in [line.split(":", 1)]
    }
    if headers.get("transfer-encoding", "").lower() == "chunked":
        response_body = _decode_chunked(response_body)
    return status, headers, response_body


def parse_docker_exec_frames(payload: bytes) -> tuple[bytes, bytes]:
    stdout = bytearray()
    stderr = bytearray()
    while payload:
        if len(payload) < 8:
            raise TopologyError("Docker exec stream ended inside a frame header")
        stream = payload[0]
        if payload[1:4] != b"\0\0\0":
            raise TopologyError("Docker exec frame reserved bytes are nonzero")
        length = int.from_bytes(payload[4:8], "big")
        payload = payload[8:]
        if len(payload) < length:
            raise TopologyError("Docker exec stream ended inside a frame payload")
        frame, payload = payload[:length], payload[length:]
        if stream == 1:
            stdout.extend(frame)
        elif stream == 2:
            stderr.extend(frame)
        else:
            raise TopologyError(f"Docker exec stream used unknown channel {stream}")
    return bytes(stdout), bytes(stderr)


def api_exec_attached(socket_path: Path, exec_id: str) -> tuple[bytes, bytes]:
    body = json.dumps({"Detach": False}).encode()
    client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    client.settimeout(20)
    client.connect(str(socket_path))
    request = (
        f"POST /exec/{exec_id}/start HTTP/1.1\r\n"
        "Host: carrick\r\nConnection: Upgrade\r\nUpgrade: tcp\r\n"
        f"Content-Type: application/json\r\nContent-Length: {len(body)}\r\n\r\n"
    ).encode() + body
    client.sendall(request)
    response = bytearray()
    while b"\r\n\r\n" not in response:
        chunk = client.recv(4096)
        if not chunk:
            raise TopologyError("Docker exec upgrade closed before response headers")
        response.extend(chunk)
    head, payload = bytes(response).split(b"\r\n\r\n", 1)
    try:
        status = int(head.split(b"\r\n", 1)[0].split()[1])
    except (IndexError, ValueError) as error:
        raise TopologyError("Docker exec upgrade status is malformed") from error
    if status != 101:
        raise TopologyError(f"Docker exec upgrade returned {status}: {payload[:512]!r}")
    chunks = [payload]
    while True:
        chunk = client.recv(65536)
        if not chunk:
            break
        chunks.append(chunk)
    client.close()
    return parse_docker_exec_frames(b"".join(chunks))


def _expect_api(
    socket_path: Path,
    method: str,
    path: str,
    expected: set[int],
    body: bytes = b"",
    content_type: str = "application/json",
) -> bytes:
    status, _, response = api_request(socket_path, method, path, body, content_type)
    if status not in expected:
        raise TopologyError(
            f"API {method} {path} returned {status}, expected {sorted(expected)}: {response[:512]!r}"
        )
    return response


class Campaign:
    def __init__(self, binary: Path, image: str, output: Path):
        self.binary = binary
        self.image = image
        self.output = output
        self.records: list[dict[str, Any]] = []

    def record(self, **record: Any) -> None:
        record["time_ns"] = time.time_ns()
        self.records.append(record)
        self.output.parent.mkdir(parents=True, exist_ok=True)
        with self.output.open("w", encoding="utf-8") as handle:
            for row in self.records:
                handle.write(json.dumps(row, sort_keys=True) + "\n")

    def cleanup(
        self,
        run_id: str,
        names: list[str] | None = None,
        trace_path: Path | None = None,
        trace_process: subprocess.Popen[Any] | None = None,
    ) -> None:
        exact_owned = _partial_all_pids(trace_path) if trace_path is not None else set()
        exact_targets = _partial_live_pids(trace_path) if trace_path is not None else set()
        exact_live_before = _pid_states(exact_targets)
        exact_kill_attempts: list[int] = []
        for pid in sorted(exact_live_before):
            try:
                os.kill(pid, signal.SIGKILL)
                exact_kill_attempts.append(pid)
            except ProcessLookupError:
                pass
        if trace_process is not None and trace_process.poll() is None:
            try:
                trace_process.wait(timeout=10)
            except subprocess.TimeoutExpired as error:
                raise TopologyError(
                    "trace owner did not reap exact targets after scoped termination"
                ) from error
        deadline = time.monotonic() + 5
        exact_remaining = _pid_states(exact_targets)
        while exact_remaining and time.monotonic() < deadline:
            time.sleep(0.02)
            exact_remaining = _pid_states(exact_targets)
        cleanup = subprocess.run(
            ["bash", str(ROOT / "scripts/sudo/kill.sh"), run_id],
            text=True,
            capture_output=True,
        )
        ps = subprocess.run(
            ["ps", "-axww", "-o", "command="], text=True, capture_output=True, check=True
        ).stdout
        remaining = [line for line in ps.splitlines() if f"carrick:{run_id}:" in line]
        if names:
            for name in names:
                subprocess.run([str(self.binary), "rm", "-f", name], capture_output=True)
        self.record(
            record="cleanup",
            run_id=run_id,
            cleanup_exit=cleanup.returncode,
            remaining=remaining,
            exact_owned=sorted(exact_owned),
            exact_targets=sorted(exact_targets),
            exact_live_before=exact_live_before,
            exact_kill_attempts=exact_kill_attempts,
            exact_remaining=exact_remaining,
        )
        if cleanup.returncode != 0 or remaining or exact_remaining:
            raise TopologyError(
                f"scoped cleanup did not reach zero: run_id={remaining} exact={exact_remaining}"
            )

    def _validate_arm(
        self,
        label: str,
        run_id: str,
        trace_path: Path,
        process: subprocess.Popen[Any],
        monitor: StateMonitor,
        pty_master: int | None,
        names: list[str] | None = None,
        expected_child_pids: set[int] | None = None,
    ) -> None:
        try:
            stdout, stderr = _wait_trace(process, monitor, 135, pty_master)
            if process.returncode != 0:
                raise TopologyError(
                    f"carrick trace exited {process.returncode}: stdout={stdout[-1000:]!r} stderr={stderr[-1000:]!r}"
                )
            if monitor.violations:
                raise TopologyError("; ".join(monitor.violations))
            ledger = parse_lineage(trace_path.read_text(encoding="utf-8"))
            validate_birth_policy(ledger, ARM_BIRTHS[label], self.binary.name)
            observed_child_pids = {child for _, child in ledger.births}
            if expected_child_pids is not None and observed_child_pids != expected_child_pids:
                raise TopologyError(
                    f"DTrace children {sorted(observed_child_pids)} do not match authenticated "
                    f"carrier owners {sorted(expected_child_pids)}"
                )
            required_live = API_CARRIER_COUNT + 1 if label == "docker-api" else 1
            if monitor.samples == 0 or required_live not in monitor.live_sizes:
                raise TopologyError(
                    f"state census never sampled required live topology {required_live}: "
                    f"samples={monitor.samples} live_sizes={sorted(monitor.live_sizes)}"
                )
            terminal_zombie_samples = 0
            terminal_deadline = time.monotonic() + ZOMBIE_GRACE_SECONDS
            while True:
                final_states = _pid_states(ledger.all_pids)
                terminal_zombies = classify_terminal_states(
                    final_states, ledger.all_pids, ledger.exited
                )
                if not terminal_zombies:
                    break
                terminal_zombie_samples += 1
                if time.monotonic() >= terminal_deadline:
                    raise TopologyError(
                        "DTrace-proven exited PID(s) remained zombies past "
                        f"{ZOMBIE_GRACE_SECONDS:.3f}s reap grace: "
                        f"{sorted(terminal_zombies)}"
                    )
                time.sleep(0.02)
            self.record(
                record="lineage",
                arm=label,
                run_id=run_id,
                target=ledger.target,
                births=ledger.births,
                exec_names=ledger.exec_names,
                exited=sorted(ledger.exited),
                state_samples=monitor.samples,
                live_zombie_samples=monitor.zombie_samples,
                terminal_zombie_samples=terminal_zombie_samples,
                max_live=monitor.max_live,
                observed_live_sizes=sorted(monitor.live_sizes),
                trace_path=str(trace_path),
            )
        finally:
            self.cleanup(run_id, names, trace_path, process)

    def simple_arm(self, label: str, command: list[str], tty: bool = False, name: str | None = None) -> None:
        run_id = f"topology-{label}-{os.getpid()}-{time.time_ns()}"
        trace_path = self.output.parent / f"{run_id}.raw"
        process, monitor, master = _launch_trace(
            self.binary, trace_path, run_id, command, tty=tty
        )
        self._validate_arm(
            label,
            run_id,
            trace_path,
            process,
            monitor,
            master,
            [name] if name else None,
        )

    def docker_api_arm(self) -> None:
        label = "docker-api"
        run_id = f"topology-{label}-{os.getpid()}-{time.time_ns()}"
        trace_path = self.output.parent / f"{run_id}.raw"
        socket_path = self.output.parent / f"{run_id}.sock"
        names = [f"{run_id}-{index}" for index in range(API_CARRIER_COUNT)]
        process, monitor, master = _launch_trace(
            self.binary,
            trace_path,
            run_id,
            ["serve", "--docker-api", "--host", str(socket_path)],
        )
        container_ids: list[str] = []
        carrier_pids: set[int] = set()
        try:
            deadline = time.monotonic() + 15
            while not socket_path.exists() and process.poll() is None and time.monotonic() < deadline:
                time.sleep(0.02)
            if not socket_path.exists():
                raise TopologyError("Docker API socket did not become ready")
            for name in names:
                body = json.dumps(
                    {"Image": self.image, "Cmd": ["/bin/sleep", "30"]}
                ).encode()
                created = _expect_api(
                    socket_path,
                    "POST",
                    f"/containers/create?name={quote(name)}",
                    {201},
                    body,
                )
                container_id = json.loads(created)["Id"]
                container_ids.append(container_id)
                _expect_api(socket_path, "POST", f"/containers/{container_id}/start", {204})
                deadline = time.monotonic() + 10
                while True:
                    inspected = json.loads(
                        _expect_api(
                            socket_path,
                            "GET",
                            f"/containers/{container_id}/json",
                            {200},
                        )
                    )
                    carrier_pid = int(inspected["State"]["Pid"])
                    if inspected["State"]["Running"] and carrier_pid > 0:
                        carrier_pids.add(carrier_pid)
                        break
                    if time.monotonic() >= deadline:
                        raise TopologyError(f"container {container_id} never reached Running")
                    time.sleep(0.02)

            target = _partial_target_pid(trace_path)
            if target is None:
                raise TopologyError("DTrace stream never published the API target PID")
            target_command = subprocess.run(
                ["ps", "-p", str(target), "-o", "command="],
                text=True,
                capture_output=True,
                check=True,
            ).stdout.strip()
            if "serve" not in target_command or "--docker-api" not in target_command:
                raise TopologyError(
                    f"DTrace target is not the Docker API server: {target_command!r}"
                )
            deadline = time.monotonic() + 10
            while True:
                observed_children = _partial_all_pids(trace_path) - {target}
                if observed_children == carrier_pids:
                    break
                if time.monotonic() >= deadline:
                    raise TopologyError(
                        f"DTrace children {sorted(observed_children)} do not match live carriers {sorted(carrier_pids)}"
                    )
                time.sleep(0.02)

            marker = b"topology-live-exec-marker\n"
            exec_body = json.dumps(
                {
                    "Cmd": [
                        "/bin/sh",
                        "-c",
                        "printf 'topology-live-exec-marker\\n'; mkdir -p /tmp/topology && printf 'topology-live-exec-marker\\n' > /tmp/topology/exec-marker",
                    ],
                    "AttachStdout": True,
                    "AttachStderr": True,
                }
            ).encode()
            created_exec = _expect_api(
                socket_path,
                "POST",
                f"/containers/{container_ids[0]}/exec",
                {201},
                exec_body,
            )
            exec_id = json.loads(created_exec)["Id"]
            exec_stdout, exec_stderr = api_exec_attached(socket_path, exec_id)
            deadline = time.monotonic() + 15
            while True:
                inspected = json.loads(
                    _expect_api(socket_path, "GET", f"/exec/{exec_id}/json", {200})
                )
                if not inspected["Running"]:
                    if inspected["ExitCode"] != 0:
                        raise TopologyError(
                            f"logical exec marker exited {inspected['ExitCode']}: "
                            f"stdout={exec_stdout!r} stderr={exec_stderr!r}"
                        )
                    break
                if time.monotonic() >= deadline:
                    raise TopologyError("logical exec marker did not complete")
                time.sleep(0.02)
            if exec_stdout != marker or exec_stderr:
                raise TopologyError(
                    f"logical exec result mismatch: stdout={exec_stdout!r} stderr={exec_stderr!r}"
                )

            if _partial_all_pids(trace_path) - {target} != carrier_pids:
                raise TopologyError("logical exec created an additional host process")

            for container_id in container_ids:
                _expect_api(
                    socket_path,
                    "POST",
                    f"/containers/{container_id}/kill?signal=KILL",
                    {204},
                )
            deadline = time.monotonic() + 15
            while True:
                all_terminal = True
                for container_id in container_ids:
                    inspected = json.loads(
                        _expect_api(
                            socket_path,
                            "GET",
                            f"/containers/{container_id}/json",
                            {200},
                        )
                    )
                    all_terminal &= not inspected["State"]["Running"]
                if all_terminal and _partial_live_pids(trace_path) == {target}:
                    break
                if time.monotonic() >= deadline:
                    raise TopologyError("carriers did not publish terminal exit before API shutdown")
                time.sleep(0.02)
            if target is None:
                # Kept explicit for type checkers and fail-closed readability.
                raise TopologyError("DTrace stream never published the API target PID")
            if process.poll() is None:
                try:
                    os.kill(target, signal.SIGTERM)
                except ProcessLookupError as error:
                    raise TopologyError("API target disappeared before controlled shutdown") from error
            else:
                raise TopologyError("carrick trace exited before controlled API shutdown")
        except Exception as arm_error:
            monitor.stop()
            try:
                self.cleanup(run_id, names, trace_path, process)
                trace_stdout, trace_stderr = process.communicate(timeout=1)
            except Exception as cleanup_error:
                if process.poll() is None:
                    process.kill()
                    process.wait(timeout=5)
                trace_stdout, trace_stderr = process.communicate(timeout=1)
                raise TopologyError(
                    f"arm failed: {arm_error}; exact cleanup failed: {cleanup_error}; "
                    f"trace stdout={str(trace_stdout)[-2000:]!r}; "
                    f"trace stderr={str(trace_stderr)[-4000:]!r}"
                ) from arm_error
            raise TopologyError(
                f"arm failed: {arm_error}; trace stdout={str(trace_stdout)[-2000:]!r}; "
                f"trace stderr={str(trace_stderr)[-4000:]!r}"
            ) from arm_error
        self._validate_arm(
            label,
            run_id,
            trace_path,
            process,
            monitor,
            master,
            names,
            carrier_pids,
        )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--binary", type=Path, default=DEFAULT_BINARY)
    parser.add_argument("--image", default=DEFAULT_IMAGE)
    parser.add_argument(
        "--output",
        type=Path,
        default=ROOT / "target/perf/carrier-topology-gate/receipt.jsonl",
    )
    args = parser.parse_args()
    campaign = Campaign(args.binary, args.image, args.output)
    try:
        campaign.record(record="artifact", **artifact_receipt(args.binary))
    except Exception as error:
        campaign.record(record="result", status="fail", error=str(error))
        print(f"carrier topology gate: ARTIFACT PREFLIGHT FAIL: {error}", file=os.sys.stderr)
        return 1

    base = ["run", "--raw", "--fs", "host", "--pid", "private", args.image]
    detached_name = f"topology-detached-{os.getpid()}-{time.time_ns()}"
    arms = [
        (
            "foreground-private",
            lambda: campaign.simple_arm(
                "foreground-private", [*base, "/bin/sleep", "2"]
            ),
        ),
        (
            "tty",
            lambda: campaign.simple_arm(
                "tty", ["run", "-t", "--fs", "host", args.image, "/bin/sleep", "2"], tty=True
            ),
        ),
        (
            "logical-fork-storm",
            lambda: campaign.simple_arm(
                "logical-fork-storm",
                [
                    *base,
                    "/bin/sh",
                    "-c",
                    "i=0; while [ $i -lt 24 ]; do (/bin/true) & i=$((i+1)); done; wait; sleep 1",
                ],
            ),
        ),
        (
            "detached",
            lambda: campaign.simple_arm(
                "detached",
                [
                    "run",
                    "-d",
                    "--raw",
                    "--fs",
                    "host",
                    "--name",
                    detached_name,
                    args.image,
                    "/bin/sleep",
                    "3",
                ],
                name=detached_name,
            ),
        ),
        ("docker-api", campaign.docker_api_arm),
    ]
    failures: list[str] = []
    for label, arm in arms:
        try:
            arm()
            campaign.record(record="arm-result", arm=label, status="pass")
        except Exception as error:
            failures.append(f"{label}: {error}")
            campaign.record(record="arm-result", arm=label, status="fail", error=str(error))
    if failures:
        campaign.record(record="result", status="fail", failures=failures)
        print(
            f"carrier topology gate: FAIL ({len(failures)} arm(s)); receipt: {args.output}",
            file=os.sys.stderr,
        )
        return 1
    campaign.record(record="result", status="pass")
    print(f"carrier topology gate: PASS ({args.output})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
