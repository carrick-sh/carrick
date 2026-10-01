#!/usr/bin/env python3
"""Real-workload overhead A/B for the EL1 guest descriptor lane.

Answers one question for the EL1 ranking: where do real workloads (cold
`go build`, CPython with threads, Node) spend their overhead against native
arm64 Docker, and does `CARRICK_EL1_DESCRIPTOR_LANE` change that?

Four subcommands, run in this order (see
docs/perf-results/2026-10-01-el1-real-workload-ab/README.md):

  plan         print every argv this campaign will execute; with
               --check-harness, prove the suite argv equals the conformance
               harness's own `--dry-run` line.
  carrick      timing phase: ABBA quads of two env arms on ONE binary,
               uninstrumented. Records wall, RUSAGE_CHILDREN CPU, the in-guest
               workload window when the workload prints one, binary SHA-256,
               CDHash, LC_UUID, entitlement, `__dof_carrick`, git state.
  attribution  per arm, one `carrick trace --profile hvpatch-exit-attribution`
               run and one `--profile hvpatch-carrier-cpu-attribution` run per
               workload. Separate from timing: attribution runs are perturbed.
  docker       oracle phase. Never overlaps Carrick: refuses to start while any
               Carrick process is alive. The director runs it.
  report       join the three artifacts into one per-workload table.

Workloads are not invented here. `go-build` is native_go_build.py's cold
GOCACHE build (same guest script and window); every other workload is a
conformance suite read from scripts/conformance/suites.toml and launched with
the harness's own argv rules (crates/carrick-conformance/src/engine.rs).
"""

from __future__ import annotations

import argparse
import dataclasses
import datetime
import json
import math
import os
import pathlib
import platform
import plistlib
import resource
import statistics
import subprocess
import sys
import time
import tomllib
from collections.abc import Sequence

import embed_go_build_abba
import native_go_build
import native_go_build_abba as native_abba
import paired_stats


SCHEMA_CARRICK = "carrick.el1-workload-ab.carrick.v1"
SCHEMA_ATTRIBUTION = "carrick.el1-workload-ab.attribution.v1"
SCHEMA_DOCKER = "carrick.el1-workload-ab.docker.v1"
SCHEMA_REPORT = "carrick.el1-workload-ab.report.v1"
LANE_ENV = "CARRICK_EL1_DESCRIPTOR_LANE"
DEFAULT_ARMS = (f"lane-off:{LANE_ENV}=0", "lane-on")
DEFAULT_WORKLOADS = ("go-build", "cpython-threading", "node-core-worker-message-port")
GO_BUILD = "go-build"
# `--max-traps usize::MAX`, exactly as carrick_argv spells it.
MAX_TRAPS = str((1 << 64) - 1)
ATTRIBUTION_PROFILES = (
    "hvpatch-exit-attribution",
    "hvpatch-carrier-cpu-attribution",
)
HYPERVISOR_ENTITLEMENT = "com.apple.security.hypervisor"
METRICS = ("cpu_s", "elapsed_ms", "workload_ms")
# Whole-carrier sampled split (hvpatch-carrier-cpu-attribution summary keys).
CARRIER_SHARE_KEYS = (
    ("guest", "guest_execution"),
    ("syscall", "host_syscall"),
    ("fault", "fault_service"),
    ("sched", "executor_scheduling"),
    ("el1-mailbox", "el1_mailbox"),
    ("lock", "lock_wait"),
    ("other", "other"),
)
REPO = pathlib.Path(__file__).resolve().parents[2]
DEFAULT_MANIFESTS = (
    REPO / "scripts/conformance/suites.toml",
    REPO / "scripts/perf/manifests/el1-real-workloads-v1.toml",
)


@dataclasses.dataclass(frozen=True)
class Arm:
    label: str
    environment: tuple[tuple[str, str], ...]

    def env(self) -> dict[str, str]:
        return dict(self.environment)


@dataclasses.dataclass(frozen=True)
class Workload:
    name: str
    image: str
    timeout_s: int
    suite: dict[str, object] | None
    manifest: pathlib.Path | None = None

    @property
    def has_window(self) -> bool:
        return self.suite is None


def parse_arm(spec: str) -> Arm:
    """`label` or `label:KEY=VAL[,KEY=VAL]`; keys must be CARRICK_*."""
    label, _, rest = spec.partition(":")
    if not label or not label.replace("-", "").replace("_", "").isalnum():
        raise ValueError(f"arm label must be a plain token: {spec!r}")
    pairs: list[tuple[str, str]] = []
    if rest:
        for item in rest.split(","):
            key, sep, value = item.partition("=")
            if not sep or not key.startswith("CARRICK_") or key == "CARRICK_RUN_ID":
                raise ValueError(f"arm {label!r}: {item!r} is not a CARRICK_* control")
            pairs.append((key, value))
    if len({key for key, _ in pairs}) != len(pairs):
        raise ValueError(f"arm {label!r} repeats a key")
    return Arm(label, tuple(sorted(pairs)))


def parse_arms(specs: Sequence[str]) -> tuple[Arm, Arm]:
    arms = tuple(parse_arm(spec) for spec in specs)
    if len(arms) != 2:
        raise ValueError("an ABBA campaign takes exactly two arms (A control, B candidate)")
    if arms[0].label == arms[1].label:
        raise ValueError("arm labels must differ")
    # Every key either arm sets is scrubbed from the other, so "unset" means
    # the binary default and never an inherited value.
    return arms  # type: ignore[return-value]


def load_suites(*manifests: pathlib.Path) -> dict[str, dict[str, object]]:
    """Suites by name, each tagged with the manifest that declares it."""
    suites: dict[str, dict[str, object]] = {}
    for manifest in manifests:
        for suite in tomllib.loads(manifest.read_text()).get("suite", []):
            if suite["name"] in suites:
                raise ValueError(f"suite {suite['name']!r} is declared twice")
            suites[suite["name"]] = {**suite, "_manifest": str(manifest)}
    return suites


def resolve_workload(name: str, suites: dict[str, dict[str, object]]) -> Workload:
    if name == GO_BUILD:
        return Workload(
            GO_BUILD,
            native_go_build.DEFAULT_IMAGE,
            native_go_build.DEFAULT_TIMEOUT_SECONDS,
            None,
        )
    suite = suites.get(name)
    if suite is None:
        raise ValueError(f"unknown workload {name!r}: not go-build and not a suite in suites.toml")
    return Workload(
        name,
        str(suite["image"]),
        int(suite["timeout_s"]),
        suite,
        pathlib.Path(str(suite["_manifest"])),
    )


def _effective_cmd(suite: dict[str, object]) -> list[str]:
    cmd = [str(token) for token in suite["cmd"]]
    if suite["ecosystem"] == "ltp":
        return ["/bin/sh", "-c", " ".join(cmd)]
    return cmd


def _entrypoint(suite: dict[str, object], engine: str) -> str | None:
    pair = suite.get("entrypoint") or {}
    assert isinstance(pair, dict)
    value = pair.get(engine) or pair.get("both")
    return None if value is None else str(value)


def _env_args(*sets: object) -> list[str]:
    args: list[str] = []
    for entries in sets:
        for entry in entries or []:  # type: ignore[union-attr]
            args.extend(["-e", f"{entry['key']}={entry['val']}"])
    return args


def carrick_argv(workload: Workload, binary: pathlib.Path, run_id: str) -> list[str]:
    if workload.suite is None:
        return native_go_build.build_carrick_command(REPO, run_id, binary=binary)
    suite = workload.suite
    argv = [str(binary), "run", "--name", run_id, "--max-traps", MAX_TRAPS]
    argv.extend(str(flag) for flag in suite.get("carrick_flags", []))
    docker_flags = [str(flag) for flag in suite.get("docker_flags", [])]
    if any(f in ("seccomp=unconfined", "--security-opt=seccomp=unconfined") for f in docker_flags):
        argv.extend(["--security-opt", "seccomp=unconfined"])
    entrypoint = _entrypoint(suite, "carrick")
    if entrypoint is not None:
        argv.extend(["--entrypoint", entrypoint])
    for mount in suite.get("bind_mounts", []):
        argv.extend(["-v", str(mount)])
    if suite.get("workdir"):
        argv.extend(["-w", str(suite["workdir"])])
    argv.extend(_env_args(suite.get("env"), suite.get("env_carrick")))
    argv.append(str(suite["image"]))
    argv.extend(_effective_cmd(suite))
    return argv


def docker_argv(workload: Workload, run_id: str) -> list[str]:
    if workload.suite is None:
        return native_go_build.build_command(REPO, native_go_build.ENGINE_DOCKER, run_id)
    suite = workload.suite
    argv = ["docker", "run", "--name", run_id, "--platform", "linux/arm64"]
    argv.extend(str(flag) for flag in suite.get("docker_flags", []))
    entrypoint = _entrypoint(suite, "docker")
    if entrypoint is not None:
        argv.extend(["--entrypoint", entrypoint])
    for mount in suite.get("bind_mounts", []):
        argv.extend(["-v", str(mount)])
    if suite.get("workdir"):
        argv.extend(["-w", str(suite["workdir"])])
    argv.extend(_env_args(suite.get("env"), suite.get("env_docker")))
    argv.append(str(suite["image"]))
    argv.extend(_effective_cmd(suite))
    return argv


def harness_dry_run_lines(
    suite_name: str, binary: pathlib.Path, manifest: pathlib.Path
) -> tuple[str, str]:
    """The conformance harness's own planned argv for one suite."""
    result = subprocess.run(
        [
            "cargo", "run", "-q", "-p", "carrick-conformance", "--",
            "--dry-run", "--manifest", str(manifest), "--tier", "full",
            "--suite", suite_name, "--carrick-bin", str(binary),
        ],
        cwd=REPO, capture_output=True, text=True, check=False, timeout=1800,
    )
    if result.returncode != 0:
        raise RuntimeError(f"harness dry-run failed: {result.stderr.strip()}")
    carrick = [l.strip() for l in result.stdout.splitlines() if l.strip().startswith("carrick:")]
    docker = [l.strip() for l in result.stdout.splitlines() if l.strip().startswith("docker:")]
    if len(carrick) != 1 or len(docker) != 1:
        raise RuntimeError(f"harness dry-run printed no unique plan for {suite_name}")
    return carrick[0].removeprefix("carrick:").strip(), docker[0].removeprefix("docker:").strip()


def check_against_harness(workload: Workload, binary: pathlib.Path) -> None:
    if workload.suite is None:
        return
    assert workload.manifest is not None
    want_carrick, want_docker = harness_dry_run_lines(workload.name, binary, workload.manifest)
    marker = "RUNID"
    for want, have in (
        (want_carrick, " ".join(carrick_argv(workload, binary, marker))),
        (want_docker, " ".join(docker_argv(workload, marker))),
    ):
        normalized = " ".join(
            marker if token.startswith("conf-") else token for token in want.split(" ")
        )
        if normalized != have:
            raise RuntimeError(
                f"{workload.name}: argv drifted from the conformance harness\n"
                f"  harness: {normalized}\n  runner:  {have}"
            )


def binary_identity(binary: pathlib.Path) -> dict[str, object]:
    native_abba.verify_codesign(binary)
    entitlements = subprocess.run(
        ["codesign", "-d", "--entitlements", ":-", str(binary)],
        capture_output=True, check=False,
    )
    plist = plistlib.loads(entitlements.stdout) if entitlements.returncode == 0 else {}
    if plist.get(HYPERVISOR_ENTITLEMENT) is not True:
        raise RuntimeError(f"{binary} lacks {HYPERVISOR_ENTITLEMENT}: HV_DENIED waiting to happen")
    return {
        "path": str(binary),
        "sha256": native_go_build.sha256_file(binary),
        "cdhash": embed_go_build_abba.codesign_cdhash(binary),
        "macho_uuid": native_abba.macho_uuid(binary),
        "entitlement_sha256": native_abba.entitlement_digest(binary),
        "has_dof_carrick": native_abba.has_dof_carrick(binary),
    }


def git_state(repo: pathlib.Path) -> dict[str, object]:
    status = native_go_build.git_output(repo, "status", "--porcelain").splitlines()
    return {
        "repo": str(repo),
        "head": native_go_build.git_output(repo, "rev-parse", "HEAD"),
        "branch": native_go_build.git_output(repo, "rev-parse", "--abbrev-ref", "HEAD"),
        "dirty": bool(status),
        "status": status,
    }


def docker_oracles_or_absent() -> list[str]:
    """Running Docker oracles; an unreachable daemon runs none."""
    try:
        return native_go_build.running_docker_oracles()
    except (RuntimeError, FileNotFoundError, subprocess.TimeoutExpired):
        return []


def preflight(binary: pathlib.Path, *, allow_busy: bool, run_id: str | None = None) -> dict[str, object]:
    reasons = native_go_build.busy_host_reasons()
    foreign = native_go_build.foreign_workload_census(
        current_run_id=run_id, known_receipt_binaries=(binary,)
    )
    oracles = docker_oracles_or_absent()
    record = {
        "busy_reasons": reasons,
        "foreign_processes": foreign,
        "docker_oracles": oracles,
        "load_average": list(os.getloadavg()),
        "allow_busy": allow_busy,
    }
    if oracles:
        # Never overridable: Carrick beside a Docker VM starves both.
        raise RuntimeError("a Docker oracle is running beside the Carrick phase: " + json.dumps(oracles))
    if (reasons or foreign) and not allow_busy:
        raise RuntimeError("host is not quiet: " + json.dumps({"busy": reasons, "foreign": foreign}))
    return record


def arm_environment(arm: Arm, arms: Sequence[Arm], run_id: str) -> dict[str, str]:
    native_go_build.reject_ambient_carrick(os.environ, {})
    environment = dict(os.environ)
    for other in arms:
        for key, _ in other.environment:
            environment.pop(key, None)
    environment.update(arm.env())
    environment["CARRICK_RUN_ID"] = run_id
    return environment


def run_id_for(prefix: str, *parts: object) -> str:
    return "-".join([prefix, *(str(part) for part in parts)])


def timed(
    argv: list[str], environment: dict[str, str], timeout_s: int
) -> dict[str, object]:
    before = resource.getrusage(resource.RUSAGE_CHILDREN)
    started = time.monotonic_ns()
    timed_out = False
    try:
        result = subprocess.run(
            argv, cwd=REPO, env=environment, capture_output=True, text=True,
            timeout=timeout_s, check=False,
        )
        stdout, stderr, rc = result.stdout, result.stderr, result.returncode
    except subprocess.TimeoutExpired as error:
        timed_out = True
        stdout = native_go_build.combined_output(error.stdout, None)
        stderr = native_go_build.combined_output(None, error.stderr)
        rc = None
    elapsed_ms = (time.monotonic_ns() - started) // 1_000_000
    after = resource.getrusage(resource.RUSAGE_CHILDREN)
    user = after.ru_utime - before.ru_utime
    system = after.ru_stime - before.ru_stime
    workload_ms = None
    try:
        workload_ms = native_go_build.workload_ns_from_stdout(stdout) // 1_000_000
    except ValueError:
        pass
    return {
        "argv": argv,
        "return_code": rc,
        "timed_out": timed_out,
        "elapsed_ms": elapsed_ms,
        "cpu_user_s": round(user, 6),
        "cpu_sys_s": round(system, 6),
        "cpu_s": round(user + system, 6),
        "workload_ms": workload_ms,
        "stdout_tail": stdout[-4000:],
        "stderr_tail": stderr[-4000:],
    }


def sample_ok(workload: Workload, sample: dict[str, object], accept_nonzero: bool) -> bool:
    if sample["timed_out"]:
        return False
    if workload.has_window:
        return sample["return_code"] == 0 and sample["workload_ms"] is not None and "BUILD_OK" in str(sample["stdout_tail"])
    return sample["return_code"] == 0 or (accept_nonzero and sample["return_code"] is not None)


def cleanup(run_id: str) -> dict[str, object]:
    return native_go_build.carrick_cleanup(REPO, run_id)


def abba_positions(quads: int) -> list[tuple[str, int | None, str]]:
    """(position, quad, arm-letter): one warm-up per arm, then A1 B1 B2 A2."""
    if quads < 2:
        raise ValueError("at least two quads are required for paired statistics")
    positions: list[tuple[str, int | None, str]] = [("warmup-a", None, "A"), ("warmup-b", None, "B")]
    for index in range(1, quads + 1):
        positions.extend(
            (f"q{index}-{name}", index, name[0].upper()) for name in ("a1", "b1", "b2", "a2")
        )
    return positions


def summarize_abba(rows: Sequence[dict[str, object]], metric: str) -> dict[str, object] | None:
    """Per-quad candidate/control ratios with paired_stats' fixed estimators."""
    by_quad: dict[int, dict[str, list[float]]] = {}
    for row in rows:
        if row["quad"] is None:
            continue
        value = row[metric]
        if value is None:
            return None
        by_quad.setdefault(int(row["quad"]), {"A": [], "B": []})[str(row["arm_letter"])].append(float(value))
    ratios, control, candidate, wins, ties = [], [], [], 0, 0
    for quad in sorted(by_quad):
        a, b = by_quad[quad]["A"], by_quad[quad]["B"]
        if len(a) != 2 or len(b) != 2 or min(a + b) <= 0:
            return None
        a_mean, b_mean = sum(a) / 2, sum(b) / 2
        control.append(a_mean)
        candidate.append(b_mean)
        ratios.append(b_mean / a_mean)
        wins += b_mean < a_mean
        ties += b_mean == a_mean
    if len(ratios) < 2:
        return None
    bootstrap = paired_stats.paired_bootstrap(ratios)
    return {
        "quads": len(ratios),
        "control_median": paired_stats.median_binary64(control),
        "candidate_median": paired_stats.median_binary64(candidate),
        "median_ratio_candidate_over_control": paired_stats.median_binary64(ratios),
        "bootstrap_95": [bootstrap.two_sided_lower, bootstrap.two_sided_upper],
        "candidate_wins": wins,
        "ties": ties,
        "sign_test": paired_stats.exact_probability_json(
            paired_stats.exact_one_sided_sign_probability(wins, len(ratios) - ties)
        ),
        "resolution": paired_stats.ratio_resolution(ratios),
        "log_ratio_sd": statistics.stdev(math.log(r) for r in ratios),
    }


def utc_now() -> str:
    return datetime.datetime.now(datetime.UTC).isoformat()


def campaign_header(args: argparse.Namespace, schema: str) -> dict[str, object]:
    header: dict[str, object] = {
        "schema": schema,
        "started_at": utc_now(),
        "campaign": args.campaign,
        "evidence": not args.validation,
        "validation_only": args.validation,
        "harness_git": git_state(REPO),
        "host": {
            "platform": platform.platform(),
            "machine": platform.machine(),
            "node": platform.node(),
            "logical_cpus": os.cpu_count(),
        },
    }
    return header


def run_carrick_phase(args: argparse.Namespace) -> dict[str, object]:
    arms = parse_arms(args.arm)
    suites = load_suites(*args.manifest)
    workloads = [resolve_workload(name, suites) for name in args.workload]
    binary = args.binary.resolve()
    identity = binary_identity(binary)
    payload = campaign_header(args, SCHEMA_CARRICK)
    payload.update(
        binary=identity,
        source_git=git_state(args.source_repo) if args.source_repo else None,
        arms={"A": dataclasses.asdict(arms[0]), "B": dataclasses.asdict(arms[1])},
        quads=args.quads,
        workloads={},
    )
    if payload["harness_git"]["dirty"] and not args.validation:  # type: ignore[index]
        raise RuntimeError("timing evidence requires a clean harness tree")
    if args.validation:
        positions = [("validation-a", None, "A"), ("validation-b", None, "B")]
    else:
        positions = abba_positions(args.quads)
    failures = 0
    for workload in workloads:
        rows: list[dict[str, object]] = []
        for position, quad, letter in positions:
            arm = arms[0] if letter == "A" else arms[1]
            run_id = run_id_for(args.campaign, "t", workload.name, position)
            receipt = preflight(binary, allow_busy=args.allow_busy or args.validation)
            sample = timed(
                carrick_argv(workload, binary, run_id),
                arm_environment(arm, arms, run_id),
                args.timeout_s or workload.timeout_s,
            )
            sample.update(
                run_id=run_id, position=position, quad=quad, arm_letter=letter,
                arm=arm.label, preflight=receipt, cleanup=cleanup(run_id),
            )
            sample["ok"] = sample_ok(workload, sample, args.accept_nonzero)
            failures += not sample["ok"]
            rows.append(sample)
            print(
                f"[carrick] {workload.name} {position} arm={arm.label} run_id={run_id} "
                f"ok={sample['ok']} wall_ms={sample['elapsed_ms']} cpu_s={sample['cpu_s']} "
                f"workload_ms={sample['workload_ms']}",
                flush=True,
            )
        if binary_identity(binary) != identity:
            raise RuntimeError("the measured binary changed during the campaign")
        all_ok = all(row["ok"] for row in rows)
        payload["workloads"][workload.name] = {  # type: ignore[index]
            "image": workload.image,
            "samples": rows,
            "all_ok": all_ok,
            "summary": (
                {metric: summarize_abba(rows, metric) for metric in METRICS}
                if all_ok and not args.validation
                else None
            ),
        }
    payload["finished_at"] = utc_now()
    payload["failures"] = failures
    return payload


def trace_argv(
    binary: pathlib.Path, profile: str, raw: pathlib.Path, summary: pathlib.Path,
    bound_s: int, run_argv: list[str],
) -> list[str]:
    return [
        str(binary), "trace", "--profile", profile,
        "--profile-bound-seconds", str(bound_s),
        "--trace-out", str(raw), "--summary-jsonl", str(summary),
        "--", *run_argv[1:],
    ]


def attribution_bound(timeout_s: int) -> int:
    """Twice the workload budget, in the profile's 10 s granularity."""
    return min(21_600, max(30, math.ceil(2 * timeout_s / 10) * 10))


def run_attribution_phase(args: argparse.Namespace) -> dict[str, object]:
    arms = parse_arms(args.arm)
    suites = load_suites(*args.manifest)
    workloads = [resolve_workload(name, suites) for name in args.workload]
    binary = args.binary.resolve()
    identity = binary_identity(binary)
    out_dir = args.output.parent / f"{args.campaign}-attribution"
    out_dir.mkdir(parents=True, exist_ok=True)
    payload = campaign_header(args, SCHEMA_ATTRIBUTION)
    payload.update(binary=identity, source_git=git_state(args.source_repo) if args.source_repo else None,
                   arms={"A": dataclasses.asdict(arms[0]), "B": dataclasses.asdict(arms[1])},
                   workloads={}, perturbation="instrumented: counts and shares only, never timings")
    failures = 0
    for workload in workloads:
        per_arm: dict[str, object] = {}
        for arm in arms:
            per_profile: dict[str, object] = {}
            for profile in args.profile:
                run_id = run_id_for(args.campaign, "a", workload.name, arm.label, profile.removeprefix("hvpatch-"))
                raw = out_dir / f"{run_id}.raw"
                summary = out_dir / f"{run_id}.summary.json"
                summary.unlink(missing_ok=True)
                receipt = preflight(binary, allow_busy=args.allow_busy or args.validation)
                argv = trace_argv(binary, profile, raw, summary, attribution_bound(workload.timeout_s),
                                  carrick_argv(workload, binary, run_id))
                sample = timed(argv, arm_environment(arm, arms, run_id), attribution_bound(workload.timeout_s) + 120)
                parsed = json.loads(summary.read_text()) if summary.is_file() else None
                accepted = sample["return_code"] == 0 and parsed is not None
                failures += not accepted
                per_profile[profile] = {
                    "run_id": run_id, "accepted": accepted, "raw": str(raw),
                    "summary": parsed, "preflight": receipt, "cleanup": cleanup(run_id),
                    "trace": {k: sample[k] for k in ("argv", "return_code", "timed_out", "stderr_tail", "stdout_tail")},
                }
                print(f"[attribution] {workload.name} arm={arm.label} {profile} run_id={run_id} accepted={accepted}", flush=True)
            per_arm[arm.label] = per_profile
        payload["workloads"][workload.name] = per_arm  # type: ignore[index]
    if binary_identity(binary) != identity:
        raise RuntimeError("the measured binary changed during the campaign")
    payload["finished_at"] = utc_now()
    payload["failures"] = failures
    return payload


def run_docker_phase(args: argparse.Namespace) -> dict[str, object]:
    suites = load_suites(*args.manifest)
    workloads = [resolve_workload(name, suites) for name in args.workload]
    alive = [
        row for row in native_go_build.foreign_workload_census()
        if "carrick" in row
    ]
    if alive:
        raise RuntimeError("Carrick is running; the Docker phase never overlaps it: " + json.dumps(alive))
    payload = campaign_header(args, SCHEMA_DOCKER)
    payload["workloads"] = {}
    failures = 0
    for workload in workloads:
        provenance = native_go_build.docker_image_provenance(workload.image)
        rows = []
        for index in range(args.samples + 1):
            run_id = run_id_for(args.campaign, "d", workload.name, index)
            sample = timed(docker_argv(workload, run_id), dict(os.environ), args.timeout_s or workload.timeout_s)
            sample.update(run_id=run_id, warmup=index == 0, cleanup=native_go_build.docker_cleanup(run_id))
            sample["ok"] = sample_ok(workload, sample, args.accept_nonzero)
            failures += not sample["ok"]
            rows.append(sample)
            print(f"[docker] {workload.name} #{index} ok={sample['ok']} wall_ms={sample['elapsed_ms']} workload_ms={sample['workload_ms']}", flush=True)
        measured = [row for row in rows if not row["warmup"] and row["ok"]]
        payload["workloads"][workload.name] = {  # type: ignore[index]
            "image": provenance,
            "samples": rows,
            "median_elapsed_ms": paired_stats.median_binary64([r["elapsed_ms"] for r in measured]) if measured else None,
            "median_workload_ms": (
                paired_stats.median_binary64([r["workload_ms"] for r in measured])
                if measured and all(r["workload_ms"] is not None for r in measured) else None
            ),
            # The docker client's RUSAGE is not the container's CPU: never compare it.
            "cpu_note": "docker client CPU only; the build runs in the LinuxKit VM",
        }
    payload["finished_at"] = utc_now()
    payload["failures"] = failures
    return payload


def _median_of(rows: Sequence[dict[str, object]], letter: str, metric: str) -> float | None:
    values = [r[metric] for r in rows if r.get("arm_letter") == letter and r.get("quad") is not None and r.get("ok")]
    if not values or any(v is None for v in values):
        return None
    return paired_stats.median_binary64([float(v) for v in values])  # type: ignore[arg-type]


def build_report(carrick: dict, attribution: dict | None, docker: dict | None) -> dict[str, object]:
    arms = carrick["arms"]
    report: dict[str, object] = {"schema": SCHEMA_REPORT, "binary": carrick["binary"], "arms": arms, "workloads": {}}
    for name, data in carrick["workloads"].items():
        rows = data["samples"]
        entry: dict[str, object] = {"all_ok": data["all_ok"], "abba": data["summary"]}
        oracle = (docker or {}).get("workloads", {}).get(name)
        for letter in ("A", "B"):
            label = arms[letter]["label"]
            arm_row: dict[str, object] = {
                "median_elapsed_ms": _median_of(rows, letter, "elapsed_ms"),
                "median_workload_ms": _median_of(rows, letter, "workload_ms"),
                "median_cpu_s": _median_of(rows, letter, "cpu_s"),
            }
            if oracle and oracle.get("median_elapsed_ms") and arm_row["median_elapsed_ms"]:
                arm_row["elapsed_over_docker"] = arm_row["median_elapsed_ms"] / oracle["median_elapsed_ms"]  # type: ignore[operator]
            if oracle and oracle.get("median_workload_ms") and arm_row["median_workload_ms"]:
                arm_row["workload_over_docker"] = arm_row["median_workload_ms"] / oracle["median_workload_ms"]  # type: ignore[operator]
            exit_summary = (((attribution or {}).get("workloads", {}).get(name, {}).get(label, {})
                             .get("hvpatch-exit-attribution", {}) or {}).get("summary"))
            if exit_summary:
                arm_row["exits_by_bucket"] = {k: v["exits"] for k, v in exit_summary["by_bucket"].items()}
                arm_row["host_oncpu_ms_by_bucket"] = {k: v["host_oncpu_ns"] / 1e6 for k, v in exit_summary["by_bucket"].items()}
                arm_row["executor_guest_oncpu_share"] = exit_summary["guest_oncpu_ns"] / max(1, exit_summary["guest_oncpu_ns"] + exit_summary["host_oncpu_ns"])
                arm_row["top_forwarded"] = [(r["nr"], r["name"], r["count"]) for r in exit_summary["forwarded"][:10]]
            cpu_summary = (((attribution or {}).get("workloads", {}).get(name, {}).get(label, {})
                            .get("hvpatch-carrier-cpu-attribution", {}) or {}).get("summary"))
            if cpu_summary:
                arm_row["carrier_cpu_attribution"] = cpu_summary
                population = max(1, int(cpu_summary["sample_population"]))
                arm_row["carrier_cpu_share"] = {
                    name: int(cpu_summary[f"{key}_samples"]) / population
                    for name, key in CARRIER_SHARE_KEYS
                }
            entry[label] = arm_row
        if oracle:
            entry["docker"] = {k: oracle.get(k) for k in ("median_elapsed_ms", "median_workload_ms")}
        report["workloads"][name] = entry  # type: ignore[index]
    return report


def render_report(report: dict[str, object]) -> str:
    arms = report["arms"]  # type: ignore[index]
    labels = [arms["A"]["label"], arms["B"]["label"]]  # type: ignore[index]
    lines = [
        "| workload | arm | wall ms | window ms | cpu s | wall/docker | window/docker | exits syscall/fault/kick-idle/other | host ms syscall/fault/kick-idle/other | carrier CPU % guest/syscall/fault/sched |",
        "|---|---|---|---|---|---|---|---|---|---|",
    ]
    for name, entry in report["workloads"].items():  # type: ignore[union-attr]
        for label in labels:
            row = entry.get(label, {})
            exits = row.get("exits_by_bucket")
            host = row.get("host_oncpu_ms_by_bucket")
            share = row.get("carrier_cpu_share")
            order = ("syscall", "fault", "kick-idle", "other")
            fmt = lambda v, spec: "-" if v is None else format(v, spec)  # noqa: E731
            lines.append(
                f"| {name} | {label} | {fmt(row.get('median_elapsed_ms'), '.0f')} | {fmt(row.get('median_workload_ms'), '.0f')} "
                f"| {fmt(row.get('median_cpu_s'), '.2f')} | {fmt(row.get('elapsed_over_docker'), '.2f')}x "
                f"| {fmt(row.get('workload_over_docker'), '.2f')}x "
                f"| {'/'.join(str(exits[k]) for k in order) if exits else '-'} "
                f"| {'/'.join(format(host[k], '.0f') for k in order) if host else '-'} "
                f"| {'/'.join(format(100 * share[k], '.0f') for k in ('guest', 'syscall', 'fault', 'sched')) if share else '-'} |"
            )
    return "\n".join(lines)


def parse_args(argv: Sequence[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="command", required=True)
    for name in ("plan", "carrick", "attribution", "docker"):
        p = sub.add_parser(name)
        p.add_argument("--workload", action="append", help=f"repeatable; default {', '.join(DEFAULT_WORKLOADS)}")
        p.add_argument("--manifest", type=pathlib.Path, action="append",
                       help="suite manifests (repeatable); default suites.toml + manifests/el1-real-workloads-v1.toml")
        p.add_argument("--campaign", default=f"el1ab-{os.getpid()}", help="run-id prefix (unique per campaign)")
        p.add_argument("--output", type=pathlib.Path, default=REPO / f"target/perf/el1-workload-ab/{name}.json")
        p.add_argument("--timeout-s", type=int, default=0, help="override each workload's own budget")
        p.add_argument("--accept-nonzero", action="store_true",
                       help="suites only: accept a completed nonzero exit (recorded)")
        p.add_argument("--validation", action="store_true",
                       help="instrument validation: one sample per arm, NOT evidence")
        if name != "docker":
            p.add_argument("--binary", type=pathlib.Path, default=REPO / "target/release/carrick")
            p.add_argument("--source-repo", type=pathlib.Path, help="worktree the binary was built from")
            p.add_argument("--arm", action="append", help=f"exactly two; default {' and '.join(DEFAULT_ARMS)}")
            p.add_argument("--allow-busy", action="store_true", help="debug only; recorded")
        if name == "plan":
            p.add_argument("--check-harness", action="store_true")
        if name == "carrick":
            p.add_argument("--quads", type=int, default=6)
        if name == "attribution":
            p.add_argument("--profile", action="append", choices=ATTRIBUTION_PROFILES)
        if name == "docker":
            p.add_argument("--samples", type=int, default=5)
    rep = sub.add_parser("report")
    rep.add_argument("--carrick", type=pathlib.Path, required=True)
    rep.add_argument("--attribution", type=pathlib.Path)
    rep.add_argument("--docker", type=pathlib.Path)
    rep.add_argument("--output", type=pathlib.Path, default=REPO / "target/perf/el1-workload-ab/report.json")
    args = parser.parse_args(argv)
    if args.command != "report":
        args.workload = args.workload or list(DEFAULT_WORKLOADS)
        args.manifest = args.manifest or list(DEFAULT_MANIFESTS)
        if hasattr(args, "arm"):
            args.arm = args.arm or list(DEFAULT_ARMS)
        if hasattr(args, "profile"):
            args.profile = args.profile or list(ATTRIBUTION_PROFILES)
    return args


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(sys.argv[1:] if argv is None else argv)
    if args.command == "report":
        carrick = json.loads(args.carrick.read_text())
        attribution = json.loads(args.attribution.read_text()) if args.attribution else None
        docker = json.loads(args.docker.read_text()) if args.docker else None
        report = build_report(carrick, attribution, docker)
        native_go_build.write_json_atomic(args.output, report)
        print(render_report(report))
        return 0
    if args.command == "plan":
        arms = parse_arms(args.arm)
        suites = load_suites(*args.manifest)
        binary = args.binary.resolve()
        for name in args.workload:
            workload = resolve_workload(name, suites)
            if args.check_harness:
                check_against_harness(workload, binary)
            run_id = run_id_for(args.campaign, "t", name, "q1-a1")
            print(f"# {name} (image {workload.image}, budget {workload.timeout_s}s)")
            for arm in arms:
                env = " ".join(f"{k}={v}" for k, v in arm.environment) or "(binary default)"
                print(f"  carrick[{arm.label}] env: {env}")
            print(f"  carrick: {' '.join(carrick_argv(workload, binary, run_id))}")
            print(f"  docker:  {' '.join(docker_argv(workload, run_id_for(args.campaign, 'd', name, 1)))}")
        if args.check_harness:
            print("harness argv check: OK")
        return 0
    phase = {"carrick": run_carrick_phase, "attribution": run_attribution_phase, "docker": run_docker_phase}
    payload = phase[args.command](args)
    native_go_build.write_json_atomic(args.output, payload)
    print(f"wrote {args.output} failures={payload['failures']}")
    return 0 if payload["failures"] == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
