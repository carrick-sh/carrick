#!/usr/bin/env python3
"""Paired release wake-latency acceptance; never builds, signs, or acquires a lease."""
import argparse
import hashlib
import fcntl
import json
import math
import os
from pathlib import Path
import platform
import re
import signal
import socket
import statistics
import stat
import subprocess
import time

TEST = "el1_sched_signal_delivery_contract_sample"
PREFIX = "signal-contract-result "
PATH_MEASURED = "parked-thread tgkill / handler / rt_sigreturn / resumed futex wait"


class Rejected(RuntimeError):
    pass


def require(ok, reason):
    if not ok:
        raise Rejected(reason)


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def pinned(image):
    require(re.fullmatch(r"[^\s@]+@sha256:[0-9a-f]{64}", image), "image must be digest-pinned")


def parse_metric(stdout):
    lines = [line for line in stdout.splitlines() if line.startswith("wfi-signal ")]
    require(len(lines) == 1, "missing or duplicate fixture result")
    fields = {}
    for token in lines[0].split()[1:]:
        require(token.count("=") == 1, "malformed fixture field")
        key, value = token.split("=")
        require(key not in fields, f"duplicate metric {key}")
        try:
            fields[key] = float(value)
        except ValueError as error:
            raise Rejected(f"invalid metric {key}") from error
    require(set(fields) == {"rounds", "eintr", "handled", "wake_p50_us", "wake_max_us"},
            "missing or unknown fixture metric")
    require(all(math.isfinite(v) and v > 0 for v in fields.values()), "nonfinite or zero metric")
    require(all(fields[k] == 200 for k in ("rounds", "eintr", "handled")), "incorrect signal counts")
    require(fields["wake_max_us"] >= fields["wake_p50_us"], "invalid maximum")
    return fields


def parse_sample(result, image=None):
    require(result["exit_code"] == 0, "nonzero child exit")
    if image is None:
        return parse_metric(result["stdout"])
    text = result["stdout"]
    require(len(re.findall(r"^running 1 test$", text, re.M)) == 1, "one test must actually run")
    require(len(re.findall(r"^test result: ok\. 1 passed; 0 failed; 0 ignored;", text, re.M)) == 1,
            "missing successful one-test summary")
    require(len(re.findall(rf"^test {TEST} \.\.\. ok$", text, re.M)) == 1,
            "named test did not finish")
    records = [line[len(PREFIX):] for line in text.splitlines() if line.startswith(PREFIX)]
    require(len(records) == 1, "missing or duplicate embed result")
    try:
        record = json.loads(records[0])
    except ValueError as error:
        raise Rejected("malformed embed result") from error
    require(record["image"] == image and record["exit_code"] == 0 and record["signal"] is None,
            "guest exit or image mismatch")
    require(record["idle_exits"] >= 200 and record["wfi_entries"] >= 200, "missing actual idle/WFI work")
    return parse_metric(record["stdout"])


def aggregate(pairs):
    require(len(pairs) >= 20, "at least 20 independent measured pairs required")
    carrick = statistics.median(p["carrick"]["wake_p50_us"] for p in pairs)
    docker = statistics.median(p["docker"]["wake_p50_us"] for p in pairs)
    require(all(math.isfinite(v) and v > 0 for v in (carrick, docker)), "invalid aggregate")
    ratio = carrick / docker
    return {"carrick_p50_us": carrick, "docker_p50_us": docker, "ratio": ratio,
            "maximum": 2.0, "passed": ratio <= 2.0}


def check_identity(expected, actual):
    require(expected == actual, "binary, fixture, source, signature, or image identity drift")


def validate_receipt(rows, head, artifact, fixture):
    """Bind existing signed-run evidence, never synthesize build provenance."""
    require(rows and all(r.get("schema") == "carrick.signed-embed-test.v1" for r in rows),
            "wrong signed receipt schema")

    def one(kind):
        found = [r for r in rows if r.get("record_type") == kind]
        require(len(found) == 1, f"missing or duplicate receipt {kind}")
        return found[0]

    header = one("header")
    require(header.get("source_head") == head and header.get("package") == "carrick-embed",
            "signed executable was not built at current HEAD for carrick-embed")
    require(isinstance(header.get("enabled_features"), list) and
            "conformance-metrics" not in header["enabled_features"], "instrumented receipt")
    matches = [r for r in rows if r.get("record_type") == "executable" and
               r.get("canonical_path") == artifact["canonical_path"]]
    require(len(matches) == 1, "missing or duplicate matching executable record")
    executable = matches[0]
    require(all(executable.get(k) == v for k, v in artifact.items()), "receipt executable identity mismatch")
    require(executable.get("executable_id") == f"{artifact['sha256']}:{artifact['canonical_path']}",
            "invalid executable id")
    executions = [r for r in rows if r.get("record_type") == "execution" and
                  r.get("executable_id") == executable["executable_id"]]
    require(executions and all(r.get("terminal_status") == "passed" and r.get("test_name") for r in executions),
            "matching executable lacks passed signed execution")
    validation = one("fixture_validation")
    require(validation.get("checkout_head") == head and validation.get("checkout_dirty") is False and
            validation.get("validation_method") == "input_identity", "invalid receipt fixture validation")
    for key in ("checkout_head", "checkout_dirty", "validation_method", "inputs_sha256", "manifest_sha256"):
        require(key in validation and validation[key] == fixture.get(key), f"fixture receipt mismatch: {key}")
    for key in ("inputs_sha256", "manifest_sha256"):
        require(re.fullmatch(r"[0-9a-f]{64}", validation[key]), f"invalid {key}")
    negative = one("unentitled_negative_control")
    require(negative.get("terminal_status") == "passed" and negative.get("entitlement_present") is False and
            negative.get("dof_carrick_present") is True and negative.get("source_executable_id") and
            negative.get("test_name", "").split("::")[-1] == "unsigned_executable_maps_hv_denied_to_entitlement",
            "missing standard passed unentitled negative control")
    cleanup = one("cleanup")
    require(cleanup.get("remaining_processes") == 0 and
            cleanup.get("carrick_run_id") == header.get("carrick_run_id") and header.get("carrick_run_id"),
            "signed receipt lacks zero scoped cleanup")
    return executable["executable_id"]


def child_run_id(campaign, label, lane):
    require(re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,30}", campaign), "campaign run id must fit child suffixes")
    require(label == "warmup" or re.fullmatch(r"pair-[0-9]{3,9}", label), "invalid sample label")
    require(lane in ("carrick", "docker"), "invalid sample lane")
    child = f"{campaign}-{label}-{lane}"
    require(len(child) <= 61 and child != campaign, "invalid child run id")
    return child


def gate_identity():
    """Read the existing host-lease holder's bounded validation protocol."""
    endpoint = os.environ.get("CARRICK_HOST_LEASE_SOCKET")
    require(endpoint, "an enclosing actual gate lease is required")
    with socket.socket(socket.AF_UNIX) as client:
        client.settimeout(5)
        client.connect(endpoint)
        data = b""
        deadline = time.monotonic() + 5
        while True:
            client.settimeout(max(0.001, deadline - time.monotonic()))
            chunk = client.recv(4096 - len(data))
            if not chunk:
                break
            data += chunk
            require(len(data) < 4096 and time.monotonic() < deadline, "invalid lease reply")
    identity = json.loads(data)
    require(identity["mode"] == "gate", "shared/Docker lease is not an enclosing gate")
    lock = Path(os.environ.get("CARRICK_HOST_LEASE_PATH", "/tmp/carrick-host-lease.lock")).stat()
    require((identity["dev"], identity["ino"]) == (lock.st_dev, lock.st_ino), "wrong lease lock")
    scope = identity.get("scope")
    require(scope is not None, "supervised gate scope required")
    fd = int(os.environ["CARRICK_HOST_LEASE_SCOPE_FD"])
    st = os.fstat(fd)
    require(stat.S_ISFIFO(st.st_mode) and fcntl.fcntl(fd, fcntl.F_GETFL) & os.O_ACCMODE == os.O_WRONLY,
            "lease scope must be the supervised writer")
    require((st.st_dev, st.st_ino) == (scope["dev"], scope["ino"]), "wrong lease scope")
    return identity


class Driver:
    def __init__(self, args):
        self.args = args
        self.root = Path(__file__).resolve().parents[2]
        self.binary = Path(args.binary).resolve()
        self.fixture = self.root / "target/embed-fixtures/el1-sched-aarch64"
        self.xtask = Path(args.xtask).resolve()
        self.receipt = Path(args.signed_receipt).resolve()
        self.output = Path(args.output).resolve()
        self.output.mkdir(parents=True, exist_ok=False)
        self.serial = 0
        self.report = {"path_measured": PATH_MEASURED, "warmup_excluded": [], "pairs": [],
                       "coverage_limit": "does not prove every timer or origin locking path", "passed": False}

    def save(self):
        (self.output / "report.json").write_text(json.dumps(self.report, indent=2, allow_nan=False) + "\n")

    def command(self, argv, timeout=30, checked=True, run_id=None):
        self.serial += 1
        stem = self.output / f"{self.serial:04d}"
        env = os.environ.copy()
        env.update(CARRICK_SIGNAL_CONTRACT_IMAGE=self.args.image, RUST_TEST_THREADS="1")
        env.pop("CARRICK_RUN_ID", None)
        if run_id is not None:
            env["CARRICK_RUN_ID"] = run_id
        scope = int(os.environ["CARRICK_HOST_LEASE_SCOPE_FD"])
        record = {"command": [str(a) for a in argv], "timeout_seconds": timeout,
                  "run_id": run_id, "command_role": "sample" if run_id else "system"}
        # Files, rather than pipes, preserve full output even on timeout/cancellation.
        with stem.with_suffix(".stdout").open("wb") as out, stem.with_suffix(".stderr").open("wb") as err:
            proc = subprocess.Popen(argv, cwd=self.root, env=env, stdin=subprocess.DEVNULL,
                                    stdout=out, stderr=err, start_new_session=True, pass_fds=(scope,))
            try:
                record["exit_code"] = proc.wait(timeout=timeout)
            except BaseException:
                try:
                    os.killpg(proc.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                proc.wait(timeout=5)
                record["exit_code"] = proc.returncode
                record["interrupted"] = True
                raise
            finally:
                stem.with_suffix(".json").write_text(json.dumps(record, indent=2) + "\n")
        record["stdout_sha256"] = sha(stem.with_suffix(".stdout"))
        record["stdout"] = stem.with_suffix(".stdout").read_text(errors="replace")
        record["stderr"] = stem.with_suffix(".stderr").read_text(errors="replace")
        if checked:
            require(record["exit_code"] == 0, f"command failed: {argv}; see {stem}")
        return record

    def cleanup_carrick(self, run_id):
        result = self.command(["sudo", "-n", str(self.root / "scripts/sudo/kill.sh"),
                               run_id], timeout=15)
        require(" = 0" in result["stdout"], "cleanup did not confirm zero scoped processes")
        require("killing" not in result["stdout"], "sample left scoped processes requiring cleanup")

    def identity(self):
        gate = gate_identity()
        head = self.command(["git", "rev-parse", "HEAD"])["stdout"].strip()
        dirty = self.command(["git", "status", "--porcelain", "--untracked-files=all"])["stdout"]
        require(not dirty, "acceptance requires a clean source tree")
        signature = self.command(["codesign", "-d", "--verbose=4", str(self.binary)])["stderr"]
        require(re.search(r"^CDHash=[0-9a-f]+$", signature, re.M), "missing CDHash")
        self.command(["codesign", "--verify", "--strict", str(self.binary)])
        ent = self.command(["codesign", "-d", "--entitlements", ":-", str(self.binary)])
        import plistlib
        plist = ent["stdout"].encode()
        require(plistlib.loads(plist).get("com.apple.security.hypervisor") is True, "missing hypervisor entitlement")
        uuid = self.command(["dwarfdump", "--uuid", str(self.binary)])["stdout"].strip()
        require(re.search(r"UUID: [0-9A-Fa-f-]{36} .*arm64", uuid), "missing ARM64 LC_UUID")
        load = self.command(["otool", "-l", str(self.binary)])["stdout"]
        require("__dof_carrick" in load, "missing USDT section")
        image = self.command(["docker", "image", "inspect", self.args.image, "--format", "{{json .}}"])["stdout"]
        info = json.loads(image)
        require(info["Os"] == "linux" and info["Architecture"] in ("arm64", "aarch64"), "wrong image architecture")
        require(self.args.image in info["RepoDigests"], "image digest absent")
        artifact = {"canonical_path": str(self.binary), "sha256": sha(self.binary),
                    "cdhash": re.search(r"^CDHash=([0-9a-f]+)$", signature, re.M)[1],
                    "lc_uuid": re.search(r"UUID: ([0-9A-Fa-f-]{36})", uuid)[1],
                    "entitlement_digest": ent["stdout_sha256"],
                    "entitlement_present": True, "dof_carrick_present": True}
        receipt_bytes = self.receipt.read_bytes()
        rows = [json.loads(line) for line in receipt_bytes.splitlines() if line.strip()]
        executable_id = validate_receipt(rows, head, artifact, self.report["fixture_identity"])
        return {"signed_receipt_sha256": hashlib.sha256(receipt_bytes).hexdigest(),
                "signed_receipt_path": str(self.receipt), "executable_id": executable_id, "head": head, "binary_sha256": sha(self.binary), "fixture_sha256": sha(self.fixture),
                "signature": signature, "entitlements": ent["stdout"], "uuid": uuid,
                "image_id": info["Id"], "image": self.args.image, "lease": gate}

    def pair(self, label, baseline):
        check_identity(baseline, self.identity())
        carrick_id = child_run_id(os.environ["CARRICK_RUN_ID"], label, "carrick")
        docker_id = child_run_id(os.environ["CARRICK_RUN_ID"], label, "docker")
        pair = {"label": label, "carrick_run_id": carrick_id, "docker_run_id": docker_id}
        self.report["warmup_excluded" if label == "warmup" else "pairs"].append(pair)
        self.save()
        try:
            result = self.command([str(self.binary), "--ignored", "--exact", TEST,
                                   "--show-output", "--test-threads=1"], timeout=150, checked=False, run_id=carrick_id)
            pair["carrick_raw"] = result
            pair["carrick"] = parse_sample(result, self.args.image)
        finally:
            self.save()
            self.cleanup_carrick(carrick_id)
        check_identity(baseline, self.identity())
        name = docker_id
        try:
            result = self.command(["docker", "run", "--name", name, "--rm", "--pull=never",
                                   "--platform", "linux/arm64", "--network=none",
                                   "--env", f"CARRICK_RUN_ID={docker_id}",
                                   "--mount", f"type=bind,src={self.fixture},dst=/opt/carrick/el1-sched,readonly",
                                   "--entrypoint", "/opt/carrick/el1-sched", self.args.image,
                                   "wfi-signal", "200"], timeout=150, checked=False, run_id=docker_id)
            pair["docker_raw"] = result
            pair["docker"] = parse_sample(result)
        finally:
            self.save()
            remaining = self.command(["docker", "ps", "-aq", "--filter", f"name=^/{re.escape(name)}$"])["stdout"].strip()
            if remaining:
                self.command(["docker", "rm", "-f", name])
                require(False, "Docker sample left a container requiring cleanup")
        check_identity(baseline, self.identity())
        self.save()

    def run(self):
        try:
            require(platform.system() == "Darwin" and platform.machine() == "arm64", "native ARM64 macOS required")
            require(self.args.samples >= 20, "at least 20 samples required")
            pinned(self.args.image)
            child_run_id(os.environ.get("CARRICK_RUN_ID", ""), "warmup", "carrick")
            require(self.binary.parent == self.root / "target/release/deps", "use the prebuilt target/release/deps executable")
            gate_identity()
            # Existing verifier checks the complete source inventory and executable
            # hashes against the restored fixture manifest, without compiling fixtures.
            self.report["fixture_validation"] = self.command([str(self.xtask), "fixtures", "verify", "--receipt", str(self.output / "fixture-validation.json")], timeout=120)
            self.report["fixture_identity"] = json.loads((self.output / "fixture-validation.json").read_text())
            docker = self.command(["docker", "info", "--format", "{{.OSType}}/{{.Architecture}}"])["stdout"].strip()
            require(docker in ("linux/arm64", "linux/aarch64"), "Docker daemon is not native ARM64 Linux")
            baseline = self.identity()
            self.report["provenance"] = baseline
            self.pair("warmup", baseline)
            for index in range(self.args.samples):
                self.pair(f"pair-{index:03d}", baseline)
            self.report["aggregate"] = aggregate(self.report["pairs"])
            require(self.report["aggregate"]["passed"], "runtime ratio exceeds 2.0")
            self.report["passed"] = True
        except BaseException as error:
            self.report["failure"] = f"{type(error).__name__}: {error}"
            raise
        finally:
            self.save()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", required=True, help="one already signed release el1_sched test executable")
    parser.add_argument("--signed-receipt", required=True, help="existing test-signed.sh artifact JSONL receipt")
    parser.add_argument("--xtask", required=True, help="prebuilt carrick-xtask for fixture verification")
    parser.add_argument("--image", required=True, help="same ARM64 image@sha256:digest for both lanes")
    parser.add_argument("--samples", type=int, default=20)
    parser.add_argument("--output", required=True, help="new directory for full evidence")
    args = parser.parse_args()
    def interrupted(_signum, _frame):
        raise KeyboardInterrupt("signal-delivery driver terminated")

    signal.signal(signal.SIGTERM, interrupted)
    Driver(args).run()


if __name__ == "__main__":
    main()
