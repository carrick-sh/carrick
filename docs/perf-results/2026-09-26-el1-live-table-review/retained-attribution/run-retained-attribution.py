from pathlib import Path
import base64, hashlib, json, os, subprocess
root = Path.cwd()
base = root / "target/el1-completion/live-integrated"
out = base / "retained-attribution"
out.mkdir(exist_ok=True)
image = "ubuntu@sha256:7607b6f97024ef850f1bd6e91a89273beb5973d04432c5b87f15f813d64b9c05"
info = json.loads(subprocess.check_output(["docker", "image", "inspect", image]))[0]
assert info["Architecture"] == "arm64"
assert info["RootFS"]["Layers"] == ["sha256:d9a56420aee7ff835e0c05fc666d1237d40f0da5fe338738e651b01db4672a5d"]
snippet = "base64 -d > /tmp/p && chmod +x /tmp/p && /tmp/p"
rows = []
for venue in ["aa5d55dd6", "863e81757", "docker"]:
    for name in ["ppollwaitset", "sigprofvdso"]:
        probe = root / "conformance-probes/target/aarch64-unknown-linux-gnu/release" / name
        data = base64.b64encode(probe.read_bytes()) + b"\n"
        for sample in [1, 2]:
            run_id = f"el1-retained-{venue}-{name}-{sample}-20260926"
            env = os.environ.copy()
            env["CARRICK_RUN_ID"] = run_id
            if venue == "docker":
                cmd = ["docker", "run", "--rm", "--pull=never", "--name", run_id, "--platform", "linux/arm64", "-i", image, "/bin/sh", "-c", snippet]
            else:
                binary = base / f"cli-frozen-{venue}"
                record = json.loads((base / f"cli-artifact-{venue}.json").read_text())
                assert hashlib.sha256(binary.read_bytes()).hexdigest() == record["sha256"]
                cmd = [str(binary), "run", "--platform", "linux/arm64", "--fs", "host", "ubuntu:24.04", "/bin/sh", "-c", snippet]
            result = None
            try:
                result = subprocess.run(cmd, input=data, capture_output=True, env=env, timeout=90)
            finally:
                if venue == "docker":
                    cleanup = subprocess.run(["docker", "ps", "-aq", "--filter", f"name=^/{run_id}$"], capture_output=True, text=True, check=True).stdout
                    if cleanup.strip():
                        subprocess.run(["docker", "rm", "-f", run_id], check=True)
                else:
                    cleanup = subprocess.run([str(root / "scripts/sudo/kill.sh"), run_id], capture_output=True, text=True, check=True).stdout
            assert result is not None
            (out / f"{run_id}.out").write_bytes(result.stdout)
            (out / f"{run_id}.err").write_bytes(result.stderr)
            observation = [line for line in result.stdout.decode(errors="replace").splitlines() if line.startswith(("wake_after_ms_bucket=", "timer_pc_in_text="))]
            rows.append({"venue": venue, "probe": name, "sample": sample, "command": cmd, "run_id": run_id, "exit_code": result.returncode, "probe_sha256": hashlib.sha256(probe.read_bytes()).hexdigest(), "observations": observation, "cleanup": cleanup})
            (out / "receipt.json").write_text(json.dumps({"native_image": image, "rootfs": info["RootFS"], "rows": rows}, indent=2) + "\n")
            print(venue, name, sample, result.returncode, observation, flush=True)
            assert result.returncode == 0, rows[-1]
