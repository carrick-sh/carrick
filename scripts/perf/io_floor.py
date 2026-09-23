#!/usr/bin/env python3
"""Serialized same-source host-I/O controls; no tracing, no durable-write claim.

Compile io-floor.c for native macOS and static Linux ARM64 into --shared as
io-floor-macos/io-floor-linux. Host and Carrick use the SAME host directory;
Docker-local and Docker-bind use the exact same Linux executable. All paths
validate bytes, length, offset and cleanup. No failed observation is retried.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import statistics
import subprocess
import time


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--shared', type=Path, required=True)
    ap.add_argument('--output', type=Path, required=True)
    ap.add_argument('--carrick', type=Path, required=True)
    ap.add_argument('--image', required=True)
    ap.add_argument('--iterations', type=int, default=16384)
    ap.add_argument('--samples', type=int, default=9)
    args = ap.parse_args()
    shared = args.shared.resolve()
    out = args.output.resolve()
    out.mkdir(parents=True, exist_ok=False)
    carrick = args.carrick.resolve()
    native = shared/'io-floor-macos'
    linux = shared/'io-floor-linux'
    identities = {str(p): sha(p) for p in [native, linux, carrick, Path(__file__).resolve(), Path(__file__).with_name('io-floor.c').resolve()]}
    metadata = {'image': args.image, 'shared': str(shared), 'identities': identities,
                'iterations': args.iterations, 'samples': args.samples,
                'phases_serialized': True, 'fsync': False}
    for name, cmd in [('uname', ['uname', '-a']), ('filesystem', ['df', '-h', str(shared)]),
                      ('native_compiler', ['clang', '--version']),
                      ('linux_compiler', ['aarch64-linux-gnu-gcc', '--version'])]:
        r = subprocess.run(cmd, capture_output=True, text=True)
        metadata[name] = {'returncode': r.returncode, 'stdout': r.stdout, 'stderr': r.stderr}
    (out/'inputs.json').write_text(json.dumps(metadata, indent=2)+'\n')
    # Never overlap Carrick with Docker. Reversed-order blocks reduce drift.
    lanes = ['macos' if a == 'A' else 'carrick' for a in 'ABBAABBA']
    lanes += ['linux-local' if a == 'A' else 'docker-bind' for a in 'ABBAABBA']
    all_rows = []
    env = os.environ.copy()
    env['CARRICK_INSECURE_REGISTRIES'] = 'localhost:5005,localhost:5050'
    for index, lane in enumerate(lanes):
        rid = f'io-floor-{out.name}-{index}'
        host_file = shared/(rid+'.data')
        guest_file = '/bench/'+host_file.name
        counts = [str(args.iterations), str(args.samples)]
        if lane == 'macos':
            cmd = [str(native), str(host_file), *counts]
        elif lane == 'carrick':
            cmd = [str(carrick), 'run', '--max-traps', '18446744073709551615', '--fs', 'host',
                   '-v', f'{shared}:/bench', '--entrypoint', '/bench/io-floor-linux', args.image,
                   guest_file, *counts]
        else:
            cmd = ['docker', 'run', '--rm', '--name', rid, '--platform', 'linux/arm64',
                   '-v', f'{shared}:/bench', '--entrypoint', '/bench/io-floor-linux', args.image,
                   guest_file if lane == 'docker-bind' else '/tmp/'+host_file.name, *counts]
        env['CARRICK_RUN_ID'] = rid
        begin = time.monotonic()
        p = subprocess.Popen(cmd, env=env, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        try:
            stdout, stderr = p.communicate(timeout=120)
        except subprocess.TimeoutExpired:
            if lane == 'carrick':
                cleanup = subprocess.run(['scripts/sudo/kill.sh', rid], capture_output=True)
            elif lane.startswith('linux') or lane.startswith('docker'):
                cleanup = subprocess.run(['docker', 'rm', '-f', rid], capture_output=True)
            else:
                p.kill()
                cleanup = None
            if cleanup:
                (out/(rid+'.cleanup')).write_bytes(cleanup.stdout+cleanup.stderr)
            stdout, stderr = p.communicate(timeout=10)
            (out/(rid+'.out')).write_bytes(stdout)
            (out/(rid+'.err')).write_bytes(stderr)
            raise RuntimeError(f'{lane} timed out; retained fixture and evidence, no retry')
        elapsed = time.monotonic()-begin
        (out/(rid+'.out')).write_bytes(stdout)
        (out/(rid+'.err')).write_bytes(stderr)
        assert p.returncode == 0, (lane, p.returncode, stderr[-2000:])
        rows = [json.loads(line) for line in stdout.splitlines()]
        assert rows[-1] == {'schema': 1, 'verified': True, 'bytes': 64, 'offset': 0, 'removed': True}
        assert not host_file.exists(), host_file
        samples = rows[:-1]
        assert len(samples) == 4*args.samples
        values = {}
        for phase in ['seek', 'pwrite64', 'write64_seek', 'fstat']:
            selected = [r for r in samples if r['phase'] == phase]
            assert [r['sample'] for r in selected] == list(range(1, args.samples+1))
            assert all(r['iterations'] == args.iterations and r['elapsed_ns'] > 0 for r in selected)
            values[phase] = statistics.median(r['elapsed_ns']/r['iterations'] for r in selected)
        record = {'index': index, 'lane': lane, 'run_id': rid, 'argv': cmd, 'returncode': p.returncode,
                  'outer_seconds': elapsed, 'median_ns_per_iteration': values, 'samples': samples}
        all_rows.append(record)
        with (out/'runs.jsonl').open('a') as f:
            f.write(json.dumps(record)+'\n')
        print(json.dumps({k: record[k] for k in ['index', 'lane', 'median_ns_per_iteration']}), flush=True)
    assert all(sha(Path(p)) == digest for p, digest in identities.items()), 'artifact changed during screen'
    summary = {lane: {phase: statistics.median(r['median_ns_per_iteration'][phase] for r in all_rows if r['lane'] == lane)
                      for phase in ['seek', 'pwrite64', 'write64_seek', 'fstat']}
               for lane in ['macos', 'carrick', 'linux-local', 'docker-bind']}
    (out/'summary.json').write_text(json.dumps(summary, indent=2)+'\n')
    print(json.dumps(summary, indent=2), flush=True)


if __name__ == '__main__':
    main()
