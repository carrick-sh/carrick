from pathlib import Path
import subprocess,os,json,time,hashlib
root=Path.cwd(); out=root/'docs/perf-results/2026-09-21-syscall-floor/watch-refresh'; probe=root/'conformance-probes/target/aarch64-unknown-linux-musl/release/perf_inotify09_scale'; binary=Path('/Volumes/CaseSensitive/carrick/target/syscall-floor/carrick-discard-retire'); image='localhost:5050/ltp@sha256:bc75ded40c5827f2ec9e1891edc23b988beae3f428f5be2c8fd7e3ee52fee80b'
for phase in ['carrick','docker']:
 for i in range(3):
  rid=f'floor-watch-refresh-{phase}-{i}'; env=os.environ.copy(); env['CARRICK_RUN_ID']=rid; env['CARRICK_INSECURE_REGISTRIES']='localhost:5050'
  prefix=[str(binary),'run','--max-traps','18446744073709551615','--fs','host'] if phase=='carrick' else ['docker','run','--rm','--name',rid,'--platform','linux/arm64']
  argv=prefix+['-v',f'{probe}:/probe:ro',image,'/bin/sh','-c','/probe watch-only']; start=time.monotonic()
  p=subprocess.Popen(argv,env=env,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
  try: stdout,stderr=p.communicate(timeout=90)
  except subprocess.TimeoutExpired:
   subprocess.run([str(root/'scripts/sudo/kill.sh'),rid] if phase=='carrick' else ['docker','rm','-f',rid],check=False); raise
  (out/f'{rid}.out').write_bytes(stdout); (out/f'{rid}.err').write_bytes(stderr)
  row=dict(phase=phase,run_id=rid,argv=argv,returncode=p.returncode,elapsed_s=time.monotonic()-start,probe_sha256=hashlib.sha256(probe.read_bytes()).hexdigest(),binary_sha256=hashlib.sha256(binary.read_bytes()).hexdigest() if phase=='carrick' else None)
  with (out/'runs.jsonl').open('a') as f:f.write(json.dumps(row)+'\n')
  assert p.returncode==0 and b'probe_complete=1' in stdout,(rid,p.returncode)
  print(rid,stdout.decode().splitlines()[-5:],flush=True)
