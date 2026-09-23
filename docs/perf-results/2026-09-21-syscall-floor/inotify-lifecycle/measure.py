from pathlib import Path
import subprocess,os,json,hashlib,time,re,shutil,statistics
root=Path.cwd();out=root/'target/lease-cost/inotify-lifecycle';binary=out/'carrick-candidate'
image='localhost:5050/ltp@sha256:bc75ded40c5827f2ec9e1891edc23b988beae3f428f5be2c8fd7e3ee52fee80b'
probe=root/'conformance-probes/target/aarch64-unknown-linux-musl/release/perf_inotify09_scale'
rows=[]
for phase in ['carrick','docker']:
 for i in range(3):
  rid=f'inotify-states-{phase}-{i}-20260922'
  prefix=[str(binary),'run','--max-traps','18446744073709551615','--fs','host'] if phase=='carrick' else ['docker','run','--rm','--name',rid,'--platform','linux/arm64']
  cmd=prefix+['-v',str(probe)+':/probe:ro','--entrypoint','/bin/sh',image,'-c','/probe watch-states']
  env=os.environ.copy();env.update(CARRICK_RUN_ID=rid,CARRICK_INSECURE_REGISTRIES='localhost:5050')
  start=time.monotonic();p=subprocess.Popen(cmd,cwd=root,env=env,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
  try:so,se=p.communicate(timeout=45)
  except subprocess.TimeoutExpired:
   subprocess.run([str(root/'scripts/sudo/kill.sh'),rid] if phase=='carrick' else ['docker','rm','-f',rid]);raise
  (out/(rid+'.out')).write_bytes(so);(out/(rid+'.err')).write_bytes(se)
  cleanup=subprocess.run([str(root/'scripts/sudo/kill.sh'),rid] if phase=='carrick' else ['docker','ps','-a','--filter','name='+rid,'--format','{{.Names}}'],capture_output=True)
  (out/(rid+'.cleanup')).write_bytes(cleanup.stdout+cleanup.stderr)
  row=dict(phase=phase,index=i,argv=cmd,run_id=rid,returncode=p.returncode,elapsed_s=time.monotonic()-start,probe_sha256=hashlib.sha256(probe.read_bytes()).hexdigest(),binary_sha256=hashlib.sha256(binary.read_bytes()).hexdigest() if phase=='carrick' else None,cleanup_returncode=cleanup.returncode)
  rows.append(row);(out/'timing-runs.json').write_text(json.dumps(rows,indent=2)+'\n')
  assert p.returncode==0 and b'probe_complete=1' in so,(rid,p.returncode,se)
  assert so.count(b'sample_phase=')==63 and so.count(b'complete=1')==4
  assert cleanup.returncode==0
  if phase=='docker':assert not cleanup.stdout
  print(rid, '\n'.join(line for line in so.decode().splitlines() if line.startswith('phase=')),flush=True)
summary={}
for row in rows:
 for name,scale,ns in re.findall(r'phase=(\w+) scale=(\d+) samples=21 p50_ns_per_iter=(\d+) complete=1',(out/(row['run_id']+'.out')).read_text()):
  summary.setdefault(name,{}).setdefault(row['phase'],[]).append(int(ns))
for name,arms in summary.items():arms['raw_linux_ratio']=statistics.median(arms['carrick'])/statistics.median(arms['docker'])
(out/'timing-summary.json').write_text(json.dumps(summary,indent=2)+'\n')
print(json.dumps(summary,indent=2))
