from pathlib import Path
import subprocess,os,json,hashlib,time,re,shutil,statistics
r=Path.cwd();d=r/'target/lease-cost/inotify-transport-control';binary=d/'carrick-control'
probe=d/'probe-current';shutil.copy2(r/'conformance-probes/target/aarch64-unknown-linux-musl/release/perf_inotify09_scale',probe)
image='localhost:5050/ltp@sha256:bc75ded40c5827f2ec9e1891edc23b988beae3f428f5be2c8fd7e3ee52fee80b'
rows=[]
base_env=os.environ.copy();base_env.update(CARRICK_INSECURE_REGISTRIES='localhost:5050')
source_hash=hashlib.sha256((r/'conformance-probes/src/bin/perf_inotify09_scale.rs').read_bytes()).hexdigest()
def run(arm,index,workload,warmup=False):
 rid=f'itc-{workload}-{arm}-{index}-20260922'
 env=base_env.copy();env.update(CARRICK_RUN_ID=rid,CARRICK_HVF_SYSCALL_TRANSPORT=arm)
 code='/probe watch-controls && /probe watch-states' if workload=='micro' else '/opt/ltp/testcases/bin/inotify09'
 prefix=[str(binary),'run','--max-traps','18446744073709551615','--fs','host'] if arm!='docker' else ['docker','run','--rm','--name',rid,'--platform','linux/arm64']
 cmd=prefix+['-v',str(probe)+':/probe:ro','--entrypoint','/bin/sh',image,'-c',code]
 start=time.monotonic();p=subprocess.Popen(cmd,cwd=r,env=env,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
 bounded=False
 try:so,se=p.communicate(timeout=40 if workload=='ltp' else 60)
 except subprocess.TimeoutExpired:
  bounded=True
  subprocess.run([str(r/'scripts/sudo/kill.sh'),rid] if arm!='docker' else ['docker','rm','-f',rid],capture_output=True)
  so,se=p.communicate(timeout=10)
 elapsed=time.monotonic()-start
 (d/(rid+'.out')).write_bytes(so);(d/(rid+'.err')).write_bytes(se)
 cleanup=subprocess.run([str(r/'scripts/sudo/kill.sh'),rid] if arm!='docker' else ['docker','ps','-a','--filter','name='+rid,'--format','{{.Names}}'],capture_output=True)
 (d/(rid+'.cleanup')).write_bytes(cleanup.stdout+cleanup.stderr)
 row=dict(arm=arm,index=index,workload=workload,warmup=warmup,argv=cmd,run_id=rid,returncode=p.returncode,bounded=bounded,elapsed_s=elapsed,probe_sha256=hashlib.sha256(probe.read_bytes()).hexdigest(),probe_source_sha256=source_hash,binary_sha256=hashlib.sha256(binary.read_bytes()).hexdigest() if arm!='docker' else None,cleanup_returncode=cleanup.returncode)
 if workload=='micro':
  row['medians']={n:int(v) for n,s,v in re.findall(rb'phase=(\w+) scale=(\d+) samples=21 p50_ns_per_iter=(\d+) complete=1',so) for n in [n.decode()]}
  row['samples']=so.count(b'sample_phase=')
 rows.append(row);(d/'runs.json').write_text(json.dumps(rows,indent=2)+'\n')
 assert not bounded and p.returncode==0,(rid,p.returncode,se)
 assert cleanup.returncode==0
 if arm=='docker':assert not cleanup.stdout
 if workload=='micro':assert row['samples']==105 and len(row['medians'])==5 and so.count(b'probe_complete=1')==2
 else:assert b'TPASS' in so+se and b'Exceeded execution loops' in so+se
 print(json.dumps({k:row[k] for k in ['run_id','elapsed_s','returncode']+(['medians'] if workload=='micro' else [])}),flush=True)
for i,arm in enumerate(['mailbox','legacy']):run(arm,i,'micro',True)
for i,arm in enumerate(['mailbox','legacy','legacy','mailbox','legacy','mailbox','mailbox','legacy']):run(arm,i+2,'micro')
for i,arm in enumerate(['mailbox','legacy','legacy','mailbox']):run(arm,i,'ltp')
for i in range(3):run('docker',i,'micro')
run('docker',0,'ltp')
summary={}
for row in rows:
 if row['workload']=='micro' and not row['warmup']:
  for name,ns in row['medians'].items():summary.setdefault(name,{}).setdefault(row['arm'],[]).append(ns)
for name,arms in summary.items():
 arms['mailbox_to_legacy']=statistics.median(arms['mailbox'])/statistics.median(arms['legacy'])
 arms['mailbox_to_linux']=statistics.median(arms['mailbox'])/statistics.median(arms['docker'])
(d/'summary.json').write_text(json.dumps(summary,indent=2)+'\n')
print(json.dumps(summary,indent=2),flush=True)
