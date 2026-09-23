from pathlib import Path
import subprocess,os,json,hashlib,shutil,statistics,sys
root=Path.cwd(); out=root/'target/lease-cost/fstat-guest';out.mkdir(exist_ok=True)
shared=root/'target/lease-cost/io-floor/shared'
image=json.loads((root/'target/lease-cost/io-floor/screen1/inputs.json').read_text())['image']
candidate=Path('/Volumes/CaseSensitive/carrick/target/syscall-floor/carrick-fstat-allocation')
control=root/'target/lease-cost/carrick-retained-query-candidate'
mode=sys.argv[1]
env={**os.environ,'CARRICK_INSECURE_REGISTRIES':'localhost:5005,localhost:5050'}
fixture=shared/'io-floor-profile-linux'
def run(label,binary,iterations,samples,trace=None):
 rid='floor-fstat-'+label
 argv=[str(binary)]
 if trace=='service':argv+=['trace','--require-script-exit','--script',str(root/'scripts/dtrace/hvpatch-fstat-service-lowering.d'),'-o',str(out/(label+'.raw')),'--']
 if trace=='profile':argv+=['trace','--profile','hvpatch-carrier-cpu-low-rate','-o',str(out/(label+'.raw')),'--']
 argv+=['run','--max-traps','18446744073709551615','--fs','host','-v',f'{shared}:/bench','--entrypoint','/bench/io-floor-profile-linux',image,'/bench/'+rid+'.data',str(iterations),str(samples),'fstat']
 (out/(label+'.command.json')).write_text(json.dumps({'argv':argv,'run_id':rid,'binary_sha256':hashlib.sha256(binary.read_bytes()).hexdigest(),'fixture_sha256':hashlib.sha256(fixture.read_bytes()).hexdigest()},indent=2))
 with (out/(label+'.out')).open('w') as stdout,(out/(label+'.err')).open('w') as stderr:
  p=subprocess.Popen(argv,env={**env,'CARRICK_RUN_ID':rid},stdin=subprocess.DEVNULL,stdout=stdout,stderr=stderr)
  try: code=p.wait(timeout=110)
  finally:
   cleanup=subprocess.run(['scripts/sudo/kill.sh',rid],capture_output=True,text=True)
   (out/(label+'.cleanup')).write_text(cleanup.stdout+cleanup.stderr)
   if p.poll() is None:p.kill();p.wait()
  assert code==0,(label,code)
 return [json.loads(line) for line in (out/(label+'.out')).read_text().splitlines() if line.startswith('{')]
if mode=='timing':
 summary=[]
 for i,arm in enumerate(['control','candidate','candidate','control']*2):
  rows=([json.loads(x) for x in (out/'untraced-0-control.out').read_text().splitlines() if x.startswith('{')] if i==0 else run(f'untraced-{i}-{arm}',control if arm=='control' else candidate,65536,9))
  assert rows[-1].get('verified') is True,rows[-1]
  rows=[x for x in rows if x.get('phase')=='fstat']
  assert len(rows)==9,rows
  summary.append({'arm':arm,'run':i,'median_ns':statistics.median(x['elapsed_ns']/x['iterations'] for x in rows)})
 (out/'summary.json').write_text(json.dumps(summary,indent=2));print(json.dumps(summary,indent=2))
elif mode=='trace':
 run('service',candidate,8192,3,'service')
 run('profile',candidate,1048576,5,'profile')
else:raise ValueError(mode)
