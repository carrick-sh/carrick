from pathlib import Path
import sys,json,hashlib,statistics,subprocess
root=Path('/Users/tjfontaine/.codex/worktrees/inotify-lease-cost/carrick')
sys.path.insert(0,str(root/'target/lease-cost/workloads'))
import screen
out=root/'target/lease-cost/discard-edges/concurrency';screen.ROOT=root;screen.OUT=out
phase=sys.argv[1]
node='/opt/node-src/v24/out/Release/node /opt/nodejs-conformance/fixtures/app-smoke.js'
for n in [1,2,4,8]:
 body='time { pids=(); for ((i=0;i<'+str(n)+';i++)); do '+node+' & pids+=("$!"); done; status=0; for child in "${pids[@]}"; do wait "$child" || status=1; done; test "$status" -eq 0; }; echo GROUP_OK'
 screen.WORK['parallel'+str(n)]=(screen.NODE,body,30)
for arm in ['control','candidate']:
 binary=root/'target/lease-cost/discard-edges'/('carrick-'+arm)
 assert hashlib.sha256(binary.read_bytes()).hexdigest()==json.loads((binary.parent/(arm+'-artifact.json')).read_text())['sha256']
results={}
for n in [1,2,4,8]:
 arms={a:[] for a in ('AB' if phase=='carrick' else 'L')}
 order=([('warm-A','A'),('warm-B','B')]+list(enumerate('ABBAABBA'))) if phase=='carrick' else [('warm-L','L')]+list(enumerate('LLLL'))
 for i,a in order:
  screen.BIN=root/'target/lease-cost/discard-edges'/('carrick-control' if a=='A' else 'carrick-candidate')
  label=f'edges-parallel-{phase}-{n}-{i}-{a}'
  sys.argv=['screen.py',phase,'--label',label,'--workloads','parallel'+str(n)];screen.main()
  row=json.loads((out/(label+'.jsonl')).read_text())
  if phase=='carrick':
   c=subprocess.run([str(root/'scripts/sudo/kill.sh'),row['run_id']],capture_output=True,check=True)
   (out/(row['run_id']+'.cleanup')).write_bytes(c.stdout+c.stderr)
  assert row['returncode']==0 and not row['timed_out'] and len(row['guest_timing'])==1,row
  stdout=(out/(row['run_id']+'.out')).read_text()
  assert stdout.count('app-smoke ok')==n and stdout.count('GROUP_OK')==1,stdout
  if isinstance(i,int):arms[a].append(row['guest_timing'][0][0])
 results[n]={a:{'samples_s':v,'mean_s':statistics.mean(v),'median_s':statistics.median(v),'workloads_per_second':n/statistics.mean(v)} for a,v in arms.items()}
 (out/(phase+'-summary.json')).write_text(json.dumps(results,indent=2)+'\n')
for arm in ['control','candidate']:
 binary=root/'target/lease-cost/discard-edges'/('carrick-'+arm)
 assert hashlib.sha256(binary.read_bytes()).hexdigest()==json.loads((binary.parent/(arm+'-artifact.json')).read_text())['sha256']
print(json.dumps(results,indent=2))
