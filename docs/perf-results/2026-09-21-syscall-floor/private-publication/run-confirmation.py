from pathlib import Path
import sys,json,hashlib,statistics,subprocess
import screen
root=Path('/Users/tjfontaine/.codex/worktrees/inotify-lease-cost/carrick')
out=Path(__file__).resolve().parent
screen.ROOT=root;screen.OUT=out
node='/opt/node-src/v24/out/Release/node /opt/nodejs-conformance/fixtures/app-smoke.js'
for n in [1,8]:
 body='time { pids=(); for ((i=0;i<'+str(n)+';i++)); do '+node+' & pids+=("$!"); done; status=0; for child in "${pids[@]}"; do wait "$child" || status=1; done; test "$status" -eq 0; }; echo GROUP_OK'
 screen.WORK['parallel'+str(n)]=(screen.NODE,body,30)
for arm in ['control','candidate']:
 binary=out/('carrick-'+arm)
 assert hashlib.sha256(binary.read_bytes()).hexdigest()==json.loads((out/(arm+'-artifact.json')).read_text())['sha256']
results={}
for name in ['node-app','parallel8']:
 arms={a:[] for a in 'AB'}
 for i,a in [('warm-A','A'),('warm-B','B')]+list(enumerate('ABBAABBA')):
  screen.BIN=out/('carrick-control' if a=='A' else 'carrick-candidate')
  label=f'private-publish-confirm-{name}-{i}-{a}'
  sys.argv=['screen.py','carrick','--label',label,'--workloads',name];screen.main()
  row=json.loads((out/(label+'.jsonl')).read_text())
  c=subprocess.run([str(root/'scripts/sudo/kill.sh'),row['run_id']],capture_output=True,check=True)
  (out/(row['run_id']+'.cleanup')).write_bytes(c.stdout+c.stderr)
  assert row['returncode']==0 and not row['timed_out'] and len(row['guest_timing'])==1,row
  stdout=(out/(row['run_id']+'.out')).read_text()
  n=8 if name=='parallel8' else 1
  assert stdout.count('app-smoke ok')==n,stdout
  if name.startswith('parallel'):assert stdout.count('GROUP_OK')==1
  if isinstance(i,int):arms[a].append(row['guest_timing'][0][0])
 results[name]={a:{'samples_s':v,'mean_s':statistics.mean(v),'median_s':statistics.median(v)} for a,v in arms.items()}
 results[name]['candidate_control_ratio']=statistics.mean(arms['B'])/statistics.mean(arms['A'])
 (out/'confirmation-summary.json').write_text(json.dumps(results,indent=2)+'\n')
for arm in ['control','candidate']:
 binary=out/('carrick-'+arm)
 assert hashlib.sha256(binary.read_bytes()).hexdigest()==json.loads((out/(arm+'-artifact.json')).read_text())['sha256']
print(json.dumps(results,indent=2))
