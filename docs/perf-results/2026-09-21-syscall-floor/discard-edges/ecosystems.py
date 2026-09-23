from pathlib import Path
import sys,json,statistics,subprocess,hashlib
root=Path('/Users/tjfontaine/.codex/worktrees/inotify-lease-cost/carrick')
sys.path.insert(0,str(root/'target/lease-cost/workloads'))
import screen
out=root/'target/lease-cost/discard-edges';screen.OUT=out;screen.ROOT=root
result={}
for name in ['go-build-cold','python-os']:
 arms={a:[] for a in 'AB'}
 for i,a in [('warmA','A'),('warmB','B')]+list(enumerate('ABBA')):
  arm='control' if a=='A' else 'candidate';screen.BIN=out/('carrick-'+arm)
  label=f'edges-ecosystem-{name}-{i}-{a}'
  sys.argv=['screen.py','carrick','--label',label,'--workloads',name];screen.main()
  row=json.loads((out/(label+'.jsonl')).read_text())
  assert row['returncode']==0 and not row['timed_out'] and len(row['guest_timing'])==1
  output=(out/(row['run_id']+'.out')).read_text()+(out/(row['run_id']+'.err')).read_text()
  assert ('BUILD_OK' in output) if name=='go-build-cold' else ('Tests result: SUCCESS' in output)
  clean=subprocess.run([str(root/'scripts/sudo/kill.sh'),row['run_id']],capture_output=True,check=True)
  (out/(row['run_id']+'.cleanup')).write_bytes(clean.stdout+clean.stderr)
  if isinstance(i,int):arms[a].append(row['guest_timing'][0][0])
 result[name]={'control_s':arms['A'],'candidate_s':arms['B'],'candidate_control_mean_ratio':statistics.mean(arms['B'])/statistics.mean(arms['A'])}
for arm in ['control','candidate']:
 assert hashlib.sha256((out/('carrick-'+arm)).read_bytes()).hexdigest()==json.loads((out/(arm+'-artifact.json')).read_text())['sha256']
(out/'ecosystems.json').write_text(json.dumps(result,indent=2)+'\n');print(json.dumps(result,indent=2))
