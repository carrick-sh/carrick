from pathlib import Path
import sys,json,statistics,subprocess,hashlib
root=Path('/Users/tjfontaine/.codex/worktrees/inotify-lease-cost/carrick')
sys.path.insert(0,str(root/'target/lease-cost/workloads'))
import screen
out=root/'target/lease-cost/cow-inventory-bound'; screen.OUT=out; screen.ROOT=root
for label,arm in [('warm-control','A'),('warm-candidate','B')]+[(str(i),a) for i,a in enumerate('ABBAABBA')]:
 screen.BIN=out/('carrick-control' if arm=='A' else 'carrick-candidate')
 run='owner-query-'+label+'-'+arm
 sys.argv=['screen.py','carrick','--label',run,'--workloads','node-app']; screen.main()
 row=json.loads((out/(run+'.jsonl')).read_text());assert row['returncode']==0 and not row['timed_out'] and len(row['guest_timing'])==1
 assert (out/(row['run_id']+'.out')).read_text().count('app-smoke ok')==1
 cleanup=subprocess.run([str(root/'scripts/sudo/kill.sh'),row['run_id']],cwd=root,capture_output=True,check=True)
 (out/(row['run_id']+'.cleanup')).write_bytes(cleanup.stdout+cleanup.stderr)
arms={a:[] for a in 'AB'}
for i,a in enumerate('ABBAABBA'):
 row=json.loads((out/f'owner-query-{i}-{a}.jsonl').read_text());arms[a].append(row['guest_timing'][0][0])
result={'control_s':arms['A'],'candidate_s':arms['B'],'candidate_control_mean_ratio':statistics.mean(arms['B'])/statistics.mean(arms['A']),'candidate_control_median_ratio':statistics.median(arms['B'])/statistics.median(arms['A'])}
for arm in ['control','candidate']:
 artifact=json.loads((out/(arm+'-artifact.json')).read_text());assert hashlib.sha256((out/('carrick-'+arm)).read_bytes()).hexdigest()==artifact['sha256']
(out/'node-impact.json').write_text(json.dumps(result,indent=2)+'\n');print(json.dumps(result,indent=2))
