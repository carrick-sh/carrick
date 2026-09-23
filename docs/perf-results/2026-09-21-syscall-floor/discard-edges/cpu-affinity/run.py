from pathlib import Path
import sys,json,statistics
import screen_affinity as screen
root=Path('/Users/tjfontaine/.codex/worktrees/inotify-lease-cost/carrick')
out=Path(__file__).resolve().parent;screen.ROOT=root;screen.OUT=out
node='/opt/node-src/v24/out/Release/node /opt/nodejs-conformance/fixtures/app-smoke.js'
result={}
for n in [1,2,4,8]:
 screen.WORK['parallel'+str(n)]=(screen.NODE,'time { pids=(); for ((i=0;i<'+str(n)+';i++)); do '+node+' & pids+=("$!"); done; status=0; for child in "${pids[@]}"; do wait "$child" || status=1; done; test "$status" -eq 0; }; echo GROUP_OK',30)
 arms={a:[] for a in 'AB'}
 for i,a in [('warm-A','A'),('warm-B','B')]+list(enumerate('ABBAABBA')):
  screen.CPUSET='0-9' if a=='A' else '0-3'
  label=f'affinity-{n}-{i}-{a}';sys.argv=['screen.py','docker','--label',label,'--workloads','parallel'+str(n)];screen.main()
  row=json.loads((out/(label+'.jsonl')).read_text());assert row['returncode']==0 and len(row['guest_timing'])==1 and not row['timed_out']
  stdout=(out/(row['run_id']+'.out')).read_text();assert stdout.count('app-smoke ok')==n and stdout.count('GROUP_OK')==1
  if isinstance(i,int):arms[a].append(row['guest_timing'][0][0])
 result[n]={'ten_cpus_s':arms['A'],'four_cpus_s':arms['B'],'ten_mean_s':statistics.mean(arms['A']),'four_mean_s':statistics.mean(arms['B'])}
 (out/'summary.json').write_text(json.dumps(result,indent=2)+'\n')
print(json.dumps(result,indent=2))
