from pathlib import Path
import sys,shlex,json,subprocess,hashlib,statistics
root=Path('/Users/tjfontaine/.codex/worktrees/inotify-lease-cost/carrick')
sys.path.insert(0,str(root/'target/lease-cost/workloads'))
import screen
out=root/'target/lease-cost/node-phases'; screen.OUT=out; screen.ROOT=root
screen.BIN=Path('/Volumes/CaseSensitive/carrick/target/syscall-floor/carrick-discard-retire')
source=(root/'target/lease-cost/node-service-budget/app-smoke.js').read_text()
child=source[source.index('  const child ='):source.index('  const server =')]
worker=source[source.index('  const worker ='):source.index('  await new Promise((resolve) => setTimeout')]
variants={'both':source,'child':source.replace(worker,''),'worker':source.replace(child,''),'neither':source.replace(child,'').replace(worker,'')}
# Create files before the timed command; use a file, as the original fixture does.
for name,code in variants.items():
 (out/(name+'.js')).write_text(code)
 body='printf %s '+shlex.quote(code)+' > /tmp/node-phase.js; time /opt/node-src/v24/out/Release/node /tmp/node-phase.js'
 screen.WORK[name]=(screen.NODE,body,30)
manifest={'binary_sha256':hashlib.sha256(screen.BIN.read_bytes()).hexdigest(),'source_sha256':hashlib.sha256(source.encode()).hexdigest(),'image':screen.NODE,'diagnostic_only':True,'order':['both','child','worker','neither'],'timing':'whole Node process, including teardown; file creation outside timed interval'}
(out/'inputs.json').write_text(json.dumps(manifest,indent=2)+'\n')
phase=sys.argv[1]
orders=[list(variants),list(reversed(variants)),['child','neither','both','worker'],['worker','both','neither','child']]
for block,order in [('warm',list(variants))]+list(enumerate(orders)):
 for name in order:
  label=f'phases-{phase}-{block}-{name}'
  sys.argv=['screen.py',phase,'--label',label,'--workloads',name];screen.main()
  row=json.loads((out/(label+'.jsonl')).read_text())
  assert row['returncode']==0 and not row['timed_out'] and len(row['guest_timing'])==1
  assert (out/(row['run_id']+'.out')).read_text().count('app-smoke ok')==1
  if phase=='carrick':
   c=subprocess.run([str(root/'scripts/sudo/kill.sh'),row['run_id']],cwd=root,capture_output=True,check=True)
   (out/(row['run_id']+'.cleanup')).write_bytes(c.stdout+c.stderr)
assert hashlib.sha256(screen.BIN.read_bytes()).hexdigest()==manifest['binary_sha256']
result={}
for name in variants:
 samples=[json.loads((out/f'phases-{phase}-{i}-{name}.jsonl').read_text())['guest_timing'][0][0] for i in range(4)]
 result[name]={'samples_s':samples,'mean_s':statistics.mean(samples),'median_s':statistics.median(samples)}
(out/(phase+'-summary.json')).write_text(json.dumps(result,indent=2)+'\n');print(json.dumps(result,indent=2))
