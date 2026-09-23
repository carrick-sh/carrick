from pathlib import Path
import hashlib,json,sys
import screen
out=screen.OUT
for arm in 'AB':
    screen.BIN=(Path('/Volumes/CaseSensitive/carrick/target/syscall-floor/carrick-fstat-allocation') if arm=='A' else screen.ROOT/'target/lease-cost/carrick-pristine-scrub')
    sys.argv=['screen.py','carrick','--label','pristine-scrub-confirm-warm-'+arm,'--workloads','node-app']
    screen.main()
for index,arm in enumerate('ABBAABBA'):
    screen.BIN=(Path('/Volumes/CaseSensitive/carrick/target/syscall-floor/carrick-fstat-allocation') if arm=='A' else screen.ROOT/'target/lease-cost/carrick-pristine-scrub')
    label=f'pristine-scrub-confirm-{index}-{arm}'
    sys.argv=['screen.py','carrick','--label',label,'--workloads','node-app']
    screen.main()
    rows=[json.loads(x) for x in (out/(label+'.jsonl')).read_text().splitlines()]
    assert all(r['returncode']==0 and not r['timed_out'] and len(r['guest_timing'])==1 for r in rows),rows
    assert len(rows)==1
results={}
for name in ['node-app']:
    arms={a:[] for a in 'AB'}
    for index,arm in enumerate('ABBAABBA'):
        rows=[json.loads(x) for x in (out/f'pristine-scrub-confirm-{index}-{arm}.jsonl').read_text().splitlines()]
        arms[arm].append(next(r['guest_timing'][0][0] for r in rows if r['name']==name))
    results[name]={'control_s':arms['A'],'candidate_s':arms['B'],'candidate_control_mean_ratio':sum(arms['B'])/sum(arms['A'])}
(out/'pristine-scrub-confirm-summary.json').write_text(json.dumps(results,indent=2)+'\n')
print(json.dumps(results,indent=2),flush=True)
