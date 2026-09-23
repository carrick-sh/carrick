from pathlib import Path
import hashlib,json,sys
import screen
out=screen.OUT
for index,arm in enumerate('ABBAABBA'):
    screen.BIN=screen.ROOT/'target/lease-cost'/('carrick-retained-query-control' if arm=='A' else 'carrick-retained-query-candidate')
    label=f'retained-query-focused-{index}-{arm}'
    sys.argv=['screen.py','carrick','--label',label,'--workloads','node-app,go-build-cold,python-os']
    screen.main()
    rows=[json.loads(x) for x in (out/(label+'.jsonl')).read_text().splitlines()]
    assert all(r['returncode']==0 and not r['timed_out'] and len(r['guest_timing'])==1 for r in rows),rows
    assert len(rows)==3
results={}
for name in ['node-app','go-build-cold','python-os']:
    arms={a:[] for a in 'AB'}
    for index,arm in enumerate('ABBAABBA'):
        rows=[json.loads(x) for x in (out/f'retained-query-focused-{index}-{arm}.jsonl').read_text().splitlines()]
        arms[arm].append(next(r['guest_timing'][0][0] for r in rows if r['name']==name))
    results[name]={'control_s':arms['A'],'candidate_s':arms['B'],'candidate_control_mean_ratio':sum(arms['B'])/sum(arms['A'])}
(out/'retained-query-focused-summary.json').write_text(json.dumps(results,indent=2)+'\n')
print(json.dumps(results,indent=2),flush=True)
