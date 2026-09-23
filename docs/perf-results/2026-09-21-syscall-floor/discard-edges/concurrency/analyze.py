from pathlib import Path
import json,re
p=Path(__file__).resolve().parent
c=json.loads((p/'carrick-summary.json').read_text());l=json.loads((p/'docker-summary.json').read_text())
summary={n:{'control_s':c[n]['A']['mean_s'],'candidate_s':c[n]['B']['mean_s'],'linux_s':l[n]['L']['mean_s'],'candidate_control_ratio':c[n]['B']['mean_s']/c[n]['A']['mean_s'],'candidate_linux_ratio':c[n]['B']['mean_s']/l[n]['L']['mean_s'],'candidate_per_s':c[n]['B']['workloads_per_second'],'linux_per_s':l[n]['L']['workloads_per_second']} for n in c}
(p/'comparison.json').write_text(json.dumps(summary,indent=2)+'\n')
print(json.dumps(summary,indent=2))
for n in [1,8]:
 q=p/f'trace{n}';s=(q/'trace.raw').read_text()
 assert 'seen=1|errors=0|exited=1' in s
 assert (q/'stdout').read_text().count('app-smoke ok')==5*n
 assert (q/'stdout').read_text().count('GROUP_DONE')==5
 counts={(int(a),int(b)):int(v) for a,b,v in re.findall(r'TOPOB1\|count\|op=(\d+)\|phase=(\d+)\|v=(\d+)',s)}
 for op in {a for a,b in counts}:
  assert counts.get((op,0),0)==counts.get((op,1),0)+counts.get((op,3),0),(op,counts)
  assert counts.get((op,1),0)==counts.get((op,2),0),(op,counts)
 durations={(int(a),int(b)):int(v) for a,b,v in re.findall(r'TOPOB1\|ns\|op=(\d+)\|phase=(\d+)\|v=(\d+)',s)}
 result={str(op):{'requests':counts.get((op,0),0),'wait_ms':durations.get((op,1),0)/1e6,'hold_ms':durations.get((op,2),0)/1e6,'try_misses':counts.get((op,3),0)} for op in {a for a,b in counts}}
 (q/'summary.json').write_text(json.dumps(result,indent=2)+'\n');print(n,result)
