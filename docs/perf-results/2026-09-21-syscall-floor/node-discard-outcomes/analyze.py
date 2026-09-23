from pathlib import Path
import re,json,hashlib,shutil
root=Path.cwd();src=root/'target/lease-cost/node-discard-outcomes';report={}
for arm in ['echo-wide','base-wide']:
 p=src/arm;s=(p/'trace.raw').read_text()
 rows=[dict((k,int(v)) for k,v in re.findall(r'(\w+)=(\d+)',l)) for l in s.splitlines() if l.startswith('DISCARD1|pid=')]
 counts={k:int(n) for k,n in re.findall(r'DISCARD1\|count\|kind=(\w+)\|n=(\d+)',s)}
 assert counts=={k:len(rows) for k in ['begin','args','end']}
 assert 'seen=1|errors=0|exited=1' in s
 assert (p/'stdout').read_text().count('app-smoke ok')==5
 assert json.loads((p/'status.json').read_text())=={'returncode':0,'cleanup_returncode':0}
 for r in rows:assert r['scrub']==r['zeroed']+r['remapped']
 scrub=[r for r in rows if r['scrub']]
 assert len(scrub)==25 and all(r['advice']==4 and r['len']==8314880 and r['address']>=0x6000000000 and r['address']%16384==12288 for r in scrub)
 report[arm]={'requests':len(rows),'scrub_requests':len(scrub),'scrub_bytes':sum(r['scrub'] for r in rows),'summed_service_ms':sum(r['ns'] for r in rows)/1e6,'scrub_request_service_ms':sum(r['ns'] for r in scrub)/1e6,'scrub_bytes_per_iteration':sum(r['scrub'] for r in rows)//5,'edge_bytes_per_scrub_request':8192,'aligned_interior_bytes_per_scrub_request':8306688}
 (p/'rows.json').write_text(json.dumps(rows,indent=2)+'\n')
(src/'summary.json').write_text(json.dumps(report,indent=2)+'\n')
print(json.dumps(report,indent=2))
