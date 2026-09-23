from pathlib import Path
import json,subprocess,os
root=Path.cwd();out=root/'target/lease-cost/workloads'
prior=json.loads((out/'current-impact-node-app.command.json').read_text())
argv=prior['argv'];argv[argv.index('--profile'):argv.index('--profile')+2]=['--script',str(root/'scripts/dtrace/hvpatch-madvise-shape.d')]
argv[argv.index('-o')+1]=str(out/'node-madvise-shape-v2.raw')
rid='floor-node-madvise-shape-v2'
(out/'node-madvise-shape-v2.command.json').write_text(json.dumps({'argv':argv,'run_id':rid,'binary_sha256':prior['binary_sha256']},indent=2))
with (out/'node-madvise-shape-v2.out').open('w') as stdout,(out/'node-madvise-shape-v2.err').open('w') as stderr:
 p=subprocess.Popen(argv,env={**os.environ,'CARRICK_RUN_ID':rid,'CARRICK_INSECURE_REGISTRIES':'localhost:5005,localhost:5050'},stdin=subprocess.DEVNULL,stdout=stdout,stderr=stderr)
 try:code=p.wait(timeout=110)
 finally:
  c=subprocess.run(['scripts/sudo/kill.sh',rid],capture_output=True,text=True);(out/'node-madvise-shape-v2.cleanup').write_text(c.stdout+c.stderr)
  if p.poll() is None:p.kill();p.wait()
 assert code==0,code
assert 'PROFILE_WORKLOAD_OK' in (out/'node-madvise-shape-v2.out').read_text()

import re
raw=(out/'node-madvise-shape-v2.raw').read_text()
counts=dict((k,int(v)) for k,v in re.findall(r'windows\|kind=(\w+)\|count=(\d+)',raw))
requests=sum(int(x) for x in re.findall(r'request\|advice=\d+\|length=\d+\|count=(\d+)',raw))
assert set(counts)=={'begin','end','clear'} and len(set(counts.values()))==1 and counts['begin']==requests>0, (counts,requests)
assert 'summary|status=ok' in raw
print(counts,'requests',requests)
