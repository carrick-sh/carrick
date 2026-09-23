from pathlib import Path
import json,subprocess,os
root=Path.cwd();out=root/'target/lease-cost/workloads'
prior=json.loads((out/'current-impact-node-app.command.json').read_text())
argv=prior['argv'];argv[argv.index('--profile'):argv.index('--profile')+2]=['--script',str(root/'scripts/dtrace/hvpatch-madvise-shape.d')]
argv[argv.index('-o')+1]=str(out/'node-madvise-shape.raw')
rid='floor-node-madvise-shape'
(out/'node-madvise-shape.command.json').write_text(json.dumps({'argv':argv,'run_id':rid,'binary_sha256':prior['binary_sha256']},indent=2))
with (out/'node-madvise-shape.out').open('w') as stdout,(out/'node-madvise-shape.err').open('w') as stderr:
 p=subprocess.Popen(argv,env={**os.environ,'CARRICK_RUN_ID':rid,'CARRICK_INSECURE_REGISTRIES':'localhost:5005,localhost:5050'},stdin=subprocess.DEVNULL,stdout=stdout,stderr=stderr)
 try:code=p.wait(timeout=110)
 finally:
  c=subprocess.run(['scripts/sudo/kill.sh',rid],capture_output=True,text=True);(out/'node-madvise-shape.cleanup').write_text(c.stdout+c.stderr)
  if p.poll() is None:p.kill();p.wait()
 assert code==0,code
assert 'PROFILE_WORKLOAD_OK' in (out/'node-madvise-shape.out').read_text()
