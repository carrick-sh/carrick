from pathlib import Path
import subprocess,os,json,hashlib
root=Path.cwd();out=root/'target/lease-cost/private-publication';rows=[]
for i,arm in enumerate(['control','candidate','candidate','control']):
 binary=out/('deferred-'+arm);rid=f'private-publish-recheck-{i}-{arm}-20260922'
 env=os.environ.copy();env.update(CARRICK_RUN_ID=rid,CARRICK_INSECURE_REGISTRIES='localhost:5005,localhost:5050',RUST_TEST_THREADS='1')
 cmd=[str(binary),'deferred_anonymous','--nocapture','--test-threads=1']
 with (out/(rid+'.log')).open('wb') as f:
  run=subprocess.run(cmd,cwd=root,env=env,stdin=subprocess.DEVNULL,stdout=f,stderr=subprocess.STDOUT,timeout=30)
 cleanup=subprocess.run([str(root/'scripts/sudo/kill.sh'),rid],capture_output=True,check=True)
 (out/(rid+'.cleanup')).write_bytes(cleanup.stdout+cleanup.stderr)
 rows.append({'arm':arm,'run_id':rid,'argv':cmd,'returncode':run.returncode,'sha256':hashlib.sha256(binary.read_bytes()).hexdigest()})
 (out/'embed-rechecks.json').write_text(json.dumps(rows,indent=2)+'\n')
 print(arm,run.returncode,flush=True)
