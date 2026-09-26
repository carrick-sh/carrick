from pathlib import Path
import os,json,subprocess,hashlib
p=Path(__file__).resolve().parent
exe=p/'signed-frozen'
expected=next(json.loads(x)['sha256'] for x in (p/'signed-artifacts.jsonl').read_text().splitlines() if json.loads(x)['record_type']=='executable')
results=[]
for label,key in [('host-sched','CARRICK_EL1_SCHED'),('host-futex','CARRICK_EL1_FUTEX'),('no-gic','CARRICK_HVF_GIC')]:
 assert hashlib.sha256(exe.read_bytes()).hexdigest()==expected
 runid='el1-live-occupancy-'+label+'-20260926'
 env=os.environ.copy()
 for k in ['CARRICK_EL1_SCHED','CARRICK_EL1_FUTEX','CARRICK_HVF_GIC']:env.pop(k,None)
 env.update({key:'0','CARRICK_RUN_ID':runid,'CARRICK_CONTRACT_ID':'kernel.mm.address-space-occupancy','RUST_TEST_THREADS':'1'})
 with (p/(label+'.log')).open('w') as out:
  result=subprocess.run([str(exe),'el1_sched_mm_occupancy_two_processes','--exact','--nocapture'],env=env,stdin=subprocess.DEVNULL,stdout=out,stderr=subprocess.STDOUT)
 with (p/(label+'-cleanup.log')).open('w') as out:
  cleanup=subprocess.run(['scripts/sudo/kill.sh',runid],stdout=out,stderr=subprocess.STDOUT)
 results.append(dict(label=label,env={key:'0'},run_id=runid,exit_code=result.returncode,cleanup_exit=cleanup.returncode,sha256=hashlib.sha256(exe.read_bytes()).hexdigest()))
 (p/'controls.json').write_text(json.dumps(results,indent=2)+'\n')
 print(results[-1],flush=True)
 if result.returncode or cleanup.returncode:break
