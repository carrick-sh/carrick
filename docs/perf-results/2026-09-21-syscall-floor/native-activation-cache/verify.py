from pathlib import Path
import subprocess,json,os,shutil,datetime
out=Path('target/lease-cost/native-activation-cache').resolve()
identity=json.loads((out/'cost-identity.json').read_text())
env={**os.environ,'RUSTC_WRAPPER':'','CARRICK_NATIVE_SCOPE_REVISION':identity['source_revision']}
metrics=out/'native-activation-cache-metrics-debug'
shutil.copy2('target/debug/deps/carrick_runtime-c733ccb1138de6cb',metrics)
commands=[
 ('contract-final',[str(metrics),'vcpu_loop::memory::tests::native_data_activation_cost_contract','--exact','--nocapture']),
 ('release-memory',[str(out/'native-activation-cache-cost-release'),'vcpu_loop::memory::tests::','--nocapture']),
 ('kernel',['just','test-kernel']),
 ('runtime-stage1',['cargo','test','-p','carrick-runtime','--lib','hvpatch::stage1_mm::tests::']),
 ('runtime-quiesce',['cargo','test','-p','carrick-runtime','--lib','vcpu_loop::quiesce::tests::']),
 ('memory-doctests',['cargo','test','-p','carrick-kernel','--doc','kernel::mm_access']),
 ('hal',['cargo','test','-p','carrick-hal','--lib','foreign_mm::']),
 ('observability',['cargo','test','-p','carrick-observability','--lib','--features','conformance-metrics']),
 ('contracts',['cargo','test','-p','carrick-conformance-contract']),
 ('aarch64',['cargo','test','-p','carrick-aarch64','--lib']),
 ('aarch64-clippy',['cargo','clippy','--no-deps','-p','carrick-aarch64','-p','carrick-observability','-p','carrick-conformance-contract','--all-targets','--','-D','warnings']),
 ('signed-foreign-mm',['scripts/test-signed.sh','carrick-vmm-hvf','trap::foreign_mm::tests::']),
 ('signed-lifecycle',['scripts/test-signed.sh','carrick-vmm-hvf','trap::foreign_mm::tests::production_copied_fork_structural_backing_retention_and_exact_stage2_lifecycle','--exact','--ignored']),
]
results=[]
for name,cmd in commands:
 runenv=env.copy()
 if name.startswith('signed-'):runenv['CARRICK_RUN_ID']='native-activation-cache-'+name+'-20260922'
 with (out/(name+'.log')).open('w') as log:
  r=subprocess.run(cmd,stdout=log,stderr=subprocess.STDOUT,env=runenv)
 row={'name':name,'argv':cmd,'exit_code':r.returncode,'run_id':runenv.get('CARRICK_RUN_ID'),'finished_utc':datetime.datetime.now(datetime.timezone.utc).isoformat()}
 results.append(row);(out/'verification.json').write_text(json.dumps(results,indent=2));print(json.dumps(row),flush=True)
 if name.startswith('signed-') and r.returncode==0:
  shutil.copy2('target/test-results/carrick-vmm-hvf-signed-artifacts.jsonl',out/(name+'-receipt.jsonl'))
