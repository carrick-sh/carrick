from pathlib import Path
import json,tarfile,hashlib,subprocess,shutil,datetime,statistics,os
out=Path('target/lease-cost/native-activation-cache')
sha=lambda p:hashlib.sha256(Path(p).read_bytes()).hexdigest()
rows=[json.loads(line) for line in (out/'release-build.jsonl').read_text().splitlines()]
artifacts=[r['executable'] for r in rows if r.get('reason')=='compiler-artifact' and r.get('target',{}).get('name')=='carrick_runtime' and r.get('profile',{}).get('test') and r.get('executable')]
assert len(artifacts)==1,artifacts
new=out/'native-activation-cache-cost-release';shutil.copy2(artifacts[0],new)
old=Path('target/lease-cost/native-activation/native-activation-cost-release')
parent=json.loads(Path('docs/perf-results/2026-09-21-syscall-floor/native-activation/manifest.json').read_text())
assert sha(old)==parent['diagnostic_binaries'][old.name], 'baseline artifact drift'
print('baseline sha',sha(old),'new sha',sha(new),flush=True)
# Archive every source changed in this tranche, including the lockfile.
files=list(json.loads((out/'before-hashes.json').read_text()))+['Cargo.lock','conformance-contracts/contracts/native-data-activation.toml']
source={p:sha(p) for p in sorted(files)}
with tarfile.open(out/'measured-source.tar.gz','w:gz') as tar:
 for p in source:tar.add(p,arcname=p)
revision='sha256:'+hashlib.sha256(json.dumps(source,sort_keys=True).encode()).hexdigest()
(out/'measured-source-hashes.json').write_text(json.dumps(source,indent=2))
identity={'utc':datetime.datetime.now(datetime.timezone.utc).isoformat(),'source_revision':revision,'source_head':subprocess.check_output(['git','rev-parse','HEAD'],text=True).strip(),'baseline':str(old),'baseline_sha256':sha(old),'candidate':str(new),'candidate_sha256':sha(new),'order':['baseline-1','candidate-1','candidate-2','baseline-2'],'host_fixture_only':True,'runtime_conformance_metrics':False}
(out/'cost-identity.json').write_text(json.dumps(identity,indent=2))
procs=subprocess.check_output(['ps','-axo','pid,ppid,etime,%cpu,command'],text=True)
(out/'processes-at-measurement.txt').write_text(procs)
suspect=[p for p in procs.splitlines() if ('rustc --crate-name' in p or 'carrick run ' in p or 'docker run ' in p) and 'measure.py' not in p]
assert not suspect,suspect
all_samples=[]
for label,binary in [('baseline-1',old),('candidate-1',new),('candidate-2',new),('baseline-2',old)]:
 before=sha(binary)
 with (out/(label+'.log')).open('w') as log:
  r=subprocess.run([str(binary),'vcpu_loop::memory::tests::native_data_activation_entry_cost','--exact','--ignored','--nocapture'],stdout=log,stderr=subprocess.STDOUT,env={**os.environ,'CARRICK_NATIVE_SCOPE_REVISION':revision})
 assert r.returncode==0,(label,r.returncode)
 assert before==sha(binary),(label,'binary changed')
 samples=[json.loads(line.split('native_activation_cost ',1)[1]) for line in (out/(label+'.log')).read_text().splitlines() if line.startswith('native_activation_cost ')]
 assert len(samples)==36,(label,len(samples))
 assert {(x['scale'],x['sample']) for x in samples}=={(s,i) for s in [1,8,32,128] for i in range(9)}
 assert all(x['pages']==1 and x['iterations']==4096*x['scale'] and x['runtime_conformance_metrics'] is False and x['workload_timing_eligible'] is False for x in samples)
 for x in samples:x['cohort']=label
 all_samples+=samples
 print(label, {s:round(statistics.median(x['activated_ns'] for x in samples if x['scale']==s),2) for s in [1,8,32,128]},flush=True)
(out/'cost-samples.json').write_text(json.dumps(all_samples,indent=2))
summary={}
for scale in [1,8,32,128]:
 summary[scale]={}
 for arm in ['baseline','candidate']:
  vals=[x for x in all_samples if x['scale']==scale and x['cohort'].startswith(arm)]
  summary[scale][arm]={k:statistics.median(x[k] for x in vals) for k in ['scope_ns','activated_ns','activation_delta_ns']}
 summary[scale]['activation_reduction_pct']=100*(1-summary[scale]['candidate']['activation_delta_ns']/summary[scale]['baseline']['activation_delta_ns'])
(out/'cost-summary.json').write_text(json.dumps(summary,indent=2));print(json.dumps(summary,indent=2))
assert all(sha(p)==v for p,v in source.items()),'source changed during measurement'
