from pathlib import Path
import hashlib,json,os,subprocess
root=Path.cwd();out=root/'target/el1-completion/fault-entry-final'
archive=out/'green-frozen'
manifest=json.loads((archive/'frozen-artifacts.json').read_text())
artifacts=[x for x in manifest['artifacts'] if Path(x['canonical_path']).name.startswith('el1_sched-')]
assert len(artifacts)==1
artifact=artifacts[0];exe=Path(artifact['frozen_path'])
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
fixture=root/'target/embed-fixtures/el1-sched-aarch64'
expected_fixture='e33f7cae1859cf978a1f1cb0e765deb1a903fbe1f40244a6fa36d321b416eb67'
assert sha(fixture)==expected_fixture
results=[]
for name,settings in [('el1-off',{'CARRICK_EL1':'0'}),('gic-off',{'CARRICK_HVF_GIC':'0'})]:
 assert sha(exe)==artifact['sha256']
 run_id='el1-fault-entry-'+name+'-20260926'
 env=os.environ.copy()
 for key in ['CARRICK_EL1','CARRICK_HVF_GIC']:env.pop(key,None)
 env.update(settings);env.update({'CARRICK_RUN_ID':run_id,'RUST_TEST_THREADS':'1'})
 command=[str(exe),'el1_memory_fault_entry_preserves_context','--exact','--nocapture']
 with (out/(name+'.log')).open('wb') as log:
  try:run=subprocess.run(command,env=env,stdout=log,stderr=subprocess.STDOUT,timeout=90);code=run.returncode
  finally:
   cleanups=[]
   for ident in [run_id,run_id+'-cli']:
    c=subprocess.run(['scripts/sudo/kill.sh',ident],capture_output=True,text=True)
    cleanups.append({'run_id':ident,'exit_code':c.returncode,'stdout':c.stdout,'stderr':c.stderr})
   (out/(name+'-cleanup.json')).write_text(json.dumps(cleanups,indent=2)+'\n')
 assert all(c['exit_code']==0 and '= 0' in c['stdout'] for c in cleanups),cleanups
 assert sha(exe)==artifact['sha256'] and sha(fixture)==expected_fixture
 row={'control':name,'settings':settings,'source_head':manifest['header']['source_head'],'executable_sha256':artifact['sha256'],'fixture_sha256':expected_fixture,'command':command,'exit_code':code,'run_id':run_id,'cleanup':cleanups}
 results.append(row);(out/'controls.json').write_text(json.dumps(results,indent=2)+'\n');print(json.dumps(row),flush=True)
 if code:raise SystemExit(code)
