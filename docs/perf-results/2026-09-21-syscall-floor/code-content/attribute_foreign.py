from pathlib import Path
import hashlib, json, os, re, shutil, subprocess
root=Path.cwd()
base=root/'target/lease-cost/code-content'
env={**os.environ,'RUSTC_WRAPPER':''}
filter_name='deferred_anonymous_foreign_copyout'

def artifact(path, label):
    data=path.read_bytes()
    codesign=subprocess.run(['codesign','-dvvv',str(path)],capture_output=True,text=True,check=True)
    ent=subprocess.run(['codesign','-d','--entitlements',':-',str(path)],capture_output=True,text=True,check=True)
    macho=subprocess.check_output(['otool','-l',str(path)],text=True)
    cdhash=re.search(r'^CDHash=(.*)$',codesign.stderr,re.M).group(1)
    uuid=re.search(r'cmd LC_UUID\n\s*cmdsize \d+\n\s*uuid (\S+)',macho).group(1)
    record={'label':label,'path':str(path),'sha256':hashlib.sha256(data).hexdigest(),'cdhash':cdhash,'lc_uuid':uuid,'hypervisor_entitlement':'com.apple.security.hypervisor' in ent.stdout,'dof_carrick':'__dof_carrick' in macho}
    assert record['hypervisor_entitlement'] and record['dof_carrick']
    (base/(label+'-artifact.json')).write_text(json.dumps(record,indent=2)+'\n')
    return record

candidate_live=root/'target/release/deps/deferred_anonymous-270834789a7cee42'
candidate=base/'deferred-candidate'
shutil.copy2(candidate_live,candidate)
artifact(candidate,'deferred-candidate')
# Restore only this step's compiled source files, never unrelated campaign dirt.
backups=base/'before'
paths=[p.relative_to(backups) for p in backups.rglob('*') if p.is_file() and str(p.relative_to(backups)).startswith('crates/')]
saved={p:(root/p).read_bytes() for p in paths}
try:
    for p in paths:
        (root/p).write_bytes((backups/p).read_bytes())
    with (base/'signed-foreign-control.log').open('w') as out:
        result=subprocess.run(['scripts/test-signed.sh','carrick-conformance-next',filter_name,'--exact','--nocapture'],env={**env,'CARRICK_RUN_ID':'code-content-control-20260922'},stdin=subprocess.DEVNULL,stdout=out,stderr=subprocess.STDOUT)
    (base/'control-gate-exit.txt').write_text(str(result.returncode)+'\n')
    log=(base/'signed-foreign-control.log').read_text()
    match=re.search(r'test-signed: running (\S+/deferred_anonymous-[^\s]+)',log)
    assert match, 'control never reached signed execution'
    control=base/'deferred-control'
    shutil.copy2(match.group(1),control)
    artifact(control,'deferred-control')
finally:
    for p,data in saved.items():
        (root/p).write_bytes(data)
    assert all((root/p).read_bytes()==data for p,data in saved.items())
    (base/'control-restoration.json').write_text(json.dumps({'restored_files':len(saved),'all_byte_identical':True},indent=2)+'\n')

# Fixed diagnostic A/B/B/A population; every result retained. A passing rerun
# cannot repair the original failed acceptance or establish race attribution.
rows=[]
for index,arm in enumerate(['control','candidate','candidate','control']):
    run_id=f'code-content-attribute-{index}-{arm}-20260922'
    path=base/('deferred-'+arm)
    with (base/(run_id+'.log')).open('w') as out:
        result=subprocess.run([str(path),filter_name,'--exact','--nocapture','--test-threads=1'],env={**env,'CARRICK_RUN_ID':run_id},stdin=subprocess.DEVNULL,stdout=out,stderr=subprocess.STDOUT)
    with (base/(run_id+'.cleanup')).open('w') as out:
        cleanup=subprocess.run(['scripts/sudo/kill.sh',run_id],env=env,stdout=out,stderr=subprocess.STDOUT)
    rows.append({'arm':arm,'run_id':run_id,'sha256':hashlib.sha256(path.read_bytes()).hexdigest(),'exit_code':result.returncode,'cleanup_exit_code':cleanup.returncode})
    assert cleanup.returncode==0
(base/'attribution-runs.json').write_text(json.dumps(rows,indent=2)+'\n')
print(json.dumps(rows))
