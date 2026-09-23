from pathlib import Path
import shutil,subprocess,os,json,hashlib
root=Path.cwd();out=root/'target/lease-cost/private-publication'
binary=root/'target/release/deps/deferred_anonymous-270834789a7cee42'
def attest(arm):
 frozen=out/('deferred-'+arm);shutil.copy2(binary,frozen)
 meta={'sha256':hashlib.sha256(frozen.read_bytes()).hexdigest()}
 for key,cmd in [('codesign',['codesign','-dvvv',str(frozen)]),('entitlements',['codesign','-d','--entitlements',':-',str(frozen)]),('load_commands',['otool','-l',str(frozen)])]:
  r=subprocess.run(cmd,capture_output=True,text=True,check=True);meta[key]=r.stdout+r.stderr
 assert 'com.apple.security.hypervisor' in meta['entitlements'] and '__dof_carrick' in meta['load_commands']
 (out/('deferred-'+arm+'-artifact.json')).write_text(json.dumps(meta,indent=2)+'\n')
attest('candidate')
paths={p.name.removesuffix('.before').replace('__','/'):p for p in out.glob('*.before')}
current={f:(root/f).read_bytes() for f in paths}
contract=root/'conformance-contracts/contracts/private-publication.toml';contract_bytes=contract.read_bytes()
(out/'private-publication.toml.candidate').write_bytes(contract_bytes)
try:
 for f,p in paths.items():(root/f).write_bytes(p.read_bytes())
 contract.unlink()
 env=os.environ.copy();env.update(CARRICK_RUN_ID='private-publish-control-deferred-20260922',CARRICK_INSECURE_REGISTRIES='localhost:5005,localhost:5050',RUSTC_WRAPPER='')
 with (out/'signed-deferred-control.log').open('wb') as log:
  r=subprocess.run(['scripts/test-signed.sh','carrick-conformance-next','deferred_anonymous','--nocapture'],env=env,stdout=log,stderr=subprocess.STDOUT)
 (out/'signed-control-status.json').write_text(json.dumps({'returncode':r.returncode})+'\n')
 attest('control')
 print({'control_returncode':r.returncode},flush=True)
finally:
 for f,data in current.items():(root/f).write_bytes(data)
 contract.write_bytes(contract_bytes)
 for f,data in current.items():assert (root/f).read_bytes()==data
 print('Candidate source restored byte-for-byte',flush=True)
