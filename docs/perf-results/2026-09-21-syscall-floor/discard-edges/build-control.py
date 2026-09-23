from pathlib import Path
import subprocess,os,json,hashlib,shutil,gzip
root=Path('/Users/tjfontaine/.codex/worktrees/inotify-lease-cost/carrick'); out=root/'target/lease-cost/discard-edges'
p=root/'crates/carrick-vmm-hvf/src/hvf_aarch64_engine.rs'
candidate=p.read_text()
needle='self.state.persistent_vm_lifecycle.then_some(16384)'
assert candidate.count(needle)==1
p.write_text(candidate.replace(needle,'None'))
env=os.environ.copy();env['RUSTC_WRAPPER']=''
try:
 for arm in ['control']:
  names=subprocess.check_output(['git','ls-files','-m','-o','--exclude-standard'],cwd=root,text=True).splitlines()
  hashes={n:hashlib.sha256((root/n).read_bytes()).hexdigest() for n in names if (root/n).is_file() and (n.startswith('crates/') or n.startswith('conformance-contracts/') or n in ['Cargo.toml','Cargo.lock'])}
  (out/(arm+'-sources.json')).write_text(json.dumps(hashes,indent=2)+'\n')
  with gzip.open(out/(arm+'-source.patch.gz'),'wb') as f:f.write(subprocess.check_output(['git','diff','--binary'],cwd=root))
  with (out/(arm+'-build.log')).open('wb') as f:subprocess.run(['just','build'],cwd=root,env=env,stdout=f,stderr=subprocess.STDOUT,check=True)
  binary=out/('carrick-'+arm);shutil.copy2(root/'target/release/carrick',binary)
  meta={'head':subprocess.check_output(['git','rev-parse','HEAD'],cwd=root,text=True).strip(),'sha256':hashlib.sha256(binary.read_bytes()).hexdigest()}
  for key,args in [('codesign',['codesign','-dvvv',str(binary)]),('entitlements',['codesign','-d','--entitlements',':-',str(binary)]),('load_commands',['otool','-l',str(binary)])]:
   r=subprocess.run(args,capture_output=True,text=True,check=True);meta[key]=r.stdout+r.stderr
  assert 'com.apple.security.hypervisor' in meta['entitlements'] and '__dof_carrick' in meta['load_commands']
  (out/(arm+'-artifact.json')).write_text(json.dumps(meta,indent=2)+'\n');print(arm,meta['sha256'],flush=True)
finally:p.write_text(candidate)
