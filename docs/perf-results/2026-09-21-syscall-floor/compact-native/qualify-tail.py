import pathlib,subprocess,os,json,time,hashlib,shutil
out=pathlib.Path('target/lease-cost/compact-native').resolve()
env=os.environ|{'RUSTC_WRAPPER':''}
commands=[
 ('elf-clippy-final',['cargo','clippy','--manifest-path','experiments/native-syscall-slice/Cargo.toml','--all-targets','--','-D','warnings']),
 ('runtime-clippy',['cargo','clippy','--no-deps','-p','carrick-runtime','-p','carrick-observability','--all-targets','--features','carrick-runtime/conformance-metrics','--','-D','warnings']),
 ('inventory-check',['cargo','run','-p','carrick-conformance-contract','--bin','check-contracts','--','--root','.']),
 ('layering',['bash','scripts/closure-assert-layering.sh']),
]
rows=[]
for name,cmd in commands:
 start=time.monotonic()
 with (out/(name+'.log')).open('wb') as log:
  p=subprocess.run(cmd,env=env,stdout=log,stderr=subprocess.STDOUT,stdin=subprocess.DEVNULL)
 rows.append(dict(name=name,argv=cmd,exit_code=p.returncode,wall_s=time.monotonic()-start))
 (out/'qualification-final-status.json').write_text(json.dumps(rows,indent=2)+'\n');print(name,p.returncode,flush=True)
 if p.returncode:
  print((out/(name+'.log')).read_text(errors='replace')[-5000:]); raise SystemExit(p.returncode)
sha=json.loads((out/'measured-source.json').read_text())['sha256']
sha={p:hashlib.sha256(pathlib.Path(p).read_bytes()).hexdigest() for p in sorted(sha)}
rev='sha256:'+hashlib.sha256(json.dumps(sha,sort_keys=True,separators=(',',':')).encode()).hexdigest()
(out/'final-source.json').write_text(json.dumps(dict(revision=rev,sha256=sha),indent=2)+'\n')
env['CARRICK_NATIVE_SCOPE_REVISION']=rev
cmd=['cargo','test','--manifest-path','experiments/native-syscall-slice/Cargo.toml','--lib','--no-run','--message-format=json']
with (out/'final-executor-build.jsonl').open('wb') as log, (out/'final-executor-build.log').open('wb') as err:
 p=subprocess.run(cmd,env=env,stdout=log,stderr=err)
assert p.returncode==0
artifacts=[json.loads(l) for l in (out/'final-executor-build.jsonl').read_text().splitlines() if l.startswith('{')]
exe=[a['executable'] for a in artifacts if a.get('reason')=='compiler-artifact' and a.get('executable') and a['target']['name']=='native_syscall_slice'][-1]
frozen=out/'final-executor';shutil.copy2(exe,frozen)
cmd=[str(frozen),'--nocapture','--test-threads=1']
with (out/'executor-final.log').open('wb') as log:
 p=subprocess.run(cmd,env=env,stdout=log,stderr=subprocess.STDOUT)
print('executor-final',p.returncode,flush=True)
rows.append(dict(name='executor-final',argv=cmd,exit_code=p.returncode));(out/'qualification-final-status.json').write_text(json.dumps(rows,indent=2)+'\n')
obs=[json.loads(s.split('native_code_density_observations ',1)[1]) for s in (out/'executor-final.log').read_text().splitlines() if 'native_code_density_observations ' in s]
assert len(obs)==1
(out/'final-observations.json').write_text(json.dumps(obs[0],indent=2)+'\n')
raise SystemExit(p.returncode)
