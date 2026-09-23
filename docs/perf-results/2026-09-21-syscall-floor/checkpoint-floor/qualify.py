import pathlib,subprocess,os,json,time,hashlib
out=pathlib.Path('target/lease-cost/checkpoint-floor').resolve()
inputs=json.loads((out/'before-hashes.json').read_text())
# Include the new contract and runtime diagnostic in this run's identity.
inputs={k:hashlib.sha256(pathlib.Path(k).read_bytes()).hexdigest() for k in inputs}
for p in ['conformance-contracts/contracts/native-data-demand.toml','crates/carrick-runtime/src/vcpu_loop/memory/tests/native_floor.rs']:
 inputs[p]=hashlib.sha256(pathlib.Path(p).read_bytes()).hexdigest()
revision='sha256:'+hashlib.sha256(json.dumps(inputs,sort_keys=True,separators=(',',':')).encode()).hexdigest()
(out/'tested-source-hashes.json').write_text(json.dumps(inputs,indent=2)+'\n')
(out/'tested-source-revision.txt').write_text(revision+'\n')
env=os.environ|{'RUSTC_WRAPPER':'','CARRICK_NATIVE_DATA_DEMAND_OBSERVATIONS':str(out/'green-observations.json'),'CARRICK_NATIVE_SCOPE_REVISION':revision}
commands=[
 ('runtime-memory',['cargo','test','-p','carrick-runtime','--features','conformance-metrics','--lib','vcpu_loop::memory::tests::','--','--nocapture']),
 ('registry',['cargo','test','-p','carrick-conformance-contract']),
 ('observability',['cargo','test','-p','carrick-observability','--lib']),
 ('elf-clippy',['cargo','clippy','--manifest-path','experiments/native-syscall-slice/Cargo.toml','--all-targets','--','-D','warnings']),
 ('runtime-clippy',['cargo','clippy','--no-deps','-p','carrick-runtime','-p','carrick-observability','--all-targets','--features','carrick-runtime/conformance-metrics','--','-D','warnings']),
]
rows=[]
for name,cmd in commands:
 start=time.monotonic()
 with (out/(name+'.log')).open('wb') as log:
  p=subprocess.run(cmd,env=env,stdout=log,stderr=subprocess.STDOUT,stdin=subprocess.DEVNULL)
 rows.append(dict(name=name,argv=cmd,exit_code=p.returncode,wall_s=time.monotonic()-start))
 (out/'qualification-status.json').write_text(json.dumps(rows,indent=2)+'\n');print(name,p.returncode,flush=True)
 if p.returncode: raise SystemExit(p.returncode)
