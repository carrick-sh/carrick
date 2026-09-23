import json,os,pathlib,subprocess,time
out=pathlib.Path('target/lease-cost/current-read-reuse')
commands=[
 ('inventory',['cargo','run','-p','carrick-conformance-contract','--bin','generate-inventory']),
 ('registry',['cargo','test','-p','carrick-conformance-contract']),
 ('clippy-final',['cargo','clippy','--no-deps','-p','carrick-kernel','-p','carrick-runtime','-p','carrick-vmm-hvf','-p','carrick-hal','--all-targets','--features','carrick-runtime/conformance-metrics','--','-D','warnings']),
 ('kernel',['just','test-kernel']),
 ('runtime-memory',['cargo','test','-p','carrick-runtime','--features','conformance-metrics','--lib','vcpu_loop::memory::tests::','--','--nocapture']),
 ('runtime-quiesce',['cargo','test','-p','carrick-runtime','--features','conformance-metrics','--lib','quiesce','--','--nocapture']),
 ('memory-doctests',['cargo','test','-p','carrick-kernel','--doc','mm_access']),
 ('elf-tests',['cargo','test','--manifest-path','experiments/native-syscall-slice/Cargo.toml','--tests']),
 ('elf-clippy',['cargo','clippy','--manifest-path','experiments/native-syscall-slice/Cargo.toml','--all-targets','--','-D','warnings']),
 ('product-layering',['scripts/closure-assert-layering.sh']),
 ('signed-foreign-mm',['scripts/test-signed.sh','carrick-vmm-hvf','trap::foreign_mm::tests::','--nocapture']),
]
rows=[]
env=os.environ|{'RUSTC_WRAPPER':'','CARRICK_RUN_ID':'current-read-foreign-mm-20260922','CARRICK_TEST_SIGNED_FEATURES':'','CARRICK_CURRENT_READ_OBSERVATIONS':str(out.resolve()/'green-observations.json')}
for name,cmd in commands:
 started=time.monotonic()
 with (out/(name+'.log')).open('wb') as log:
  p=subprocess.run(cmd,env=env,stdout=log,stderr=subprocess.STDOUT,stdin=subprocess.DEVNULL)
 rows.append(dict(name=name,argv=cmd,exit_code=p.returncode,wall_s=time.monotonic()-started))
 (out/'verification-status.json').write_text(json.dumps(rows,indent=2)+'\n')
 print(name,p.returncode,flush=True)
