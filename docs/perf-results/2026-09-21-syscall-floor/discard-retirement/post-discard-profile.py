from pathlib import Path
import screen,subprocess,json,os,hashlib
binary=Path('/Volumes/CaseSensitive/carrick/target/syscall-floor/carrick-discard-retire')
for name,n in [('node-app',20)]:
 image,body,_=screen.WORK[name];label='post-discard-'+name;rid='floor-'+label
 raw=screen.OUT/(label+'.raw')
 argv=[str(binary),'trace','--require-script-exit','--profile','hvpatch-carrier-cpu-low-rate','-o',str(raw),'--','run','--max-traps','18446744073709551615','--fs','host','--entrypoint','/bin/bash',image,'-c',f'set -eu; for i in $(seq 1 {n}); do ( {body} ); done; echo PROFILE_WORKLOAD_OK']
 (screen.OUT/(label+'.command.json')).write_text(json.dumps({'argv':argv,'run_id':rid,'binary_sha256':hashlib.sha256(binary.read_bytes()).hexdigest()},indent=2))
 with (screen.OUT/(label+'.out')).open('w') as out,(screen.OUT/(label+'.err')).open('w') as err:
  p=subprocess.Popen(argv,env={**os.environ,'CARRICK_RUN_ID':rid,'CARRICK_INSECURE_REGISTRIES':'localhost:5005,localhost:5050'},stdin=subprocess.DEVNULL,stdout=out,stderr=err)
  try:code=p.wait(timeout=110)
  finally:
   clean=subprocess.run(['scripts/sudo/kill.sh',rid],capture_output=True,text=True)
   (screen.OUT/(label+'.cleanup')).write_text(clean.stdout+clean.stderr)
   if p.poll() is None:p.kill();p.wait()
  assert code==0,(name,code)
 assert 'PROFILE_WORKLOAD_OK' in (screen.OUT/(label+'.out')).read_text()
 subprocess.run(['python3',str(screen.OUT/'symbolize.py'),str(raw),str(binary)],check=True)
