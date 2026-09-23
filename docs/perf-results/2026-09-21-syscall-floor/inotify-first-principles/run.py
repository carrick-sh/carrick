from pathlib import Path
import subprocess,os,json,hashlib
root=Path.cwd();out=root/'target/lease-cost/inotify-first-principles'
binary=Path('/Volumes/CaseSensitive/carrick/target/syscall-floor/carrick-discard-edges')
image='localhost:5050/cpython-test@sha256:3126629643b4adcf57ba5cecdb7f9ed257e733b56cd81da70fd5fdbdc1745b30'
source=(out/'queue_shape.py').read_text();rows=[]
for phase in ['carrick','docker']:
 rid='inotify-queue-shape-'+phase+'-20260922'
 prefix=[str(binary),'run','--max-traps','18446744073709551615','--fs','host'] if phase=='carrick' else ['docker','run','--rm','--name',rid,'--platform','linux/arm64']
 cmd=prefix+['--entrypoint','/usr/local/bin/python3',image,'-c',source]
 env=os.environ.copy();env.update(CARRICK_RUN_ID=rid,CARRICK_INSECURE_REGISTRIES='localhost:5050')
 with (out/(phase+'.out')).open('wb') as so,(out/(phase+'.err')).open('wb') as se:
  p=subprocess.Popen(cmd,cwd=root,env=env,stdin=subprocess.DEVNULL,stdout=so,stderr=se)
  try:rc=p.wait(timeout=30)
  except subprocess.TimeoutExpired:
   subprocess.run([str(root/'scripts/sudo/kill.sh'),rid] if phase=='carrick' else ['docker','rm','-f',rid]);raise
 cleanup=subprocess.run([str(root/'scripts/sudo/kill.sh'),rid] if phase=='carrick' else ['docker','ps','-a','--filter','name='+rid,'--format','{{.Names}}'],capture_output=True)
 (out/(phase+'.cleanup')).write_bytes(cleanup.stdout+cleanup.stderr)
 rows.append(dict(phase=phase,argv=cmd,run_id=rid,returncode=rc,source_sha256=hashlib.sha256(source.encode()).hexdigest(),binary_sha256=hashlib.sha256(binary.read_bytes()).hexdigest() if phase=='carrick' else None,cleanup_returncode=cleanup.returncode))
 (out/'runs.json').write_text(json.dumps(rows,indent=2)+'\n')
 assert rc==0 and 'probe_complete=1' in (out/(phase+'.out')).read_text()
 print(phase, (out/(phase+'.out')).read_text(),flush=True)
