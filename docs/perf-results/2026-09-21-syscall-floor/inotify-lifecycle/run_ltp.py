from pathlib import Path
import subprocess,os,json,time,hashlib
root=Path.cwd();out=root/'target/lease-cost/inotify-lifecycle';binary=out/'carrick-candidate';image='localhost:5050/ltp@sha256:bc75ded40c5827f2ec9e1891edc23b988beae3f428f5be2c8fd7e3ee52fee80b'
rows=[]
for phase in ['carrick','docker']:
 rid='inotify09-lifecycle-'+phase+'-20260922'
 prefix=[str(binary),'run','--max-traps','18446744073709551615','--fs','host'] if phase=='carrick' else ['docker','run','--rm','--name',rid,'--platform','linux/arm64']
 cmd=prefix+['--entrypoint','/bin/sh',image,'-c','/opt/ltp/testcases/bin/inotify09']
 env=os.environ.copy();env.update(CARRICK_RUN_ID=rid,CARRICK_INSECURE_REGISTRIES='localhost:5050')
 start=time.monotonic();p=subprocess.Popen(cmd,env=env,cwd=root,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
 try:so,se=p.communicate(timeout=40);bounded=False
 except subprocess.TimeoutExpired:
  subprocess.run([str(root/'scripts/sudo/kill.sh'),rid] if phase=='carrick' else ['docker','rm','-f',rid]);so,se=p.communicate(timeout=10);bounded=True
 elapsed=time.monotonic()-start
 (out/(rid+'.out')).write_bytes(so);(out/(rid+'.err')).write_bytes(se)
 cleanup=subprocess.run([str(root/'scripts/sudo/kill.sh'),rid] if phase=='carrick' else ['docker','ps','-a','--filter','name='+rid,'--format','{{.Names}}'],capture_output=True)
 (out/(rid+'.cleanup')).write_bytes(cleanup.stdout+cleanup.stderr)
 row=dict(phase=phase,argv=cmd,run_id=rid,returncode=p.returncode,elapsed_s=elapsed,bounded=bounded,cleanup_returncode=cleanup.returncode,binary_sha256=hashlib.sha256(binary.read_bytes()).hexdigest() if phase=='carrick' else None)
 rows.append(row);(out/'ltp.json').write_text(json.dumps(rows,indent=2)+'\n')
 print(row,so.decode(errors='replace'),se.decode(errors='replace'),flush=True)
