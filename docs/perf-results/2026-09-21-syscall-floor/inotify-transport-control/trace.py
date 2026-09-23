from pathlib import Path
import subprocess,os,json,hashlib,re
r=Path.cwd();d=r/'target/lease-cost/inotify-transport-control';binary=Path('/Volumes/CaseSensitive/carrick/target/syscall-floor/carrick-itc-c3fb9fd30706')
assert hashlib.sha256(binary.read_bytes()).hexdigest()=='c3fb9fd30706f6f657531084df5a072f7c130b68096e60a9bb22df4213ac50b0'
image='localhost:5050/ltp@sha256:bc75ded40c5827f2ec9e1891edc23b988beae3f428f5be2c8fd7e3ee52fee80b'
rows=[]
for arm,transport in [('mailbox',1),('legacy',0)]:
 rid=f'itc-trace-{arm}-20260922';raw=d/(rid+'.raw')
 env=os.environ.copy();env.update(CARRICK_RUN_ID=rid,CARRICK_INSECURE_REGISTRIES='localhost:5050',CARRICK_HVF_SYSCALL_TRANSPORT=arm)
 cmd=[str(binary),'trace','--require-script-exit','-s',str(r/'scripts/dtrace/hvpatch-inotify-transport-control.d'),'-o',str(raw),'--','run','--max-traps','18446744073709551615','--fs','host','-v',str(d/'probe-current')+':/probe:ro','--entrypoint','/bin/sh',image,'-c','/probe invalid-contract']
 p=subprocess.run(cmd,cwd=r,env=env,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=30)
 (d/(rid+'.out')).write_bytes(p.stdout);(d/(rid+'.err')).write_bytes(p.stderr)
 cleanup=subprocess.run([str(r/'scripts/sudo/kill.sh'),rid],capture_output=True)
 (d/(rid+'.cleanup')).write_bytes(cleanup.stdout+cleanup.stderr)
 row=dict(arm=arm,argv=cmd,returncode=p.returncode,cleanup_returncode=cleanup.returncode)
 rows.append(row);(d/'traces.json').write_text(json.dumps(rows,indent=2)+'\n')
 assert p.returncode==0,(rid,p.stderr.decode(errors='replace'))
 s=raw.read_text();assert 'ITC1|seen=1|errors=0|root_exited=1' in s,s
 counts={(kind,int(t),int(n)):int(c) for kind,t,n,c in re.findall(r'ITC1\|(\w+)\|transport=(\d+)\|nr=(\d+)\|count=(\d+)',s)}
 for nr in [27,28]:
  for k,v in [('requests',169),('returns',169),('missing_decode',0),('reads',0 if transport else 169*9),('sysreads',0 if transport else 169*4),('writes',0 if transport else 169)]:
   assert counts.get((k,transport,nr))==v,(rid,k,nr,counts)
 assert cleanup.returncode==0
 print(rid,'qualified',counts,flush=True)
