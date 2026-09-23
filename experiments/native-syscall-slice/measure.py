#!/usr/bin/env python3
"""Same ELF, serial phases, exact records and artifacts. No tracing during timing."""
from pathlib import Path
import hashlib, json, os, statistics, struct, subprocess, sys, time

root=Path(__file__).resolve().parents[2]
out=root/'target/lease-cost/native-slice'
hvf=root/'target/lease-cost/inotify-transport-control/carrick-control'
native=Path(os.environ.get('NSLICE_NATIVE',root/'target/release/native-syscall-slice')).resolve()
image='localhost:5050/ltp@sha256:bc75ded40c5827f2ec9e1891edc23b988beae3f428f5be2c8fd7e3ee52fee80b'
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
assert sha(hvf)=='c3fb9fd30706f6f657531084df5a072f7c130b68096e60a9bb22df4213ac50b0'
native_sha=sha(native)
rows=[]
arms=sys.argv[1:] or ['native','hvf','docker']
tag=os.environ.get('NSLICE_VARIANT','bounded')
for arm in arms:
    for repeat in range(3):
        for phase,n in [(0,65536),(1,65536),(2,128),(2,65536),(3,65536),(4,65536)]:
            elf=out/f'fixtures/watch-{phase}-{n}'
            rid=f'nslice-{tag}-{arm}-{repeat}-{phase}-{n}-20260922'
            env=dict(os.environ,CARRICK_RUN_ID=rid,CARRICK_HVF_SYSCALL_TRANSPORT='mailbox',CARRICK_INSECURE_REGISTRIES='localhost:5050')
            if arm=='native':cmd=[str(native),str(elf)]
            else:
                prefix=[str(hvf),'run','--max-traps','18446744073709551615','--fs','host'] if arm=='hvf' else ['docker','run','--rm','--name',rid,'--platform','linux/arm64']
                cmd=prefix+['-v',str(elf)+':/probe:ro','--entrypoint','/bin/sh',image,'-c','/probe']
            started=time.monotonic()
            p=subprocess.Popen(cmd,env=env,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
            try:so,se=p.communicate(timeout=40)
            except subprocess.TimeoutExpired:
                if arm=='docker':subprocess.run(['docker','rm','-f',rid],capture_output=True)
                elif arm=='native':p.kill()  # this exact standalone child has no guest host processes
                else:subprocess.run([str(root/'scripts/sudo/kill.sh'),rid],capture_output=True)
                so,se=p.communicate(timeout=10)
                (out/(rid+'.out')).write_bytes(so);(out/(rid+'.err')).write_bytes(se)
                raise
            (out/(rid+'.out')).write_bytes(so);(out/(rid+'.err')).write_bytes(se)
            cleanup=subprocess.run(['docker','ps','-a','--filter','name='+rid,'--format','{{.Names}}'] if arm=='docker' else [str(root/'scripts/sudo/kill.sh'),rid],capture_output=True)
            (out/(rid+'.cleanup')).write_bytes(cleanup.stdout+cleanup.stderr)
            assert p.returncode==0,(rid,p.returncode,se)
            assert cleanup.returncode==0
            if arm=='docker':assert not cleanup.stdout
            assert len(so)==560,(rid,len(so),so[:80],se)
            values=[]
            for ph,count,s,ns,e,en,q in struct.iter_unpack('<7Q',so):
                assert ph==phase and count==n and ns<10**9 and en<10**9
                assert q==(min(n,16384)*16+(16 if n>16384 else 0) if phase==2 else 0)
                elapsed=(e-s)*10**9+en-ns
                assert elapsed>0
                values.append(elapsed/n)
            row=dict(arm=arm,repeat=repeat,phase=phase,n=n,run_id=rid,pid=p.pid,argv=cmd,returncode=p.returncode,wall_s=time.monotonic()-started,
                elf_sha256=sha(elf),binary_sha256=sha(native if arm=='native' else hvf) if arm!='docker' else None,
                samples_ns=values[1:],warmup_ns=values[0],median_ns=statistics.median(values[1:]))
            if arm=='native':
                counts=json.loads(se);hist=counts['syscalls']
                assert counts['exit']==0 and counts['requests']==counts['completions']+1
                assert hist.get('27',0)==(20*n+10 if phase==1 else 10*n if phase in [0,2] else 0)
                assert hist.get('28',0)==(10*n if phase in [0,2] else 0)
                assert counts['errno_returns']==(20*n if phase==0 else 0)
                row['counts']=counts
            assert sha(native)==native_sha, 'native timing artifact changed'
            rows.append(row)
            (out/('runs-'+tag+'-'+ '-'.join(arms)+'.json')).write_text(json.dumps(rows,indent=2)+'\n')
            print(json.dumps({k:row[k] for k in ['run_id','median_ns','wall_s']}),flush=True)
assert sha(hvf)=='c3fb9fd30706f6f657531084df5a072f7c130b68096e60a9bb22df4213ac50b0'
