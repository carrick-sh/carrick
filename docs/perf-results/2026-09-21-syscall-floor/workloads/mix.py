from pathlib import Path
import argparse,hashlib,json,os,re,shlex,subprocess,time
import screen
OUT=screen.OUT;ROOT=screen.ROOT
TRACER='localhost:5050/ltp@sha256:bc75ded40c5827f2ec9e1891edc23b988beae3f428f5be2c8fd7e3ee52fee80b'
SCRIPT=ROOT/'scripts/bpftrace/oracle-syscall-mix.bt'
def cmd(a,**kw):return subprocess.run(a,check=True,capture_output=True,text=True,**kw).stdout.strip()
def main():
 ap=argparse.ArgumentParser();ap.add_argument('name',choices=list(screen.WORK));ap.add_argument('--label',required=True);a=ap.parse_args()
 image,body,bound=screen.WORK[a.name];stem=f'floor-mix-{a.label}-{a.name}';target=stem+'-work';helper=stem+'-trace'
 raw=OUT/(stem+'.trace');err=OUT/(stem+'.err');assert not raw.exists()
 inner="kill -STOP $$; set -eu; TIMEFORMAT='WORKLOAD_TIMING real_s=%R user_s=%U sys_s=%S'; "+body
 outer='/bin/bash -c '+shlex.quote(inner)+'; exit $?'
 target_argv=['docker','run','-d','--name',target,'--platform','linux/arm64','--entrypoint','/bin/bash',image,'-c',outer]
 trace=None
 try:
  container=cmd(target_argv);root=int(cmd(['docker','inspect','-f','{{.State.Pid}}',target]))
  children=cmd(['docker','run','--rm','--pid=host','--entrypoint','/bin/sh',TRACER,'-c',f'cat /proc/{root}/task/{root}/children'])
  assert len(children.split())==1,children
  pid=int(children)
  status=cmd(['docker','run','--rm','--pid=host','--entrypoint','/bin/sh',TRACER,'-c',f'cat /proc/{pid}/status'])
  assert re.search(r'State:\s+T',status),status
  (OUT/(stem+'.initial-status')).write_text(status)
  trace_argv=['docker','run','--rm','--name',helper,'--privileged','--pid=host','--entrypoint','/bin/sh','-v',f'{SCRIPT}:/mix.bt:ro',TRACER,'-c','mount -t tracefs tracefs /sys/kernel/tracing 2>/dev/null || true; exec bpftrace -B line /mix.bt "$1" "$2"','sh',str(pid),str(bound)]
  with raw.open('w') as f,err.open('w') as e:
   trace=subprocess.Popen(trace_argv,stdout=f,stderr=e)
   deadline=time.monotonic()+30
   while f'ORACLEMIX1|ready|root={pid}' not in raw.read_text():
    if trace.poll() is not None:raise RuntimeError(err.read_text())
    if time.monotonic()>deadline:raise RuntimeError('bpftrace readiness deadline')
    time.sleep(.1)
   cmd(['docker','exec',helper,'/bin/kill','-CONT',str(pid)])
   rc=trace.wait(timeout=bound+5)
  exitcode=int(cmd(['docker','wait',target],timeout=5))
  logs=subprocess.run(['docker','logs',target],capture_output=True)
  (OUT/(stem+'.out')).write_bytes(logs.stdout);(OUT/(stem+'.work-err')).write_bytes(logs.stderr)
  text=raw.read_text();errors=err.read_text()
  counts={int(k):int(v) for k,v in re.findall(r'^@calls\[(\d+)\]: (\d+)$',text,re.M)}
  totals=re.findall(r'^@total: (\d+)$',text,re.M)
  assert rc==0 and exitcode==0,(rc,exitcode)
  assert f'ORACLEMIX1|complete|root={pid}' in text and 'error=' not in text,text
  assert len(totals)==1 and int(totals[0])==sum(counts.values())>0,(totals,counts)
  assert '@tracked[' not in text,text
  assert not re.search(r'dropped|lost events|ERROR:',errors,re.I),errors
  names={int(n):s for n,s in re.findall(r'\(\s*\w+,\s*(\d+),\s*"([^"]+)"', (ROOT/'crates/carrick-abi/src/syscall.rs').read_text())}
  receipt={'workload':a.name,'image':image,'tracer_image':TRACER,'target_argv':target_argv,'trace_argv':trace_argv,'root_pid':pid,'total':sum(counts.values()),'script_sha256':hashlib.sha256(SCRIPT.read_bytes()).hexdigest(),'returncode':rc,'workload_returncode':exitcode,'calls':[{'nr':nr,'name':names.get(nr,'unknown'),'count':n} for nr,n in sorted(counts.items(),key=lambda kv:-kv[1])],'scope':'Stopped inner bash and every descendant TID after tracer readiness; includes timed command plus wrapper body; instrumented times are not performance evidence.'}
  (OUT/(stem+'.json')).write_text(json.dumps(receipt,indent=2)+'\n')
  print(json.dumps({'workload':a.name,'total':receipt['total'],'top':receipt['calls'][:12]},indent=2),flush=True)
 finally:
  for name in [helper,target]:subprocess.run(['docker','rm','-f',name],capture_output=True)
  if trace is not None and trace.poll() is None:trace.wait(timeout=5)
if __name__=='__main__':main()
