from pathlib import Path
import argparse,hashlib,json,os,re,subprocess,time
ROOT=Path(__file__).resolve().parents[3]
OUT=Path(__file__).resolve().parent
BIN=ROOT/'target/lease-cost/carrick-sp'
NODE='localhost:5005/carrick-nodejs-conformance@sha256:1ed49af83bd30401e1b275957b99a1c28f6c582ab3d987997afb5888fa302718'
GO='localhost:5005/carrick-go-conformance@sha256:357a08793e683c6a174d3955c704a5194e825f38fcdcb91d1d4ee2bccd6b188b'
PYTHON='localhost:5050/cpython-test@sha256:3126629643b4adcf57ba5cecdb7f9ed257e733b56cd81da70fd5fdbdc1745b30'
WORK={
 'node-app':(NODE,"time /opt/node-src/v24/out/Release/node /opt/nodejs-conformance/fixtures/app-smoke.js",15),
 'go-build-cold':(GO,"cd /tmp; printf 'package main\\nfunc main(){println(\"ok\")}\\n' > floor.go; export GOCACHE=$(mktemp -d); time /usr/local/go/bin/go build -o /tmp/floor ./floor.go; /tmp/floor; echo BUILD_OK",120),
 'python-os':(PYTHON,'time /usr/local/bin/python3 -m test -v --randseed 0 test_os',300),
 'python-subprocess':(PYTHON,'time /usr/local/bin/python3 -m test -v --randseed 0 test_subprocess',300),
}
def main():
 ap=argparse.ArgumentParser();ap.add_argument('phase',choices=['docker','carrick']);ap.add_argument('--label',required=True);ap.add_argument('--workloads',default=','.join(WORK));args=ap.parse_args()
 path=OUT/(args.label+'.jsonl')
 assert not path.exists(),path
 for name in args.workloads.split(','):
  image,body,bound=WORK[name];rid=f'floor-{args.label}-{name}'
  script="set -eu; TIMEFORMAT='WORKLOAD_TIMING real_s=%R user_s=%U sys_s=%S'; "+body
  if args.phase=='docker':argv=['docker','run','--rm','--name',rid,'--platform','linux/arm64','--entrypoint','/bin/bash',image,'-c',script]
  else:argv=[str(BIN),'run','--max-traps','18446744073709551615','--fs','host','--entrypoint','/bin/bash',image,'-c',script]
  env=os.environ.copy();env['CARRICK_RUN_ID']=rid;env['CARRICK_INSECURE_REGISTRIES']='localhost:5005,localhost:5050'
  start=time.monotonic();p=subprocess.Popen(argv,cwd=ROOT,env=env,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
  timed_out=False
  try:stdout,stderr=p.communicate(timeout=bound)
  except subprocess.TimeoutExpired:
   timed_out=True
   if args.phase=='docker':cleanup=subprocess.run(['docker','rm','-f',rid],capture_output=True)
   else:cleanup=subprocess.run([str(ROOT/'scripts/sudo/kill.sh'),rid],capture_output=True)
   (OUT/(rid+'.cleanup')).write_bytes(cleanup.stdout+cleanup.stderr)
   try:stdout,stderr=p.communicate(timeout=10)
   except subprocess.TimeoutExpired:
    p.kill();stdout,stderr=p.communicate()
  elapsed=time.monotonic()-start
  (OUT/(rid+'.out')).write_bytes(stdout);(OUT/(rid+'.err')).write_bytes(stderr)
  matches=re.findall(rb'WORKLOAD_TIMING real_s=([0-9.]+) user_s=([0-9.]+) sys_s=([0-9.]+)',stderr)
  row={'name':name,'phase':args.phase,'run_id':rid,'argv':argv,'timeout_s':bound,'timed_out':timed_out,'returncode':p.returncode,'outer_wall_s':elapsed,'guest_timing':[[float(v) for v in m] for m in matches],'binary_sha256':hashlib.sha256(BIN.read_bytes()).hexdigest() if args.phase=='carrick' else None,'driver_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest()}
  with path.open('a') as f:f.write(json.dumps(row)+'\n')
  print(json.dumps({k:row[k] for k in ['name','phase','returncode','timed_out','outer_wall_s','guest_timing']}),flush=True)
  if timed_out:raise SystemExit('Timed-out workload retained; inspect cleanup before continuing.')
if __name__=='__main__':main()
