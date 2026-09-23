from pathlib import Path
import subprocess,os,json,hashlib,time
root=Path('/Users/tjfontaine/.codex/worktrees/inotify-lease-cost/carrick')
out=root/'target/lease-cost/node-child-control/base-service'
binary=Path('/Volumes/CaseSensitive/carrick/target/syscall-floor/carrick-discard-retire')
script=root/'scripts/dtrace/hvpatch-syscall-service-budget.d'
image='localhost:5005/carrick-nodejs-conformance@sha256:1ed49af83bd30401e1b275957b99a1c28f6c582ab3d987997afb5888fa302718'
rid='node-base-service-20260922-1'
import shlex
code=(root/'target/lease-cost/node-child-control/base.js').read_text()
body='set -eu; printf %s '+shlex.quote(code)+' > /tmp/node-child.js; for n in 1 2 3 4 5; do /opt/node-src/v24/out/Release/node /tmp/node-child.js; done; echo POPULATION_DONE'
cmd=[str(binary),'trace','--require-script-exit','-s',str(script),'-o',str(out/'trace.raw'),'--','run','--max-traps','18446744073709551615','--fs','host','--entrypoint','/bin/sh',image,'-c',body]
env=os.environ.copy();env.update(CARRICK_RUN_ID=rid,CARRICK_INSECURE_REGISTRIES='localhost:5005,localhost:5050')
(out/'inputs.json').write_text(json.dumps({'argv':cmd,'run_id':rid,'iterations':5,'binary_sha256':hashlib.sha256(binary.read_bytes()).hexdigest(),'script_sha256':hashlib.sha256(script.read_bytes()).hexdigest()},indent=2)+'\n')
with (out/'stdout').open('wb') as stdout,(out/'stderr').open('wb') as stderr:
 p=subprocess.Popen(cmd,cwd=root,env=env,stdin=subprocess.DEVNULL,stdout=stdout,stderr=stderr)
 try: rc=p.wait(timeout=40)
 except subprocess.TimeoutExpired:
  subprocess.run([str(root/'scripts/sudo/kill.sh'),rid],cwd=root,check=False)
  rc=p.wait(timeout=15)
cleanup=subprocess.run([str(root/'scripts/sudo/kill.sh'),rid],cwd=root,capture_output=True)
(out/'cleanup.log').write_bytes(cleanup.stdout+cleanup.stderr)
(out/'status.json').write_text(json.dumps({'returncode':rc,'cleanup_returncode':cleanup.returncode})+'\n')
print({'returncode':rc,'cleanup_returncode':cleanup.returncode})
