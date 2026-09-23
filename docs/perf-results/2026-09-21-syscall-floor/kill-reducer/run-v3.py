from pathlib import Path
import subprocess,os,json,hashlib
root=Path.cwd();out=root/'target/lease-cost/kill-reducer'
image='localhost:5050/cpython-test@sha256:3126629643b4adcf57ba5cecdb7f9ed257e733b56cd81da70fd5fdbdc1745b30'
code='''import subprocess,sys,selectors
subprocess._PopenSelector=selectors.SelectSelector
for i in range(50):
 print('iteration',i,flush=True)
 try: subprocess.call([sys.executable,'-c','while True: pass'],timeout=0.1)
 except subprocess.TimeoutExpired: pass
 else: raise AssertionError('child returned')
print('KILL_WAIT_OK',flush=True)
'''
(out/'guest.py').write_text(code)
for arm in ['lease-gap']:
 binary=root/'target/lease-cost'/('carrick-'+arm);rid='kill-floor-v3-'+arm
 env=os.environ.copy();env['CARRICK_INSECURE_REGISTRIES']='localhost:5005,localhost:5050'
 cmd=[str(binary),'debug','lldb-run','--deadline-seconds','20','--out-dir',str(out/(arm+'-v2')),'--run-id',rid,'--','--max-traps','18446744073709551615','--fs','host','--entrypoint','/usr/local/bin/python3',image,'-c',code]
 with (out/(arm+'-v2.log')).open('wb') as f:
  p=subprocess.run(cmd,env=env,stdout=f,stderr=subprocess.STDOUT)
 (out/(arm+'-v2.json')).write_text(json.dumps({'argv':cmd,'returncode':p.returncode,'sha256':hashlib.sha256(binary.read_bytes()).hexdigest()},indent=2)+'\n')
 print(arm,p.returncode,flush=True)
