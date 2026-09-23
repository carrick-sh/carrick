import subprocess,sys,selectors
subprocess._PopenSelector=selectors.SelectSelector
for i in range(50):
 print('iteration',i,flush=True)
 try: subprocess.call([sys.executable,'-c','while True: pass'],timeout=0.1)
 except subprocess.TimeoutExpired: pass
 else: raise AssertionError('child returned')
print('KILL_WAIT_OK',flush=True)
