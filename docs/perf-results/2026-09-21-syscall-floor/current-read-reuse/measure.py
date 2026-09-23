import hashlib, json, os, pathlib, statistics, subprocess, sys, time
root=pathlib.Path.cwd(); out=root/'target/lease-cost/current-read-reuse'
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
binary=out/'release-runtime'
if sys.argv[1]=='capture':
 import shutil
 builds=[json.loads(s) for s in (out/'release-build.jsonl').read_text().splitlines() if s.startswith('{')]
 exe=[r['executable'] for r in builds if r.get('reason')=='compiler-artifact' and r.get('target',{}).get('name')=='carrick_runtime' and r.get('executable')][-1]
 shutil.copy2(exe,binary)
 (out/'release-binary.sha256').write_text(sha(binary)+'\n')
 sys.exit(0)
assert sha(binary)==(out/'release-binary.sha256').read_text().strip()
rows=[]
phase=sys.argv[1]
cases=[(p,n) for p in range(5) for n in (1,8,32,128)] if phase=='matrix' else [(0,65536),(1,65536),(2,128),(2,65536),(3,65536),(4,65536)]
for repeat in range(1 if phase=='matrix' else 3):
 for index,(p,n) in enumerate(cases):
  for reuse in ([1] if phase=='matrix' else ([0,1] if (repeat+index)%2==0 else [1,0])):
   label=f'{phase}-{repeat}-{p}-{n}-reuse{reuse}'
   stem=out/label; elf=root/f'target/lease-cost/native-slice/fixtures/watch-{p}-{n}'
   rid='read-reuse-'+label+'-20260922'
   env=os.environ|{'CARRICK_RUN_ID':rid,'CARRICK_NATIVE_BUFFER_ELF':str(elf),'CARRICK_NATIVE_BUFFER_RESULT':str(stem),'CARRICK_NATIVE_BUFFER_READ_CACHE':str(reuse)}
   cmd=[str(binary),'native_buffers::carrier_buffer_elf_control','--ignored','--nocapture']
   started=time.monotonic()
   with pathlib.Path(str(stem)+'.log').open('wb') as log:
    proc=subprocess.run(cmd,env=env,stdin=subprocess.DEVNULL,stdout=log,stderr=subprocess.STDOUT,timeout=50)
   row=dict(phase=p,scale=n,repeat=repeat,reuse=bool(reuse),argv=cmd,run_id=rid,exit_code=proc.returncode,wall_s=time.monotonic()-started,binary_sha256=sha(binary),elf_sha256=sha(elf))
   if proc.returncode==0:
    result=json.loads(pathlib.Path(str(stem)+'.json').read_text());assert result['read_window_reuse']==bool(reuse)
    assert result['elf_sha256']==sha(elf)
    row['result']=result;row['samples_ns']=[x/n for x in result['elapsed_ns'][1:]];row['median_ns']=statistics.median(row['samples_ns'])
   rows.append(row);(out/(phase+'-runs.json')).write_text(json.dumps(rows,indent=2)+'\n')
   print(label,proc.returncode,row.get('median_ns'),flush=True)
   assert proc.returncode==0,label
   assert sha(binary)==(out/'release-binary.sha256').read_text().strip()
