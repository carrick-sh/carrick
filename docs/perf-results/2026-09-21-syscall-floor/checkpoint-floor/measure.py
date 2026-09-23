import hashlib,json,os,pathlib,statistics,subprocess,sys,time,shutil
root=pathlib.Path.cwd();out=root/'target/lease-cost/checkpoint-floor';sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
binary=out/'release-runtime'
mode=sys.argv[1]
if mode=='capture':
 rs=[json.loads(s) for s in (out/'release-build-final.jsonl').read_text().splitlines()]
 assert rs[-1]['reason']=='build-finished' and rs[-1]['success']
 exe=[r['executable'] for r in rs if r.get('reason')=='compiler-artifact' and r.get('target',{}).get('name')=='carrick_runtime' and r.get('executable')][-1]
 shutil.copy2(exe,binary);(out/'release-binary.sha256').write_text(sha(binary)+'\n');print(sha(binary));sys.exit(0)
assert sha(binary)==(out/'release-binary.sha256').read_text().strip()
if mode=='components':
 with (out/'final-components.log').open('wb') as f:
  p=subprocess.run([str(binary),'native_floor::carrier_checkpoint_component_cost','--ignored','--nocapture'],stdin=subprocess.DEVNULL,stdout=f,stderr=subprocess.STDOUT,timeout=50)
 assert p.returncode==0
 rows=[json.loads(s.split('native_checkpoint_cost ',1)[1]) for s in (out/'final-components.log').read_text().splitlines() if s.startswith('native_checkpoint_cost ')]
 (out/'final-components.json').write_text(json.dumps(rows,indent=2)+'\n')
 for a in dict.fromkeys(r['arm'] for r in rows):
  v=[r['pair_ns'] for r in rows if r['arm']==a and not r['warmup']];print(a,statistics.median(v),min(v),max(v))
 sys.exit(0)
rows=[]
cases=[(p,n) for p in range(5) for n in (1,8,32,128)] if mode=='matrix' else [(0,65536),(1,65536),(2,128),(2,65536),(3,65536),(4,65536)]
for repeat in range(1 if mode=='matrix' else 3):
 for index,(p,n) in enumerate(cases):
  pair=[]
  for demand in ([0,1] if (repeat+index)%2==0 else [1,0]):
   label=f'{mode}-{repeat}-{p}-{n}-demand{demand}';stem=out/label
   elf=root/f'target/lease-cost/native-slice/fixtures/watch-{p}-{n}';rid='checkpoint-floor-'+label+'-20260922'
   env=os.environ|{'CARRICK_RUN_ID':rid,'CARRICK_NATIVE_BUFFER_ELF':str(elf),'CARRICK_NATIVE_BUFFER_RESULT':str(stem),'CARRICK_NATIVE_BUFFER_READ_CACHE':'1','CARRICK_NATIVE_DATA_DEMAND':str(demand)}
   cmd=[str(binary),'native_buffers::carrier_buffer_elf_control','--ignored','--nocapture'];start=time.monotonic()
   with pathlib.Path(str(stem)+'.log').open('wb') as log:
    proc=subprocess.run(cmd,env=env,stdin=subprocess.DEVNULL,stdout=log,stderr=subprocess.STDOUT,timeout=50)
   row=dict(phase=p,scale=n,repeat=repeat,demand=bool(demand),argv=cmd,run_id=rid,exit_code=proc.returncode,wall_s=time.monotonic()-start,binary_sha256=sha(binary),elf_sha256=sha(elf))
   if proc.returncode==0:
    result=json.loads(pathlib.Path(str(stem)+'.json').read_text());assert result['data_demand_enabled']==bool(demand)
    assert result['elf_sha256']==sha(elf) and result['read_window_reuse']
    assert result['requests']==((20*n if p in (0,1,2) else 0)+63+(10 if p in (1,2) else 0))
    assert result['completions']==result['requests']-1
    assert result['errno_returns']==(20*n if p==0 else 0)
    row['result']=result;row['samples_ns']=[x/n for x in result['elapsed_ns'][1:]];row['median_ns']=statistics.median(row['samples_ns'])
   rows.append(row);pair.append(row);(out/(mode+'-runs.json')).write_text(json.dumps(rows,indent=2)+'\n')
   print(label,proc.returncode,row.get('median_ns'),flush=True)
   assert proc.returncode==0,label
   assert sha(binary)==(out/'release-binary.sha256').read_text().strip()
  for key in ['requests','completions','errno_returns','transitions','memory_checkpoints']:
   assert pair[0]['result'][key]==pair[1]['result'][key],(label,key)
  by={r['demand']:r for r in pair}
  assert by[True]['result']['data_activations']<=by[False]['result']['data_activations']
  assert by[False]['result']['data_activations']==by[False]['result']['transitions']
