import hashlib,json,os,pathlib,statistics,subprocess,sys,time,shutil
root=pathlib.Path.cwd();out=root/'target/lease-cost/compact-native';sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
binary=out/'release-runtime'
mode=sys.argv[1]
assert sha(binary)==(out/'release-binary.sha256').read_text().strip()
rows=[]
cases=[(p,n) for p in range(5) for n in (1,8,32,128)] if mode=='matrix' else [(0,65536),(1,65536),(2,128),(2,65536),(3,65536),(4,65536)]
for repeat in range(1 if mode=='matrix' else 3):
 for index,(p,n) in enumerate(cases):
  pair=[]
  for layout in ([0,1] if (repeat+index)%2==0 else [1,0]):
   label=f'{mode}-{repeat}-{p}-{n}-layout{layout}';stem=out/label
   elf=root/f'target/lease-cost/native-slice/fixtures/watch-{p}-{n}';rid='compact-native-'+label+'-20260922'
   env=os.environ|{'CARRICK_RUN_ID':rid,'CARRICK_NATIVE_BUFFER_ELF':str(elf),'CARRICK_NATIVE_BUFFER_RESULT':str(stem),'CARRICK_NATIVE_BUFFER_READ_CACHE':'1','CARRICK_NATIVE_DATA_DEMAND':'1','CARRICK_NATIVE_CODE_LAYOUT':('slots' if layout==0 else 'compact')}
   cmd=[str(binary),'native_buffers::carrier_buffer_elf_control','--ignored','--nocapture'];start=time.monotonic()
   with pathlib.Path(str(stem)+'.log').open('wb') as log:
    proc=subprocess.run(cmd,env=env,stdin=subprocess.DEVNULL,stdout=log,stderr=subprocess.STDOUT,timeout=50)
   row=dict(phase=p,scale=n,repeat=repeat,layout=('Slots' if layout==0 else 'Compact'),argv=cmd,run_id=rid,exit_code=proc.returncode,wall_s=time.monotonic()-start,binary_sha256=sha(binary),elf_sha256=sha(elf))
   if proc.returncode==0:
    result=json.loads(pathlib.Path(str(stem)+'.json').read_text());assert result['data_demand_enabled'] and result['code_layout']==row['layout']
    assert result['elf_sha256']==sha(elf) and result['read_window_reuse']
    assert result['requests']==((20*n if p in (0,1,2) else 0)+63+(10 if p in (1,2) else 0))
    assert result['completions']==result['requests']-1
    assert result['errno_returns']==(20*n if p==0 else 0)
    row['result']=result;row['samples_ns']=[x/n for x in result['elapsed_ns'][1:]];row['median_ns']=statistics.median(row['samples_ns'])
   rows.append(row);pair.append(row);(out/(mode+'-runs.json')).write_text(json.dumps(rows,indent=2)+'\n')
   print(label,proc.returncode,row.get('median_ns'),flush=True)
   assert proc.returncode==0,label
   assert sha(binary)==(out/'release-binary.sha256').read_text().strip()
  for key in ['requests','completions','errno_returns','transitions','memory_checkpoints','data_activations']:
   assert pair[0]['result'][key]==pair[1]['result'][key],(label,key)
  by={r['layout']:r for r in pair}
  assert by['Compact']['result']['emitted_words'] < by['Slots']['result']['emitted_words']
