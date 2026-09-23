from pathlib import Path
import re,subprocess,json,collections
out=Path(__file__).parent/'trace8';raw=(out/'trace.raw').read_text();status=json.loads((out/'status.json').read_text())
assert status=={'returncode':0,'cleanup_returncode':0}
assert 'TCB1|summary|seen=1|errors=0|exited=1' in raw
stdout=(out/'stdout').read_text();assert stdout.count('app-smoke ok')==8 and stdout.count('GROUP_DONE')==1
assert not re.search(r'\b(?:drops?|errors?)\b',(out/'stderr').read_text(),re.I)
counts={}
for op,phase,val in re.findall(r'TCB1\|count\|op=(\d+)\|phase=(\d+)\|v=(\d+)',raw):counts[int(op),int(phase)]=int(val)
for op in {o for o,p in counts}:
 assert counts.get((op,0),0)==counts.get((op,1),0)+counts.get((op,3),0)
 assert counts.get((op,1),0)==counts.get((op,2),0)
rows=[]
for phase in ['wait','hold']:
 part=raw.split('TCB1|'+phase+'-stacks\n')[1].split('TCB1|')[0]
 op=None;stack=[]
 for line in part.splitlines():
  t=line.strip()
  if not t:continue
  if t.startswith('0x'):stack.append(t)
  elif op is None:op=int(t)
  else:
   assert stack
   rows.append({'phase':phase,'operation':op,'ns':int(t),'addresses':stack})
   op=None;stack=[]
 assert op is None and not stack
addresses=sorted({a for r in rows for a in r['addresses']})
binary='/Volumes/CaseSensitive/carrick/target/syscall-floor/carrick-discard-edges'
# Observed probe PC 0x10340f404 minus exact binary USDT nop 0x100d4f404.
# Both were qualified with nm and otool. Slide is 0x26c0000, load 0x1026c0000.
resolved=subprocess.check_output(['atos','-o',binary,'-l','0x1026c0000',*addresses],text=True).splitlines()
assert len(addresses)==len(resolved)
symbols=dict(zip(addresses,resolved));totals=collections.defaultdict(int)
for r in rows:
 r['symbols']=[symbols[a] for a in r['addresses']]
 joined='\n'.join(r['symbols'])
 if 'FrameRegistryGuard' in joined:r['class']='frame_registry'
 elif 'MmTransactionGuard' in joined or 'MmMutationGuard::begin_transaction' in joined or 'terminal_process_transaction' in joined:r['class']='mm_transaction'
 elif r['phase']=='hold' and int(r['addresses'][2],16)-0x26c0000 in [0x100499ddc,0x1004d62a4]:
  # Exact return PCs; symbol-qualification.txt proves BL MmTransactionGuard::drop.
  r['class']='mm_transaction'
 else:r['class']='unresolved'
 totals[r['phase'],r['operation'],r['class']]+=r['ns']
rows.sort(key=lambda r:r['ns'],reverse=True)
(out/'resolved-stacks.json').write_text(json.dumps(rows,indent=2)+'\n')
summary=[{'phase':k[0],'operation':k[1],'class':k[2],'ns':v} for k,v in sorted(totals.items())]
(out/'class-summary.json').write_text(json.dumps(summary,indent=2)+'\n')
print(json.dumps(summary,indent=2))
for r in rows[:8]:print(r['phase'],r['operation'],r['class'],r['ns']/1e6,'ms','\n'.join(r['symbols'][:6]))
