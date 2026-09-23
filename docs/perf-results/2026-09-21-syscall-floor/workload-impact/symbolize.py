from pathlib import Path
import argparse,collections,json,re,subprocess
ap=argparse.ArgumentParser();ap.add_argument('raw',type=Path);ap.add_argument('binary',type=Path);a=ap.parse_args()
raw=a.raw.read_text();base=re.search(r'text_base=(0x[0-9a-f]+)',raw).group(1)
assert 'status=ok|root_exited=1|bounded=0|errors=0|saw_sample=1' in raw
expected=int(re.search(r'sample-population\|count=(\d+)',raw).group(1))
stacks=[];frames=[]
for line in raw.split('HVPCARRIERLOW|section=user-stacks',1)[1].splitlines():
 s=line.strip()
 if re.fullmatch(r'0x[0-9a-f]+',s):frames.append(s)
 elif re.fullmatch(r'[0-9]+',s) and frames:stacks.append((frames,int(s)));frames=[]
assert sum(n for fs,n in stacks)==expected
addrs=sorted({a for fs,n in stacks for a in fs});syms={}
for i in range(0,len(addrs),300):
 batch=addrs[i:i+300];out=subprocess.run(['atos','-o',str(a.binary),'-l',base,*batch],capture_output=True,text=True,check=True).stdout.splitlines();assert len(out)==len(batch)
 syms.update(zip(batch,out))
def name(s):return re.sub(r' \(in [^)]+\)(?: \+ \d+)?$','',s)
leaf=collections.Counter();inclusive=collections.Counter();owner=collections.Counter()
for fs,n in stacks:
 symbols=[name(syms[x]) for x in fs];leaf[symbols[0]]+=n
 for s in set(symbols):inclusive[s]+=n
 own=next((s for s in symbols if not s.startswith('0x')),'unresolved');owner[own]+=n
result={'sample_population':expected,'base':base,'stacks':len(stacks),'leaf':leaf.most_common(),'inclusive':inclusive.most_common(),'first_resolved_frame':owner.most_common(),'note':'Inclusive functions overlap; first resolved frame includes unresolved callees and is not exclusive Rust function CPU.'}
a.raw.with_suffix('.symbols.json').write_text(json.dumps(result,indent=2)+'\n')
print(json.dumps({'population':expected,'first_resolved_frame':owner.most_common(18)},indent=2))
