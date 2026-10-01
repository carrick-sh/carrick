import sys,json,statistics
d=sys.argv[1]
t0,t1,rc,*rest=open(d+'/total.txt').read().split()
t0=float(t0)*1000; t1=float(t1)*1000
rows=[]
for l in open(d+'/timeline.txt'):
    s,e,r,name=l.split(None,3)
    rows.append([float(s)*1000,float(e)*1000,name.strip().split('/')[-1].replace('test-worker-message-port','*').replace('.js','')])
rows.sort()
nodes=[json.loads(l) for l in open(d+'/node.jsonl')]
# match each node record to the wrapper row whose [s,e] contains origin, nearest start
def short(f): return f.split('/')[-1].replace('test-worker-message-port','*').replace('.js','')
for n in nodes:
    key=short(n['file']) if n['file'] else None
    cands=[r for r in rows if r[0]<=n['origin']<=r[1] and len(r)==3 and (key is None or r[2]==key)]
    if cands:
        r=min(cands,key=lambda r:n['origin']-r[0]); r.append(n)
first=rows[0][0]; last=max(r[1] for r in rows)
tests=[r for r in rows if r[2].startswith('*')]
probes=[r for r in rows if not r[2].startswith('*')]
print(f"wall {t1-t0:.0f} ms | runner->first spawn {first-t0:.0f} | config probes {probes[0][0]-t0:.0f}..{probes[-1][1]-t0:.0f} | first test spawn {tests[0][0]-t0:.0f} | last exit->runner end {t1-last:.0f}")
ph={k:[] for k in ['exec','boot','js_to_worker','worker_start','worker_life_to_exit','exit_to_reap','life']}
print(f"{'test':42} {'start':>6} {'life':>6} {'exec':>5} {'boot':>5} {'w_new':>6} {'w_up':>5} {'wkrs':>4} {'js_end':>7} {'reap':>5}")
for r in tests:
    s,e,name=r[:3]; n=r[3] if len(r)>3 else None
    if not n:
        print(f"{name:42} {s-t0:6.0f} {e-s:6.0f}  (no node record)"); continue
    o=n['origin']; ex=o-s; boot=n['bootstrap']; jsend=n['exit']; reap=e-(o+jsend)
    news=[t for k,t in n['events'] if k=='new']; ups=[t for k,t in n['events'] if k=='online']
    wnew=news[0]-boot if news else float('nan'); wup=(ups[0]-news[0]) if ups and news else float('nan')
    print(f"{name:42} {s-t0:6.0f} {e-s:6.0f} {ex:5.0f} {boot:5.0f} {wnew:6.0f} {wup:5.0f} {len(news):4} {jsend:7.0f} {reap:5.0f}")
    ph['exec'].append(ex); ph['boot'].append(boot); ph['exit_to_reap'].append(reap); ph['life'].append(e-s)
    if ups and news: ph['worker_start'].append(wup)
for k,v in ph.items():
    if v: print(f"median {k}: {statistics.median(v):.1f} ms (n={len(v)}, sum {sum(v):.0f})")
print(open(d+'/micro.txt').read().strip())
