from pathlib import Path
import json,hashlib,tarfile,difflib,subprocess,datetime,shutil,io
root=Path.cwd(); out=root/'target/lease-cost/native-activation-cache'; reports=root/'docs/perf-results/2026-09-21-syscall-floor'; report=reports/'native-activation-cache';report.mkdir(exist_ok=True)
sha=lambda p:hashlib.sha256(Path(p).read_bytes()).hexdigest()
measured_source=json.loads((out/'measured-source-hashes.json').read_text());assert all(sha(p)==h for p,h in measured_source.items())
source={**measured_source, **{p:sha(p) for p in ['crates/carrick-conformance-contract/tests/claims.rs','conformance-contracts/inventory.json']}}
parents={}
for folder,key in [('native-carrier','dirty_source_sha256'),('native-scope','source_sha256'),('native-activation','source_sha256')]:
 d=json.loads((reports/folder/'manifest.json').read_text());parents.update(d[key])
changes={p:{'before':h,'after':sha(p) if Path(p).is_file() else None} for p,h in parents.items() if not Path(p).is_file() or sha(p)!=h}
unexpected={p:h for p,h in changes.items() if p not in source};assert not unexpected,unexpected
before={}
with tarfile.open(out/'before.tar.gz') as t:
 for member in t.getmembers():before[member.name]=t.extractfile(member).read()
with tarfile.open(reports/'native-carrier/dirty-source.tar.gz') as t:before['Cargo.lock']=t.extractfile('dirty-source/Cargo.lock').read()
assert hashlib.sha256(before['Cargo.lock']).hexdigest()==parents['Cargo.lock']
before['crates/carrick-conformance-contract/tests/claims.rs']=(out/'before-claims.rs').read_bytes()
before['conformance-contracts/inventory.json']=(out/'before-inventory.json').read_bytes()
assert hashlib.sha256(before['crates/carrick-conformance-contract/tests/claims.rs']).hexdigest()==parents['crates/carrick-conformance-contract/tests/claims.rs']
with tarfile.open(out/'before-complete.tar.gz','w:gz') as t:
 for name,data in before.items():
  info=tarfile.TarInfo(name);info.size=len(data);t.addfile(info,io.BytesIO(data))
patch=''.join(''.join(difflib.unified_diff(before.get(p,b'').decode().splitlines(True),Path(p).read_text().splitlines(True),fromfile='a/'+p if p in before else '/dev/null',tofile='b/'+p)) for p in sorted(source))
(out/'implementation.patch').write_text(patch)
with tarfile.open(out/'final-source.tar.gz','w:gz') as tar:
 for p in source:tar.add(p,arcname=p)
controls={}
for p,expected in {'target/release/carrick':'c3fb9fd30706f6f657531084df5a072f7c130b68096e60a9bb22df4213ac50b0','target/lease-cost/inotify-transport-control/carrick-control':'c3fb9fd30706f6f657531084df5a072f7c130b68096e60a9bb22df4213ac50b0','target/release/native-syscall-slice':'2440ad8f103e016dd6d859cec061a6065cb9708dd55e6559dbb182d28433ea65','target/lease-cost/native-memory/native-guarded-executor':'2440ad8f103e016dd6d859cec061a6065cb9708dd55e6559dbb182d28433ea65'}.items():
 assert sha(p)==expected,p;controls[p]=expected
(out/'preservation.json').write_text(json.dumps({'parent_source_count':len(parents),'unchanged':len(parents)-len(changes),'changed':changes,'unexpected':unexpected,'controls':controls},indent=2))
# Logs/scripts and small source archives travel with the report. Large binaries
# remain immutable under target; their exact hashes are recorded separately.
for p in out.rglob('*'):
 if p.is_file() and p.suffix in ['.json','.jsonl','.log','.err','.py','.txt','.patch','.sha256','.gz','.rs','.out'] and not p.name.startswith('processes-'):
  dest=report/p.relative_to(out);dest.parent.mkdir(parents=True,exist_ok=True);shutil.copy2(p,dest)
manifest={'created_utc':datetime.datetime.now(datetime.timezone.utc).isoformat(),'worktree':str(root),'source_head':subprocess.check_output(['git','rev-parse','HEAD'],text=True).strip(),'local_uncommitted':True,'parent_checkpoint':'../native-activation/manifest.json','source_sha256':source,'source_revision':'sha256:'+hashlib.sha256(json.dumps(source,sort_keys=True).encode()).hexdigest(),'measured_source_revision':json.loads((out/'cost-identity.json').read_text())['source_revision'],'files_changed':list(source),'parent_preservation':json.loads((out/'preservation.json').read_text()),'contract':'kernel.mm.native-data-activation','parent_contract':'kernel.execution.native-synchronous-syscall','native_execution_binding':False,'new_workload_speedup_claim':False,'cost_summary_ns':json.loads((out/'cost-summary.json').read_text()),'diagnostic_binaries':{p.name:sha(p) for p in out.iterdir() if p.is_file() and p.name in ['red-runtime','native-activation-cache-metrics-debug','native-activation-cache-cost-release','native-elf-default-debug']},'verification_initial':json.loads((out/'verification.json').read_text()),'validation_final':json.loads((out/'validation-final.json').read_text()),'evidence_sha256':{str(p.relative_to(report)):sha(p) for p in report.rglob('*') if p.is_file() and p.name not in ['manifest.json','README.md']}}
(report/'manifest.json').write_text(json.dumps(manifest,indent=2));print('archived',len(source),'source files; preserved',len(parents)-len(changes),'of',len(parents),'parent files; intentional changes',list(changes))
