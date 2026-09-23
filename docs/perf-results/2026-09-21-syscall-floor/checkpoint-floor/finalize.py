from pathlib import Path
import hashlib,json,shutil,subprocess
root=Path.cwd();out=root/'target/lease-cost/checkpoint-floor';dest=root/'docs/perf-results/2026-09-21-syscall-floor/checkpoint-floor'
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
revision=lambda d:'sha256:'+hashlib.sha256(json.dumps(d,sort_keys=True,separators=(',',':')).encode()).hexdigest()
final=json.loads((out/'final-source-hashes.json').read_text());measured=json.loads((out/'tested-source-hashes.json').read_text());red=json.loads((out/'red-source-hashes.json').read_text())
assert all(sha(root/p)==h for p,h in final.items())
frozen=json.loads((out/'frozen-hashes.json').read_text());assert all(sha(root/p)==h for p,h in frozen.items())
assert len(json.loads((out/'matrix-runs.json').read_text()))==40
paired=json.loads((out/'paired-runs.json').read_text());assert len(paired)==36
oracle=root/'target/lease-cost/native-slice/runs-checkpoint-floor-docker.json';linux=json.loads(oracle.read_text());assert len(linux)==18
for row in paired:
 match=[r for r in linux if r['phase']==row['phase'] and r['n']==row['scale']]
 assert match and all(r['elf_sha256']==row['elf_sha256'] for r in match)
assert all(r['exit_code']==0 for r in json.loads((out/'final-checks.json').read_text()))
assert len(json.loads((out/'cleanup.json').read_text()))==76
for label,expected in [('red',[1,8,32,128]),('green',[0,0,0,0])]:
 obs=json.loads((out/(label+'-bound-observations.json')).read_text())
 assert [r['work']['values']['native_data_activations'] for r in obs]==expected
 assert all(all(a['passed'] for a in r['semantic_assertions']) for r in obs)
binaries=['baseline-runtime','red-runtime','release-runtime','attribution-runtime','host-compute-short','host-compute-floor']
for file in out.iterdir():
 if file.is_file() and file.name not in binaries:shutil.copy2(file,dest/file.name)
shutil.copy2(oracle,dest/oracle.name)
for row in linux:
 for suffix in ['.out','.err','.cleanup']:
  file=root/'target/lease-cost/native-slice'/(row['run_id']+suffix);assert file.exists();shutil.copy2(file,dest/file.name)
manifest=dict(
 schema_version=1,source_head=subprocess.run(['git','-c','core.fsmonitor=false','rev-parse','HEAD'],capture_output=True,text=True,check=True).stdout.strip(),
 source_revision=revision(final),source_sha256=final,
 measured_source_revision=revision(measured),measured_source_sha256=measured,
 measured_to_final_changes=[p for p in measured if measured[p]!=final[p]],
 measured_to_final_note='Only the runtime diagnostic gains a resource-capture arm. Native implementation, guest fixtures, policy and timing runner code are unchanged. Additional final inputs include standalone host-control and registry metadata.',
 red_source_revision=revision(red),red_source_sha256=red,
 parent_manifest='../current-read-reuse/manifest.json',
 binaries=[dict(path=str((out/name).relative_to(root)),sha256=sha(out/name)) for name in binaries],
 frozen_artifacts=frozen,
 control=dict(knob='CARRICK_NATIVE_DATA_DEMAND=0/1',read_window_reuse=True,small_invocations=40,paired_invocations=36,linux_invocations=18,samples_per_invocation=10,discarded_warmup_samples=1,ordering='Alternating arm order by case and repetition',cpu_pinned=False,traced_timing=False,private_code_publication=True,mock_stage2=True,product_acceptance=False),
 linux_image='localhost:5050/ltp@sha256:bc75ded40c5827f2ec9e1891edc23b988beae3f428f5be2c8fd7e3ee52fee80b',
 summary=json.loads((out/'summary.json').read_text()),
 validation=dict(carrier_memory_tests=41,research_executor_tests=12,observability_tests=83,contract_package_tests=33,ignored_runtime_diagnostics=3,scoped_research_cleanup=76),
 uncompleted=['Signed native execution and carrier code publication','Full inotify09 on native path','Node Go Python workload differentials','Full CI and product probe smoke full promotion','Prior checkpoint signed fresh_sparse_publication_avoids_stage1_maintenance failure remains unresolved'],
 evidence=[dict(path=p.name,sha256=sha(p)) for p in sorted(dest.iterdir()) if p.is_file() and p.name!='manifest.json'],
)
(dest/'manifest.json').write_text(json.dumps(manifest,indent=2)+'\n')
# Independently verify copied receipts and preserved artifacts after writing.
assert all(sha(dest/r['path'])==r['sha256'] for r in manifest['evidence'])
assert all(sha(root/r['path'])==r['sha256'] for r in manifest['binaries'])
print(json.dumps(dict(evidence_files=len(manifest['evidence']),source_inputs=len(final),source_revision=manifest['source_revision'],measured_revision=manifest['measured_source_revision'],binaries=len(binaries),all_verified=True)))
