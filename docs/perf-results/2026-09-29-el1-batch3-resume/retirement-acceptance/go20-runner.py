import subprocess,pathlib,json,hashlib,os,sys
base=pathlib.Path('target/el1-resume-b3/retirement-acceptance')
base.mkdir(exist_ok=True)
cli=pathlib.Path('target/release/carrick')
sha=hashlib.file_digest(cli.open('rb'),'sha256').hexdigest()
assert sha != '9d266e3aa63562d92764f6e3659f6be85e86aeb65691a862717ea1ed26c1b18a', 'old failing CLI must not be accepted as new build'
status=[]
for i in range(1,21):
    output=base/f'go-round{i}.jsonl'
    assert not output.exists(), 'never overwrite an acceptance population'
    args=['target/debug/carrick-conformance','--suite','go-build','--oracle-cache','target/el1-resume-b3/arm64-acceptance/workload-oracle.jsonl','--require-cached-oracle','--force','--carrick-serial-confirm-budget-s','0','--flake-retries','0','--jsonl',str(output)]
    env=os.environ.copy();env['CARRICK_RUN_ID']=f'el1-retire-go-{os.getpid()}-{i:02d}'
    with (base/f'go-round{i}.log').open('w') as log:
        rc=subprocess.run(args,env=env,stdout=log,stderr=subprocess.STDOUT).returncode
    status.append({'round':i,'exit':rc,'args':args,'cli_sha256':sha})
    (base/'go-status.json').write_text(json.dumps(status,indent=2)+'\n')
    print(f'round {i}: exit {rc}',flush=True)
    assert hashlib.file_digest(cli.open('rb'),'sha256').hexdigest()==sha,'CLI changed during acceptance'
sys.exit(1 if any(r['exit'] for r in status) else 0)
