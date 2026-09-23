from pathlib import Path
import subprocess,hashlib,json
root=Path.cwd();p=root/'crates/carrick-conformance-next/tests/fixtures/pristine_scrub.py'
image='localhost:5050/cpython-test@sha256:3126629643b4adcf57ba5cecdb7f9ed257e733b56cd81da70fd5fdbdc1745b30'
rid='floor-discard-boundary-oracle'
args=['docker','run','--rm','--name',rid,'--platform','linux/arm64','--entrypoint','/usr/local/bin/python3',image,'-c',p.read_text()]
r=subprocess.run(args,capture_output=True,timeout=30)
base=root/'target/lease-cost/discard-boundary-oracle'
base.with_suffix('.out').write_bytes(r.stdout);base.with_suffix('.err').write_bytes(r.stderr)
base.with_suffix('.json').write_text(json.dumps({'argv':args,'source_sha256':hashlib.sha256(p.read_bytes()).hexdigest(),'returncode':r.returncode},indent=2))
assert r.returncode==0,(r.returncode,r.stderr)
print(r.stdout.decode())
