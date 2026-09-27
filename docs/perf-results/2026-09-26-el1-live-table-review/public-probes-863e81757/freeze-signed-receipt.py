import hashlib
import json
import shutil
import sys
from pathlib import Path

receipt = Path(sys.argv[1])
destination = Path(sys.argv[2])
raw = receipt.read_bytes()
rows = [json.loads(line) for line in raw.splitlines()]
headers = [row for row in rows if row['record_type'] == 'header']
assert len(headers) == 1, 'expected one header'
executables = {row['executable_id']: row for row in rows if row['record_type'] == 'executable'}
executions = [row for row in rows if row['record_type'] == 'execution']
assert executions and all(row['terminal_status'] == 'passed' and row['executable_id'] in executables for row in executions), 'incomplete execution records'
assert any(row['record_type'] == 'cleanup' and row['remaining_processes'] == 0 for row in rows), 'missing clean completion'

def digest(path):
    with path.open('rb') as source:
        return hashlib.file_digest(source, 'sha256').hexdigest()

# Validate the entire population before creating an archive. This cannot recover
# an earlier signature if another signing stage already replaced it.
for row in executables.values():
    assert digest(Path(row['canonical_path'])) == row['sha256'], 'source artifact changed: ' + row['canonical_path']
destination.mkdir(parents=True, exist_ok=False)
manifest = []
for row in executables.values():
    source = Path(row['canonical_path'])
    frozen = destination / (row['sha256'] + '-' + source.name)
    shutil.copy2(source, frozen)
    assert digest(frozen) == row['sha256'], 'copy digest mismatch'
    assert digest(source) == row['sha256'], 'source changed during capture'
    manifest.append(dict(row, frozen_path=str(frozen.resolve())))
(destination / 'signed-receipt.jsonl').write_bytes(raw)
(destination / 'frozen-artifacts.json').write_text(json.dumps({'header': headers[0], 'receipt_sha256': hashlib.sha256(raw).hexdigest(), 'artifacts': manifest}, indent=2)+'\n')
print(json.dumps({'frozen_executables': len(manifest), 'executions': len(executions), 'destination': str(destination)}))
