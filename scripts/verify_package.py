"""Validate a built wheel outside the checkout, with no parent docs present."""
from pathlib import Path
import subprocess
import sys
import tempfile
import zipfile

wheel = Path(sys.argv[1]) if len(sys.argv) > 1 else max(Path('dist').glob('*.whl'), key=lambda path: path.stat().st_mtime)
with tempfile.TemporaryDirectory() as folder:
    root = Path(folder)
    with zipfile.ZipFile(wheel) as archive:
        archive.extractall(root)
    source = Path('risk/assets')
    for path in source.rglob('*'):
        if path.is_file():
            assert path.read_bytes() == (root / 'risk/assets' / path.relative_to(source)).read_bytes()
    sample = root / 'sample.jsonl'
    sample.write_text('{"@timestamp":"2026-10-27T12:00:00+08:00","status":"200"}\n')
    code = '''import sys
sys.path.insert(0, sys.argv[1])
from risk.protocol import verify_assets, asset
verify_assets()
from risk.algorithms import checksum
from risk.protocol import validate_envelope, validate_record
from risk.paths import protect_path
import json
fixture=json.loads(asset('risk-v1-fixtures.json'))
assert checksum([fixture['record']])==fixture['checksum']
batches=json.loads(asset('risk-v1-batches.json'))
for envelope, encoded in zip(batches['batches'], batches['canonicalEnvelopes']):
    validate_envelope(envelope, encoded)
paths=json.loads(asset('risk-v1/path-fixtures.json'))
for case in paths['cases']:
    data, expected=case['input'],case['expected']
    validate_record(expected['record'])
    assert checksum([expected['record']])==expected['checksum']
from risk.__main__ import main
sys.argv=['risk', '--check-file', sys.argv[2]]
assert main()==0
'''
    result = subprocess.run([sys.executable, '-I', '-c', code, str(root), str(sample)],
                            cwd=root, text=True, capture_output=True, check=True)
    assert result.stdout.strip()
    print('Standalone wheel asset/fixture/entry point check: PASS')
