"""Verify a runtime-only wheel outside checkout, with explicit external test resources."""
from pathlib import Path
import subprocess
import sys
import tempfile
import zipfile

wheel = Path(sys.argv[1]) if len(sys.argv) > 1 else max(Path('dist').glob('*.whl'), key=lambda p:p.stat().st_mtime)
resources = Path('tests/resources').resolve()
with tempfile.TemporaryDirectory() as folder:
    root = Path(folder)
    with zipfile.ZipFile(wheel) as archive:
        names = archive.namelist()
        assert 'risk/migrate.py' not in names
        assert not any(n.startswith(('tests/', 'docs/', 'tools/')) for n in names)
        expected = {'risk/assets/' + str(p.relative_to('risk/assets')) for p in Path('risk/assets').rglob('*') if p.is_file()}
        assert {n for n in names if n.startswith('risk/assets/') and not n.endswith('/')} == expected
        assert not any('fixture' in n or n.endswith('.md') for n in names if n.startswith('risk/assets/'))
        archive.extractall(root)
    for p in Path('risk/assets').rglob('*'):
        if p.is_file():assert p.read_bytes() == (root/'risk/assets'/p.relative_to('risk/assets')).read_bytes()
    sample=root/'sample.jsonl'
    sample.write_text('{"@timestamp":"2026-11-02T12:00:00+08:00","status":"200"}\n')
    code='''import sys,json,hashlib
from pathlib import Path
sys.path.insert(0,sys.argv[1])
from risk.protocol import verify_assets,asset,validate_record,validate_envelope
from risk.algorithms import checksum
from risk.parsing import PrivacyPolicy,PathRule
verify_assets()
resources=Path(sys.argv[3])
def test_asset(name):return json.loads((resources/name).read_text())
for directory in ('risk-v1','geoip-v1'):
    manifest=test_asset(directory+'/sha256.json')
    for name,expected in manifest['test'].items():
        assert hashlib.sha256((resources/directory/name).read_bytes()).hexdigest()==expected
fixture=test_asset('risk-v1-fixtures.json')
validate_record(fixture['record'])
assert checksum([fixture['record']])==fixture['checksum']
for name in ('risk-v1-batches.json','risk-v1/geo-fixtures.json'):
    data=test_asset(name)
    for envelope,encoded in zip(data['batches'],data['canonicalEnvelopes']):validate_envelope(envelope,encoded)
for case in test_asset('risk-v1/path-fixtures.json')['cases']:
    value,expected=case['input'],case['expected']
    policy=PrivacyPolicy([PathRule(r['pattern'],r['template']) for r in value['pathRules']])
    key=value['keyUtf8'].encode() if value['keyUtf8'] else None
    assert policy.protected_path(value['uri'],value['businessDate'],key).template==expected['pathTemplate']
    validate_record(expected['record'])
    assert checksum([expected['record']])==expected['checksum']
for case in test_asset('risk-v1/geo-boundary-fixtures.json')['cases']:
    try:validate_record(case['record']);accepted=True
    except ValueError:accepted=False
    assert accepted==case['valid']
from risk.__main__ import main
sys.argv=['risk','--check-file',sys.argv[2]]
assert main()==0
'''
    result=subprocess.run([sys.executable,'-I','-c',code,str(root),str(sample),str(resources)],cwd=root,text=True,capture_output=True,check=True)
    assert result.stdout.strip()
    print('Runtime-only wheel, external golden fixtures, isolated entry point: PASS')
