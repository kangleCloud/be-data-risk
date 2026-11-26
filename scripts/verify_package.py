"""Verify wheel assets and current golden records from an isolated directory."""
from pathlib import Path
import subprocess
import sys
import tempfile
import zipfile

wheel=Path(sys.argv[1]).resolve()
repo=Path(__file__).resolve().parents[1]
examples=(repo/'examples/risk-monitor.samples.json').resolve()
with tempfile.TemporaryDirectory() as folder:
    root=Path(folder)
    with zipfile.ZipFile(wheel) as archive:
        names=archive.namelist()
        assert not any(n.startswith(('tests/','docs/','tools/','scripts/')) for n in names)
        expected={'risk/assets/'+str(p.relative_to(repo/'risk/assets')) for p in (repo/'risk/assets').rglob('*') if p.is_file()}
        assert {n for n in names if n.startswith('risk/assets/') and not n.endswith('/')}==expected
        assert not any('fixture' in n or n.endswith('.md') for n in names if n.startswith('risk/assets/'))
        archive.extractall(root)
    for path in (repo/'risk/assets').rglob('*'):
        if path.is_file():assert path.read_bytes()==(root/'risk/assets'/path.relative_to(repo/'risk/assets')).read_bytes()
    sample=root/'sample.jsonl'
    sample.write_text('{"@timestamp":"2026-11-03T12:00:00+08:00","uri":"/api/test","status":"200"}\n')
    code='''import sys,json
from pathlib import Path
sys.path.insert(0,sys.argv[1])
from risk.protocol import verify_assets,validate_record
from risk.parsing import PrivacyPolicy
from risk.resources import validate_sample
verify_assets()
fixture=json.loads(Path(sys.argv[3]).read_text())
validate_sample(fixture['resourceSample'])
record=fixture['accessRecord']
assert record.pop('sourceId')
validate_record(record)
assert PrivacyPolicy().path('/api/token/private')==('/api/token/{redacted}','API')
from risk.__main__ import main
sys.argv=['risk','--check-file',sys.argv[2]]
assert main()==0
'''
    result=subprocess.run([sys.executable,'-I','-c',code,str(root),str(sample),str(examples)],cwd=root,text=True,capture_output=True,check=True)
    assert result.stdout.strip()
    print('Runtime-only wheel; isolated schemas, external current records and entry point: PASS')
