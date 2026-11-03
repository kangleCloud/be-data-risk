"""Hash-checked copies of authoritative test assets, absent from the runtime package."""
import hashlib
import json
from pathlib import Path
from risk.protocol import asset as runtime_asset

ROOT = Path(__file__).with_name('resources')


def asset(name):
    path = ROOT / name
    return path.read_text(encoding='utf-8') if path.is_file() else runtime_asset(name)


def verify_test_assets():
    for directory in ('risk-v1', 'geoip-v1'):
        manifest = json.loads((ROOT / directory / 'sha256.json').read_text())
        for name, expected in manifest['test'].items():
            if hashlib.sha256((ROOT / directory / name).read_bytes()).hexdigest() != expected:
                raise ValueError('TEST_ASSET_MISMATCH')


verify_test_assets()
