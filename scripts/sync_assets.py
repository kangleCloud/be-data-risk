"""Copy only consumed authoritative assets; never edit their source."""
from pathlib import Path
import hashlib
import json
import shutil

REPO = Path(__file__).resolve().parents[1]
SOURCE = REPO.parent / 'docs'
RUNTIME = REPO / 'risk/assets'
TEST = REPO / 'tests/resources'


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def sync():
    for directory in ('risk-v1', 'geoip-v1'):
        root = SOURCE / directory
        source = json.loads((root / 'sha256.json').read_text())
        if set(source) != {'runtime', 'test'}:
            raise ValueError('INVALID_SOURCE_MANIFEST')
        if directory == 'risk-v1':
            manifest = source
        else:
            # Geo authority is Java-owned. Select only this consumer's actual needs.
            hashes = source['runtime'] | source['test']
            manifest = {'runtime': {name: hashes[name] for name in ('control.schema.json', 'result.schema.json')},
                        'test': {'fixtures.json': hashes['fixtures.json']}}
        for section, output in (('runtime', RUNTIME), ('test', TEST)):
            destination = output / directory
            destination.mkdir(parents=True, exist_ok=True)
            for name, expected in manifest[section].items():
                path = root / name
                if digest(path) != expected:
                    raise ValueError('SOURCE_ASSET_MISMATCH')
                target = destination / name
                target.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(path, target)
            (destination / 'sha256.json').write_text(json.dumps(manifest, indent=2) + '\n')
            # Only generated consumer directories are pruned, never the authority.
            expected_names = {str((destination / name).resolve()) for name in manifest[section]} | {str((destination / 'sha256.json').resolve())}
            for path in destination.iterdir():
                if path.is_file() and str(path.resolve()) not in expected_names:
                    path.unlink()
    print('Runtime/test assets synchronized from workspace docs')


if __name__ == '__main__':
    sync()
