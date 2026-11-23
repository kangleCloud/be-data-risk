"""Export an actual fenced monitor status using only fake Redis and synthetic inputs."""
from pathlib import Path
import json
import sys
import tempfile

import fakeredis
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from risk.algorithms import canonical
from risk.config import Config, SourceConfig
from risk.monitor import MonitorRuntime
from risk.parsing import PrivacyPolicy


def export():
    client = fakeredis.FakeRedis(decode_responses=True)
    with tempfile.TemporaryDirectory() as folder:
        path = Path(folder) / 'access.log'
        path.write_text('')
        config = Config((SourceConfig('nginx-v1', path),), PrivacyPolicy(), 65536,
                        collector_id='collector-v2')
        payload = {'schemaVersion': 2, 'configVersion': '42',
                   'generatedAt': '2026-11-19T10:00:00.000+08:00',
                   'targets': [{'targetId': '1', 'type': 'LOCAL', 'enabled': True,
                                'collectorId': 'collector-v2', 'intervalSeconds': 30,
                                'connection': None}]}
        client.hset('risk:monitor:config', mapping={'version': '42', 'payload': canonical(payload).decode(),
                                                   'publishedAt': payload['generatedAt']})
        runtime = MonitorRuntime(config, client, lease_wait=0)
        try:
            runtime.start()
            owner = runtime.ownership
            body = client.hget('risk:heartbeat', 'monitor:' + owner.segment)
            secs, micros = client.time()
            snapshot = {'body': body, 'epoch': client.hget('risk:heartbeat', owner.epoch_field),
                        'leaseActive': bool(client.exists(owner.key)),
                        'nowMillis': secs * 1000 + micros // 1000}
            return {'synthetic': True, 'collectorId': owner.collector_id, 'snapshot': snapshot}
        finally:
            runtime.close()
            client.close()


if __name__ == '__main__':
    output = Path(sys.argv[1] if len(sys.argv) > 1 else '/tmp/risk-collector-status.json')
    output.write_text(json.dumps(export(), ensure_ascii=False, indent=2) + '\n')
    print(str(output))
