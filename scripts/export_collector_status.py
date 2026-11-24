"""Export an actual monitor status using only fake Redis and synthetic inputs."""
from pathlib import Path
import json
import sys
import tempfile

import fakeredis
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from risk.algorithms import canonical
from risk.config import Config, SourceConfig
from risk.monitor import MonitorRuntime
from risk.monitor_config import CONFIG_KEY, INITIALIZED_FIELD
from risk.redis_keys import key_segment
from risk.parsing import PrivacyPolicy


def export():
    client = fakeredis.FakeRedis(decode_responses=True)
    with tempfile.TemporaryDirectory() as folder:
        path = Path(folder) / 'access.log'
        path.write_text('')
        config = Config((SourceConfig('nginx-v1', path),), PrivacyPolicy(), 65536,
                        collector_id='collector-v2')
        target = {'targetId': '1', 'type': 'LOCAL', 'enabled': True,
                  'collectorId': 'collector-v2', 'intervalSeconds': 30, 'connection': None}
        client.hset(CONFIG_KEY, mapping={INITIALIZED_FIELD: '2026-11-19T10:00:00.000+08:00',
                                        '1': canonical(target).decode()})
        runtime = MonitorRuntime(config, client)
        try:
            runtime.start()
            body = client.hget('risk:heartbeat', 'monitor:' + key_segment(config.collector_id))
            secs, micros = client.time()
            return {'synthetic': True, 'collectorId': config.collector_id,
                    'snapshot': {'body': body, 'nowMillis': secs * 1000 + micros // 1000}}
        finally:
            runtime.close()
            client.close()


if __name__ == '__main__':
    output = Path(sys.argv[1] if len(sys.argv) > 1 else '/tmp/risk-collector-status.json')
    output.write_text(json.dumps(export(), ensure_ascii=False, indent=2) + '\n')
    print(str(output))
