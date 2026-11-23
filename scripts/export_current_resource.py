"""Export an actual latest resource value using fake Redis and synthetic metrics."""
from pathlib import Path
import json
import sys

import fakeredis
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from risk.monitor_config import MonitorTarget
from risk.ownership import CollectorOwnership
from risk.resources import MetricsSnapshot, ResourceScheduler, ResourceStore


def export():
    client = fakeredis.FakeRedis(decode_responses=True)
    try:
        owner = CollectorOwnership(client, 'collector-v2')
        owner.acquire()
        client.hset('risk:monitor:config', mapping={'version': '42'})
        target = MonitorTarget('7', 'LOCAL', True, 'collector-v2', 30, None)
        class Probe:
            def snapshot(self):
                return MetricsSnapshot(cpu_total=100, cpu_idle=40, memory_used=1024, memory_total=2048,
                                       disk_used=4096, disk_total=8192, net_receive=1000, net_transmit=2000,
                                       load1='0.5', uptime_seconds=60, boot_id='synthetic')
        scheduler = ResourceScheduler(ResourceStore(client, owner), 'collector-v2', '42', [target],
                                      clock=lambda: '2026-11-19T10:00:00.000+08:00', local_probe=Probe())
        scheduler.tick()
        key = 'risk:monitor:resource:current:7'
        raw = client.get(key)
        seconds, micros = client.time()
        return {'synthetic': True, 'key': key, 'body': json.loads(raw),
                'redisNowMillis': str(seconds * 1000 + micros // 1000), 'ttlSeconds': client.ttl(key)}
    finally:
        client.close()


if __name__ == '__main__':
    output = Path(sys.argv[1] if len(sys.argv) > 1 else '/tmp/risk-resource-current.json')
    output.write_text(json.dumps(export(), ensure_ascii=False, indent=2) + '\n')
    print(str(output))
