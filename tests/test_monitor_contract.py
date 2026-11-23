import base64
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import fakeredis
from risk.aggregation import event_records, merge
from risk.config import Config, SourceConfig, load_config
from risk.monitor import MonitorRuntime, _build_plan
from risk.monitor_config import MonitorConfig, MonitorTarget, TargetConnection, parse_config
from risk.parsing import PrivacyPolicy
from risk.protocol import validate_record
from risk.resources import MetricsSnapshot, ResourceScheduler
from risk.service import Collector
from risk.ssh import SshBindingError, decrypt_binding
from risk.storage import HTTP_QUEUE, RedisStore


class MonitorContractTest(unittest.TestCase):
    def setUp(self):
        self.key = base64.b64encode(bytes(16)).decode()
        self.connection = TargetConnection('example.test', 22, 'monitor', 'D1bwnWAseX03lwevPGd14Q==')

    def test_password_decrypt_and_invalid_input(self):
        binding = decrypt_binding(self.connection, self.key)
        self.assertEqual(binding.password, 'risk-example')
        self.assertNotIn(binding.password, repr(binding))
        malformed = TargetConnection('example.test', 22, 'monitor', base64.b64encode(b'invalid').decode())
        for connection, key in ((malformed, self.key), (self.connection, None), (self.connection, base64.b64encode(bytes(range(16))).decode())):
            with self.subTest(connection=connection), self.assertRaisesRegex(SshBindingError, 'SSH_BINDING_UNAVAILABLE'):
                decrypt_binding(connection, key)

    def test_java_bouncy_castle_sm4_ecb_vector(self):
        # Synthetic vector from Java Bouncy Castle using a zero-filled test key.
        connection = TargetConnection('example.test', 22, 'monitor', 'D1bwnWAseX03lwevPGd14Q==')
        self.assertEqual(decrypt_binding(connection, 'AAAAAAAAAAAAAAAAAAAAAA==').password, 'risk-example')

    def test_current_remote_configuration_and_local_key(self):
        payload = {'schemaVersion': 2, 'configVersion': '1', 'generatedTime': '2026-11-19T12:00:00.000+08:00',
                   'targets': [{'targetId': '1', 'type': 'REMOTE', 'enabled': True, 'collectorId': 'c',
                                'intervalSeconds': 30, 'connection': {'host': 'example.test', 'port': 22,
                                'username': 'monitor', 'passwordCiphertext': self.connection.password_ciphertext}},
                               {'targetId': '2', 'type': 'REMOTE', 'enabled': False, 'collectorId': 'c',
                                'intervalSeconds': 30, 'connection': {'host': 'example.test', 'port': 22,
                                'username': 'monitor', 'passwordCiphertext': None}}]}
        parsed = parse_config({'version': '1', 'payload': json.dumps(payload), 'publishedTime': payload['generatedTime']})
        self.assertEqual(parsed.targets[0].connection.password_ciphertext, self.connection.password_ciphertext)
        self.assertNotIn(self.connection.password_ciphertext, repr(parsed))
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / '.env.test'
            path.write_text('SM4_KEY=' + self.key + '\n')
            config = load_config(path)
        self.assertEqual(config.sm4_key, self.key)
        self.assertNotIn(self.key, repr(config))

    def test_local_and_disabled_targets_do_not_decrypt(self):
        local = MonitorTarget('1', 'LOCAL', True, 'c', 30, None)
        disabled = MonitorTarget('2', 'REMOTE', False, 'c', 30, self.connection)
        monitor = MonitorConfig('1', '{}', '2026-01-01T00:00:00+08:00', (local, disabled))
        with tempfile.TemporaryDirectory() as directory:
            source = SourceConfig('nginx_access', Path(directory) / 'access.log')
            config = Config((source,), PrivacyPolicy(), 65536, collector_id='c')
            plan = _build_plan(config, monitor)
        self.assertEqual(plan.sources, (source,))
        self.assertEqual(plan.monitor_targets, (local,))
        runtime = object.__new__(MonitorRuntime)
        runtime.config = config
        runtime.runner = None
        probe = type('Local', (), {'snapshot': lambda self: MetricsSnapshot()})()
        scheduler = ResourceScheduler(None, 'c', '1', plan.monitor_targets,
                                      local_probe=probe, remote_probe_factory=runtime._remote_probe,
                                      asynchronous=False)
        with patch('risk.monitor.decrypt_binding', side_effect=AssertionError('local must not decrypt')):
            sample, failure = scheduler.sample_target(local)
        self.assertIsNone(failure)
        scheduler.close()

    def test_logs_start_without_monitor_configuration(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'access.log'
            event = {'@timestamp': '2026-11-19T12:00:01.000+08:00', 'uri': '/api/test',
                     'remote_addr': '8.8.8.8', 'status': '200', 'request_method': 'GET'}
            path.write_text(json.dumps(event) + '\n', encoding='utf-8')
            config = Config((SourceConfig('nginx_access', path),), PrivacyPolicy(direct_peer_trusted=True),
                            65536, collector_id='collector')
            client = fakeredis.FakeRedis(decode_responses=True)
            runtime = MonitorRuntime(config, client, clock=lambda: '2026-11-19T12:00:02.000+08:00')
            try:
                runtime.start()
                runtime.tick()
                self.assertEqual(runtime.applied_sources, ('nginx_access',))
                self.assertIsNone(runtime.applied_version)
                runtime.close()
                self.assertEqual(client.llen(HTTP_QUEUE), 1)
            finally:
                runtime.close()
                client.close()

    def test_minutes_group_without_monitor_target(self):
        event = {'event_time': '2026-11-19T12:00:01.000+08:00', 'request_type': 'API',
                 'method': 'GET', 'path_template': '/api/test', 'source_ip': '8.8.8.8',
                 'status': 200, 'region_code': 'UNKNOWN', 'geo': {}}
        row = event_records(event)[0]
        self.assertEqual(row['minuteTime'], '2026-11-19T12:00:00.000+08:00')
        self.assertNotIn('targetId', row)
        self.assertEqual(merge(row, event_records(event)[0])['requestCount'], '2')

    def test_actual_collector_publication_uses_source(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'access.log'
            event = {'@timestamp': '2026-11-19T12:00:01.000+08:00', 'uri': '/api/test?token=secret',
                     'remote_addr': '8.8.8.8', 'status': '200', 'request_method': 'GET'}
            path.write_text(json.dumps(event) + '\n', encoding='utf-8')
            config = Config((SourceConfig('nginx_access', path),), PrivacyPolicy(direct_peer_trusted=True), 65536)
            client = fakeredis.FakeRedis(decode_responses=True)
            collector = Collector(RedisStore(client), config,
                                  clock=lambda: '2026-11-19T12:00:02.000+08:00')
            try:
                while collector.tick():
                    pass
                collector.close()
                self.assertEqual(client.llen(HTTP_QUEUE), 1)
                raw = client.lpop(HTTP_QUEUE)
                row = json.loads(raw)
                self.assertEqual(row.pop('sourceId'), 'nginx_access')
                validate_record(row)
                self.assertNotIn('targetId', row)
                self.assertNotIn('secret', raw)
                restarted = Collector(RedisStore(client), config, clock=collector.clock)
                while restarted.tick():
                    pass
                restarted.close()
                self.assertEqual(client.llen(HTTP_QUEUE), 0)
                self.assertIsNotNone(client.hget('risk:checkpoints', 'nginx_access'))
            finally:
                collector.close(flush=False)
                client.close()


if __name__ == '__main__':
    unittest.main()
