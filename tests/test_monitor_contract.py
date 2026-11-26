import base64
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import fakeredis
from redis.exceptions import ConnectionError
from risk.aggregation import event_records, merge
from risk.config import Config, SourceConfig, load_config
from risk.monitor import MonitorRuntime, _build_plan
from risk.monitor_config import (CONFIG_KEY, INITIALIZED_FIELD, MonitorConfig, MonitorConfigError,
                                 MonitorConfigSync, MonitorTarget, TargetConnection, parse_config)
from risk.parsing import PrivacyPolicy
from risk.protocol import validate_record
from risk.redis_keys import key_segment
from risk.resources import MetricsSnapshot, ResourceScheduler, ResourceStore
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
        target = {'targetId': '1', 'type': 'REMOTE', 'enabled': True, 'collectorId': 'c',
                  'intervalSeconds': 30, 'connection': {'host': 'example.test', 'port': 22,
                  'username': 'monitor', 'passwordCiphertext': self.connection.password_ciphertext}}
        marker = {INITIALIZED_FIELD: '2026-11-19T12:00:00.000+08:00'}
        parsed = parse_config({**marker, '1': json.dumps(target)})
        self.assertEqual(parsed.targets[0].connection.password_ciphertext, self.connection.password_ciphertext)
        self.assertNotIn(self.connection.password_ciphertext, repr(parsed))
        with self.assertRaisesRegex(MonitorConfigError, 'CONFIG_INVALID'):
            parse_config({**marker, '2': json.dumps(target)})
        with self.assertRaisesRegex(MonitorConfigError, 'CONFIG_INVALID'):
            parse_config({**marker, '1': json.dumps({**target, 'enabled': False})})
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / '.env.test'
            path.write_text('SM4_KEY=' + self.key + '\n')
            config = load_config(path)
        self.assertEqual(config.sm4_key, self.key)
        self.assertNotIn(self.key, repr(config))

    def test_local_and_disabled_targets_do_not_decrypt(self):
        local = MonitorTarget('1', 'LOCAL', True, 'c', 30, None)
        disabled = MonitorTarget('2', 'REMOTE', False, 'c', 30, self.connection)
        monitor = MonitorConfig('2026-01-01T00:00:00+08:00', (local, disabled))
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
        scheduler = ResourceScheduler(None, 'c', plan.monitor_targets,
                                      local_probe=probe, remote_probe_factory=runtime._remote_probe,
                                      asynchronous=False)
        with patch('risk.monitor.decrypt_binding', side_effect=AssertionError('local must not decrypt')):
            sample, failure = scheduler.sample_target(local)
        self.assertIsNone(failure)
        self.assertEqual(json.loads(sample.body)['configVersion'], '')
        scheduler.close()

    def test_refresh_compares_targets_and_ignores_initialization_timestamp(self):
        with fakeredis.FakeRedis(decode_responses=True) as client:
            sync = MonitorConfigSync(client)
            target = {'targetId': '1', 'type': 'LOCAL', 'enabled': True,
                      'collectorId': 'c', 'intervalSeconds': 30, 'connection': None}
            now = '2026-11-19T12:00:00.000+08:00'
            client.hset(CONFIG_KEY, mapping={INITIALIZED_FIELD: now, '1': json.dumps(target)})
            self.assertTrue(sync.refresh(force=True))
            self.assertEqual(sync.current.targets[0].interval_seconds, 30)

            now = '2026-11-19T12:01:00.000+08:00'
            client.hset(CONFIG_KEY, INITIALIZED_FIELD, now)
            self.assertFalse(sync.refresh(force=True))

            target['intervalSeconds'] = 60
            client.hset(CONFIG_KEY, '1', json.dumps(target))
            self.assertTrue(sync.refresh(force=True))
            self.assertEqual(sync.current.targets[0].interval_seconds, 60)

            with patch.object(client, 'hgetall', side_effect=ConnectionError):
                self.assertFalse(sync.refresh(force=True))
            self.assertEqual(sync.status.error, 'CONFIG_UNAVAILABLE')
            self.assertEqual(sync.current.targets[0].interval_seconds, 60)

            client.hdel(CONFIG_KEY, INITIALIZED_FIELD)
            self.assertFalse(sync.refresh(force=True))
            self.assertEqual(sync.status.error, 'CONFIG_UNAVAILABLE')
            self.assertEqual(sync.current.targets[0].interval_seconds, 60)

    def test_initialized_hash_with_no_targets_is_applied(self):
        with fakeredis.FakeRedis(decode_responses=True) as client:
            now = '2026-11-19T12:00:00.000+08:00'
            client.hset(CONFIG_KEY, INITIALIZED_FIELD, now)
            runtime = MonitorRuntime(Config((), PrivacyPolicy(), 65536, collector_id='c'), client)
            try:
                runtime.start()
                status = json.loads(client.hget('risk:heartbeat', 'monitor:' + key_segment('c')))
                self.assertEqual(status['configState'], 'APPLIED')
                self.assertEqual(status['appliedConfigVersion'], '')
                self.assertEqual(status['observedConfigVersion'], '')
            finally:
                runtime.close()

    def test_remove_and_readd_one_target_keeps_other_target_scheduled(self):
        with fakeredis.FakeRedis(decode_responses=True) as client:
            clock = [0]
            first = {'targetId': '1', 'type': 'LOCAL', 'enabled': True,
                     'collectorId': 'c', 'intervalSeconds': 30, 'connection': None}
            second = {**first, 'targetId': '2'}
            client.hset(CONFIG_KEY, mapping={INITIALIZED_FIELD: '2026-11-19T12:00:00+08:00',
                                            '1': json.dumps(first), '2': json.dumps(second)})
            runtime = MonitorRuntime(Config((), PrivacyPolicy(), 65536, collector_id='c'), client,
                                     monotonic=lambda: clock[0])
            try:
                runtime.start()
                with patch.object(runtime.resources, 'tick', return_value=False):
                    runtime.resources.next_due['2'] = 42
                    client.hdel(CONFIG_KEY, '1')
                    clock[0] = 5
                    runtime.tick()
                    self.assertEqual(set(runtime.resources.targets), {'2'})
                    self.assertEqual(runtime.resources.next_due, {'2': 42})

                    client.hset(CONFIG_KEY, '1', json.dumps({**first, 'intervalSeconds': 60}))
                    clock[0] = 10
                    runtime.tick()
                    self.assertEqual(runtime.resources.targets['1'].interval_seconds, 60)
                    self.assertEqual(runtime.resources.next_due, {'1': 10, '2': 42})
                status = json.loads(client.hget('risk:heartbeat', 'monitor:' + key_segment('c')))
                self.assertEqual(status['configState'], 'APPLIED')
            finally:
                runtime.close()

    def test_target_change_discards_old_inflight_sample(self):
        with fakeredis.FakeRedis(decode_responses=True) as client:
            original = MonitorTarget('1', 'LOCAL', True, 'c', 30, None)
            edited = MonitorTarget('1', 'LOCAL', True, 'c', 60, None)
            probe = type('Local', (), {'snapshot': lambda self: MetricsSnapshot(memory_used=1, memory_total=2)})()
            scheduler = ResourceScheduler(ResourceStore(client), 'c', [original], local_probe=probe, asynchronous=True)
            key = 'risk:monitor:resource:current:1'
            try:
                scheduler.tick()
                scheduler.update_config([edited])
                scheduler.inflight['1'][1].result(timeout=3)
                scheduler.tick()
                self.assertIsNone(client.get(key))

                # Republishing identical settings leaves this new sample valid.
                scheduler.update_config([MonitorTarget('1', 'LOCAL', True, 'c', 60, None)])
                scheduler.inflight['1'][1].result(timeout=3)
                scheduler.tick()
                self.assertEqual(json.loads(client.get(key))['memoryUsedBytes'], '1')
            finally:
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
                self.assertFalse(runtime.config_applied)
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
