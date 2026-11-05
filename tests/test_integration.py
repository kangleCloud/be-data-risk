from test_assets import asset
"""Immutable V1 Collector with real shared Lua executed by fakeredis/Lupa."""
from dataclasses import replace
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import fakeredis
from redis.exceptions import ConnectionError, TimeoutError
from risk.aggregation import merge
from risk.algorithms import canonical
from risk.config import Config, SourceConfig
from risk.parsing import PathRule, PrivacyPolicy
from risk.protocol import validate_envelope, verify_assets
from risk.service import Collector
from risk.storage import PREFIX, RedisStore, StorageError
from risk.tailer import restore_checkpoint

NOW = '2026-10-28T12:00:00.000+08:00'


def log(day='2026-10-28', **updates):
    value = {'@timestamp': day + 'T11:00:01+08:00', 'uri': '/api/sample?token=secret',
             'status': '200', 'request_method': 'GET', 'request_time': '0.0010015',
             'body_bytes_sent': '123', 'remote_addr': '10.0.0.1'}
    value.update(updates)
    return json.dumps(value).encode() + b'\n'


class CollectorTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = Path(self.tmp.name) / 'access.log'
        self.path.write_bytes(b'')
        self.client = fakeredis.FakeRedis(decode_responses=True)
        self.addCleanup(self.client.close)
        self.store = RedisStore(self.client)
        self.source = SourceConfig('source_test', self.path)
        self.policy = PrivacyPolicy([PathRule('/api/sample', '/api/sample'), PathRule('/market/dashboard/stream', '/market/dashboard/stream')], direct_peer_trusted=True)
        self.config = Config((self.source,), self.policy, 65536)
        self.time = 0.0
        self.collector = self.new_collector()

    def new_collector(self):
        collector = Collector(self.store, self.config, clock=lambda: NOW, monotonic=lambda: self.time)
        collector.stage_limit = 1 # individual cursor tests; batching covered separately
        self.addCleanup(lambda: collector.close(flush=False))
        return collector

    def batches(self):
        result = []
        for day in sorted(self.client.smembers(PREFIX + 'days')):
            for batch in sorted(self.client.smembers(PREFIX + 'pending:' + day)):
                encoded = self.client.get(PREFIX + 'batch:' + day + ':' + batch)
                envelope = json.loads(encoded)
                validate_envelope(envelope, encoded)
                result.append(envelope)
        return result

    def count(self):
        return sum(int(row['requestCount']) for env in self.batches() for row in env['records'])

    def drain(self, collector=None):
        collector = collector or self.collector
        while collector.tick():
            pass

    def test_memory_cursor_is_not_durable_checkpoint(self):
        self.path.write_bytes(log())
        self.collector.tick()
        state = self.collector.states[self.source.alias]
        self.assertEqual(state.reader.checkpoint.offset, len(log()))
        self.assertIsNone(self.store.checkpoint(self.source.alias))
        self.assertEqual(self.batches(), [])
        self.collector.flush_all()
        self.assertEqual(restore_checkpoint(self.store.checkpoint(self.source.alias)).offset, len(log()))
        self.assertEqual(self.count(), 1)

    def test_ten_second_flush_and_lease_renew(self):
        self.path.write_bytes(log())
        with patch.object(self.store, 'lease', wraps=self.store.lease) as lease:
            self.collector.tick()
            self.time = 9.999
            self.assertFalse(self.collector.tick())
            self.assertEqual(self.batches(), [])
            lease.assert_not_called()
            self.time = 10.0
            self.collector.tick()
            self.assertEqual(self.count(), 1)
            lease.assert_called_once_with('RENEW', self.source.alias, self.collector.states[self.source.alias].token)

    def test_idle_wait_never_sleeps_past_buffer_deadline(self):
        self.path.write_bytes(log())
        self.collector.config=replace(self.config,poll_millis=10000)
        self.collector.tick()
        self.time=3
        self.assertEqual(self.collector.wait_seconds(),7)
        self.time=10
        self.assertEqual(self.collector.wait_seconds(),0)
        self.collector.tick()
        self.assertEqual(self.count(),1)

    def test_same_dimensions_merge_before_publish(self):
        self.path.write_bytes(log() * 3)
        self.drain()
        self.collector.flush_all()
        self.assertEqual(len(self.batches()), 1)
        rows = self.batches()[0]['records']
        counter = next(row for row in rows)
        self.assertEqual(counter['requestCount'], '3')

    def test_late_second_batch_never_mutates_first(self):
        self.path.write_bytes(log('2026-10-27'))
        self.drain(); self.collector.flush_all()
        first = self.batches()[0]
        key = PREFIX + 'batch:' + first['businessDate'] + ':' + first['batchId']
        original = self.client.get(key)
        with self.path.open('ab') as stream:
            stream.write(log('2026-10-27'))
        self.drain(); self.collector.flush_all()
        self.assertEqual(self.client.get(key), original)
        self.assertEqual(len(self.batches()), 2)
        self.assertEqual(self.count(), 2)
        self.assertEqual(len({batch['batchId'] for batch in self.batches()}), 2)

    def test_mixed_dates_commit_previous_segment_before_read_cursor_crosses(self):
        lines = [log('2026-10-27'), log('2026-10-28'), log('2026-10-27')]
        self.path.write_bytes(b''.join(lines))
        self.collector.tick()
        self.assertIsNone(self.store.checkpoint(self.source.alias))
        self.collector.tick()
        self.assertEqual(restore_checkpoint(self.store.checkpoint(self.source.alias)).offset, len(lines[0]))
        self.collector.tick()
        self.assertEqual(restore_checkpoint(self.store.checkpoint(self.source.alias)).offset, len(lines[0]) + len(lines[1]))
        self.collector.flush_all()
        self.assertEqual(self.count(), 3)
        self.assertEqual(len(self.batches()), 3)

    def test_crash_unpublished_buffer_replays(self):
        self.path.write_bytes(log() * 2)
        self.drain()
        self.collector.close(flush=False)
        self.assertIsNone(self.store.checkpoint(self.source.alias))
        restarted = self.new_collector()
        self.drain(restarted); restarted.flush_all()
        self.assertEqual(self.count(), 2)

    def test_restart_published_data_no_duplicate(self):
        self.path.write_bytes(log())
        self.drain(); self.collector.close()
        restarted = self.new_collector()
        self.assertFalse(restarted.tick())
        restarted.flush_all()
        self.assertEqual(self.count(), 1)

    def test_shutdown_flushes_remaining_buffer(self):
        self.path.write_bytes(log())
        self.collector.tick()
        self.collector.close()
        self.assertEqual(self.count(), 1)
        self.assertIsNone(self.client.get(PREFIX + 'lease:' + self.source.alias))

    def test_failed_close_does_not_advance_durable_checkpoint(self):
        self.path.write_bytes(log())
        self.collector.tick()
        with patch.object(self.store, 'publish', side_effect=StorageError('REDIS_UNAVAILABLE')):
            with self.assertRaises(StorageError):
                self.collector.close()
        self.assertIsNone(self.store.checkpoint(self.source.alias))
        self.assertEqual(self.batches(), [])

    def test_redis_failure_retains_exact_publication(self):
        self.path.write_bytes(log())
        self.collector.tick()
        original = self.store.publish_script
        self.store.publish_script = lambda **_: (_ for _ in ()).throw(ConnectionError('secret'))
        with self.assertRaises(StorageError): self.collector.flush_all()
        state = self.collector.states[self.source.alias]
        frozen = state.publication
        self.assertIsNone(self.store.checkpoint(self.source.alias))
        self.store.publish_script = original
        self.collector.tick()
        self.assertEqual(self.batches()[0]['batchId'], frozen.batch_id)
        self.assertEqual(canonical(self.batches()[0]).decode(), frozen.envelope)
        self.assertEqual(self.count(), 1)

    def test_lost_result_recovers_same_id_without_recount(self):
        self.path.write_bytes(log())
        self.collector.tick()
        original = self.store.publish_script
        def lose(**kwargs):
            self.assertEqual(original(**kwargs), 'OK')
            raise TimeoutError('private transport')
        self.store.publish_script = lose
        with self.assertRaises(StorageError): self.collector.flush_all()
        first = self.batches()[0]
        self.store.publish_script = original
        self.collector.tick()
        self.assertEqual(self.count(), 1)
        self.assertEqual(len(self.batches()), 1)
        self.assertEqual(self.batches()[0], first)

    def test_lost_result_after_java_cleanup_does_not_recreate_batch(self):
        self.path.write_bytes(log())
        self.collector.tick()
        original = self.store.publish_script
        def clean_then_lose(**kwargs):
            self.assertEqual(original(**kwargs), 'OK')
            batch = self.batches()[0]
            pipe = self.client.pipeline()
            pipe.delete(PREFIX + 'batch:' + batch['businessDate'] + ':' + batch['batchId'])
            pipe.srem(PREFIX + 'pending:' + batch['businessDate'], batch['batchId'])
            pipe.execute()
            raise TimeoutError()
        self.store.publish_script = clean_then_lose
        with self.assertRaises(StorageError): self.collector.flush_all()
        self.store.publish_script = original
        self.collector.tick()
        self.assertEqual(self.batches(), [])
        self.assertIsNotNone(self.store.checkpoint(self.source.alias))
        self.assertEqual(self.client.smembers(PREFIX + 'days'), {'2026-10-28'})

    def test_lost_result_then_restart_no_duplicate(self):
        self.path.write_bytes(log())
        self.collector.tick()
        original = self.store.publish_script
        def lose(**kwargs):
            original(**kwargs); raise TimeoutError()
        self.store.publish_script = lose
        with self.assertRaises(StorageError): self.collector.flush_all()
        self.store.publish_script = original
        self.collector.close(flush=False)
        restarted = self.new_collector()
        self.assertFalse(restarted.tick())
        self.assertEqual(self.count(), 1)

    def test_same_source_lease_prevents_double_read(self):
        self.path.write_bytes(log())
        self.collector.tick()
        with self.assertRaises(StorageError) as caught: self.new_collector().tick()
        self.assertEqual(caught.exception.code, 'LEASE_LOST')

    def test_lease_lost_discards_only_volatile_buffer(self):
        self.path.write_bytes(log())
        self.collector.tick()
        self.client.delete(PREFIX + 'lease:' + self.source.alias)
        other = self.new_collector()
        other.tick(); other.flush_all()
        self.time = 10
        with self.assertRaises(StorageError): self.collector.tick()
        self.assertNotIn(self.source.alias, self.collector.states)
        self.assertEqual(self.count(), 1)

    def test_checkpoint_conflict_stops_source_without_new_batch(self):
        self.path.write_bytes(log())
        self.collector.tick()
        state = self.collector.states[self.source.alias]
        self.client.hset(PREFIX + 'checkpoints', self.source.alias, '{"generation":"other","offset":"99"}')
        with self.assertRaises(StorageError) as caught: self.collector.flush_all()
        self.assertEqual(caught.exception.code, 'CHECKPOINT_CONFLICT')
        self.assertNotIn(self.source.alias, self.collector.states)
        self.assertEqual(self.batches(), [])


    def test_half_line_restart_keeps_start_offset(self):
        self.path.write_bytes(log()[:-2])
        self.assertFalse(self.collector.tick())
        self.collector.close(flush=False)
        with self.path.open('ab') as stream: stream.write(log()[-2:])
        other = self.new_collector(); self.drain(other); other.flush_all()
        self.assertEqual(self.count(), 1)

    def test_rotation_flushes_old_segment_and_publishes_empty_transition(self):
        self.path.write_bytes(log())
        self.collector.tick()
        self.path.rename(self.path.with_suffix('.1'))
        self.path.write_bytes(log())
        self.collector.tick()
        self.assertEqual(self.count(), 1)
        self.assertEqual(len(self.batches()), 2)
        self.assertEqual(sorted(len(env['records']) for env in self.batches()), [0, 1])
        self.collector.tick(); self.collector.flush_all()
        self.assertEqual(self.count(), 2)

    def test_restart_finds_renamed_inode_before_switch(self):
        self.path.write_bytes(log() * 2)
        self.collector.tick(); self.collector.close()
        self.path.rename(self.path.with_suffix('.1'))
        self.path.write_bytes(log())
        other = self.new_collector(); self.drain(other); other.flush_all()
        self.assertEqual(self.count(), 3)

    def test_truncate_changes_generation_quality_only_transition(self):
        self.path.write_bytes(log() + b' ' * 400 + b'\n')
        self.drain(); self.collector.flush_all()
        before = restore_checkpoint(self.store.checkpoint(self.source.alias))
        self.path.write_bytes(log())
        self.collector.tick()
        after = restore_checkpoint(self.store.checkpoint(self.source.alias))
        self.assertNotEqual(before.generation, after.generation)
        self.drain(); self.collector.flush_all()
        self.assertEqual(self.count(), 2)
        self.assertTrue(any(not env['records'] for env in self.batches()))

    def test_bad_json_fixed_reason_aggregation_and_privacy(self):
        self.path.write_bytes(b'{"password":"secret","bad":"\\x"}\n' * 3)
        diagnostics = []; self.collector.diagnostic = diagnostics.append
        self.drain(); self.collector.flush_all()
        env = self.batches()[0]
        self.assertEqual(env['records'], [])
        self.assertEqual(diagnostics[0]['count'], '3')
        self.assertEqual(diagnostics[0]['offset'], '0')
        self.assertNotIn('secret', json.dumps(env) + json.dumps(diagnostics))

    def test_privacy_and_sse_upstream_statuses_unchanged(self):
        self.path.write_bytes(log(uri='/market/dashboard/stream', request_time='60', status='200', upstream_status='502, 504', authorization='secret-token'))
        self.drain(); self.collector.flush_all()
        env = self.batches()[0]
        self.assertEqual(env['records'], [])
        self.assertNotIn('secret-token', canonical(env).decode())

    def test_idle_heartbeat_without_checkpoint_or_index(self):
        self.assertFalse(self.collector.tick())
        self.assertEqual(self.client.hget(PREFIX + 'heartbeat', 'collectorHeartbeatAt'), NOW)
        self.assertIsNone(self.client.hget(PREFIX + 'heartbeat', 'lastEventTime'))
        self.assertIsNone(self.store.checkpoint(self.source.alias))
        self.assertFalse(self.client.exists(PREFIX + 'days'))

    def test_publication_updates_last_event_atomically(self):
        self.path.write_bytes(log())
        self.collector.tick()
        self.assertIsNone(self.client.hget(PREFIX + 'heartbeat', 'lastEventTime'))
        self.collector.flush_all()
        self.assertEqual(self.client.hget(PREFIX + 'heartbeat', 'lastEventTime'), '2026-10-28T11:00:01.000+08:00')

    def test_only_lease_has_ttl_and_no_obsolete_keys_created(self):
        self.path.write_bytes(log())
        self.drain(); self.collector.flush_all()
        for key in self.client.keys(PREFIX + '*'):
            if ':lease:' in key: self.assertGreater(self.client.pttl(key), 0)
            else: self.assertEqual(self.client.ttl(key), -1)
        for suffix in ['revision', 'active', 'directory']:
            self.assertFalse(self.client.exists(PREFIX + suffix))
        self.assertTrue(all(key.startswith(PREFIX) for key in self.client.keys('*')))

    def test_single_line_exceeding_capacity_stops_before_ack(self):
        self.path.write_bytes(log())
        with patch('risk.service.MAX_BYTES', 1):
            with self.assertRaises(StorageError) as caught: self.collector.tick()
        self.assertEqual(caught.exception.code, 'RECORD_TOO_LARGE')
        self.assertEqual(len(self.collector.states[self.source.alias].staged), 1)
        self.assertIsNone(self.store.checkpoint(self.source.alias))

    def test_500_distinct_records_flush_before_adding_next(self):
        self.collector.close(flush=False)
        self.policy.direct_peer_trusted = False
        self.policy.rules = [( __import__('re').compile('/'+str(index)), '/'+str(index)) for index in range(501)]
        lines = [log(uri='/api/'+str(index)) for index in range(501)]
        self.path.write_bytes(b''.join(lines))
        with patch('time.time', return_value=1000):
            other = self.new_collector()
            self.drain(other); other.flush_all()
        envs = self.batches()
        self.assertEqual(len(envs), 2)
        self.assertEqual(sorted(len(env['records']) for env in envs), [1, 500])
        self.assertEqual(self.count(), 501)


    def test_other_source_has_independent_batch_and_no_global_retry(self):
        self.path.write_bytes(log())
        self.collector.tick()
        second_path = self.path.with_name('second.log'); second_path.write_bytes(log())
        config = replace(self.config, sources=(SourceConfig('second_source', second_path),))
        other = Collector(self.store, config, clock=lambda: NOW)
        try:
            other.tick(); other.flush_all(); self.collector.flush_all()
            self.assertEqual(self.count(), 2)
            self.assertEqual(len(self.batches()), 2)
        finally: other.close(flush=False)
