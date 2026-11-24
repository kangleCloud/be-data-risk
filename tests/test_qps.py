from datetime import datetime, timedelta
import json
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest import TestCase
from unittest.mock import Mock, patch

from fakeredis import FakeRedis

from risk.config import Config, SourceConfig
from risk.parsing import PrivacyPolicy, SHANGHAI
from risk.service import Collector
from risk.storage import CHECKPOINTS, HTTP_QUEUE, QPS_PREFIX, RedisStore, StorageError, qps_expiry
from risk.tailer import SourceError


class QpsTest(TestCase):
    def setUp(self):
        directory = TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.log = Path(directory.name) / 'access.log'
        self.log.touch()
        self.start = datetime.now(SHANGHAI).replace(second=0, microsecond=0)
        self.seconds = 0
        self.minute = int(self.start.timestamp() // 60)
        self.key = QPS_PREFIX + str(self.minute)
        self.client = FakeRedis(decode_responses=True)
        self.addCleanup(self.client.close)
        self.store = RedisStore(self.client)
        self.collector = self.make_collector()
        self.addCleanup(self.collector.close, False)

    def make_collector(self, geo=None):
        config = Config((SourceConfig('nginx', self.log),), PrivacyPolicy(), 65536)
        return Collector(self.store, config, clock=self.now, monotonic=lambda: self.seconds, geo=geo)

    def now(self, seconds=None):
        return (self.start + timedelta(seconds=self.seconds if seconds is None else seconds)).isoformat(timespec='milliseconds')

    def write(self, path, status, seconds):
        with self.log.open('a', encoding='utf-8') as stream:
            stream.write(json.dumps({'time_iso8601': self.now(seconds), 'uri': path, 'status': status,
                                     'request_method': 'GET'}) + '\n')

    def scan(self, seconds):
        self.seconds = seconds
        while self.collector.tick():
            pass

    def test_counts_all_completed_traffic_without_history_or_geo_success(self):
        self.collector.geo = Mock()
        self.collector.geo.resolve_many.side_effect = RuntimeError()
        self.scan(0)
        self.write('/api/test', 403, 1)
        self.write('/assets/site.css', 200, 2)
        self.write('/market/overview', 200, 3)
        self.write('/unknown', 502, 4)
        with self.log.open('a', encoding='utf-8') as stream:
            stream.write('invalid-json\n')
        self.scan(10)
        self.scan(20)
        # Simulate a stalled Java consumer; the historical records remain unread.
        self.assertEqual(self.client.llen(HTTP_QUEUE), 4)
        self.assertEqual(self.client.hgetall(self.key), {'requestCount': '4'})
        self.scan(40)
        self.scan(60)
        self.assertEqual(self.client.hgetall(self.key), {'requestCount': '4', 'ready': '1'})
        self.assertEqual(self.client.expiretime(self.key), qps_expiry(self.minute))
        self.write('/assets/late.css', 304, 59)
        self.scan(61)
        self.scan(71)
        self.assertEqual(self.client.hgetall(self.key), {'requestCount': '5', 'ready': '1'})

    def test_zero_requires_a_full_healthy_minute(self):
        self.scan(1)
        for seconds in (20, 40, 60, 80, 100, 120):
            self.scan(seconds)
        self.assertEqual(self.client.hgetall(self.key), {})
        self.assertEqual(self.client.hgetall(QPS_PREFIX + str(self.minute + 1)), {'ready': '1'})

    def test_live_window_excludes_older_and_future_log_times(self):
        self.write('/api/older', 200, -1200)
        self.write('/api/future', 200, 20)
        self.scan(0)
        self.scan(10)
        self.assertEqual(list(self.client.scan_iter(QPS_PREFIX + '*')), [])

    def test_incomplete_line_blocks_closing_and_reads_completed_line_once(self):
        self.scan(0)
        self.scan(20)
        self.scan(40)
        body = json.dumps({'time_iso8601': self.now(59), 'uri': '/api/test', 'status': 200,
                           'request_method': 'GET'})
        self.log.write_text(body, encoding='utf-8')
        self.scan(60)
        self.assertEqual(self.client.hgetall(self.key), {})
        with self.log.open('a', encoding='utf-8') as stream:
            stream.write('\n')
        self.scan(61)
        self.assertEqual(self.client.hgetall(self.key), {'requestCount': '1', 'ready': '1'})

    def test_read_and_redis_failure_invalidate_coverage(self):
        self.scan(0)
        self.scan(20)
        reader = self.collector.states['nginx'].reader
        with patch.object(reader, 'prepare', side_effect=SourceError), self.assertRaises(SourceError):
            self.scan(30)
        for seconds in (40, 60, 80):
            self.scan(seconds)
        with patch.object(self.store, 'heartbeat', side_effect=StorageError('REDIS_UNAVAILABLE')):
            with self.assertRaises(StorageError):
                self.scan(100)
        self.scan(110)
        self.scan(120)
        self.assertEqual(self.client.hgetall(self.key), {})
        self.assertEqual(self.client.hgetall(QPS_PREFIX + str(self.minute + 1)), {})

    def test_renamed_log_and_restart_keep_exact_counts(self):
        self.scan(0)
        self.write('/api/old', 200, 1)
        self.scan(2)
        self.log.rename(self.log.with_suffix('.log.1'))
        self.log.touch()
        self.write('/assets/new.js', 200, 3)
        self.scan(4)
        self.scan(20)
        self.collector.close()
        self.collector = self.make_collector()
        self.addCleanup(self.collector.close, False)
        for seconds in (21, 40, 60):
            self.scan(seconds)
        self.assertEqual(self.client.hgetall(self.key), {'requestCount': '2'})
        self.assertEqual(self.client.llen(HTTP_QUEUE), 2)

    def test_repeated_checkpoint_does_not_count_or_queue_again(self):
        self.assertEqual(self.store.publish('nginx', None, 'next', ['record'], {self.minute: 2}), (True, False))
        self.assertEqual(self.store.publish('nginx', None, 'next', ['record'], {self.minute: 2}), (True, False))
        self.assertEqual(self.client.hget(self.key, 'requestCount'), '2')
        self.assertEqual(self.client.llen(HTTP_QUEUE), 1)

    def test_restores_missing_checkpoint_without_counting_a_pending_range_twice(self):
        self.store.publish('nginx', None, 'unacknowledged', ['record'], {self.minute: 2})
        self.store.ready_minute(self.minute, {'nginx': 'unacknowledged'})
        self.client.hdel(CHECKPOINTS, 'nginx')
        self.assertEqual(self.store.publish('nginx', 'expected', 'unacknowledged', ['record'], {self.minute: 2}),
                         (True, True))
        self.assertEqual(self.store.checkpoint('nginx'), 'unacknowledged')
        self.assertEqual(self.client.hgetall(self.key), {'requestCount': '2'})
        self.assertEqual(self.client.llen(HTTP_QUEUE), 1)
        self.assertEqual(self.store.publish('nginx', 'unacknowledged', 'next', ['new'], {self.minute: 1}),
                         (True, False))
        self.assertEqual(self.client.hget(self.key, 'requestCount'), '3')
        self.assertEqual(self.client.llen(HTTP_QUEUE), 2)
        with self.assertRaisesRegex(StorageError, 'CHECKPOINT_CONFLICT'):
            self.store.publish('nginx', 'old', 'invalid', [], {})

    def test_checkpoint_loss_before_idle_close_does_not_create_zero(self):
        self.scan(0)
        self.write('/api/test', 200, 1)
        for seconds in (2, 20, 40):
            self.scan(seconds)
        checkpoint = self.store.checkpoint('nginx')
        self.client.delete(CHECKPOINTS, self.key)
        self.scan(60)
        self.assertEqual(self.store.checkpoint('nginx'), checkpoint)
        self.assertEqual(self.client.hgetall(self.key), {})
