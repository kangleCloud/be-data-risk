import contextlib
import copy
import io
import json
from pathlib import Path
import signal
import tempfile
import unittest
from unittest.mock import patch

import fakeredis
from risk.__main__ import main
from risk.algorithms import canonical
from risk.config import load_config
from risk.protocol import asset
from risk.service import run
from risk.storage import PREFIX, RedisStore

NOW = '2026-10-28T12:00:00.000+08:00'


class LuaPreflightTest(unittest.TestCase):
    def setUp(self):
        self.client = fakeredis.FakeRedis(decode_responses=True)
        self.addCleanup(self.client.close)
        self.store = RedisStore(self.client)
        self.store.acquire('source', 'immutable-test-token')
        self.envelope = json.loads(asset('risk-v1-batches.json'))['batches'][0]
        batch, day = self.envelope['batchId'], self.envelope['businessDate']
        self.keys = [PREFIX+'days', PREFIX+'pending:'+day, PREFIX+'batch:'+day+':'+batch,
                     PREFIX+'checkpoints', PREFIX+'day-key-ids', PREFIX+'lease:source', PREFIX+'heartbeat']
        self.args = [batch, day, 'source', 'immutable-test-token', '',
                     '{"generation":"safe","offset":"10"}', canonical(self.envelope).decode(), self.envelope['createdAt'], '']

    def snapshot(self):
        return {key:self.client.dump(key) for key in self.client.keys('*')}

    def reject_without_writes(self, expected):
        before = self.snapshot()
        self.assertEqual(self.store.publish_script(keys=self.keys,args=self.args),expected)
        self.assertEqual(self.snapshot(),before)

    def changed_envelope(self):
        self.args[6] = canonical(self.envelope).decode()

    def test_wrong_last_key_type(self):
        self.client.set(PREFIX+'heartbeat','wrong-type')
        self.reject_without_writes('WRONG_TYPE')

    def test_foreign_key(self):
        self.keys[0]='market:other'
        self.reject_without_writes('INVALID_ARGUMENT')

    def test_later_record_invalid_no_first_write(self):
        self.envelope['records'][-1]['dimensions']['businessDate']='2026-10-25'
        self.changed_envelope(); self.reject_without_writes('INVALID_ARGUMENT')

    def test_record_count_mismatch(self):
        self.envelope['recordCount']='99'
        self.changed_envelope(); self.reject_without_writes('INVALID_ARGUMENT')

    def test_records_order_invalid(self):
        self.envelope['records'].reverse()
        self.changed_envelope(); self.reject_without_writes('INVALID_ARGUMENT')

    def test_duplicate_record(self):
        self.envelope['records'].append(self.envelope['records'][-1])
        self.envelope['recordCount']=str(len(self.envelope['records']))
        self.changed_envelope(); self.reject_without_writes('INVALID_ARGUMENT')

    def test_source_key_id_mismatch(self):
        next(row for row in self.envelope['records'] if row['kind']=='SOURCE')['keyId']='other'
        self.changed_envelope(); self.reject_without_writes('INVALID_ARGUMENT')

    def test_extra_envelope_field(self):
        self.envelope['unsafe']='value'
        self.changed_envelope(); self.reject_without_writes('INVALID_ARGUMENT')

    def test_empty_object_is_not_records_array(self):
        self.envelope['records']={}
        self.envelope['recordCount']='0'
        self.changed_envelope(); self.reject_without_writes('INVALID_ARGUMENT')

    def test_more_than_500_records(self):
        self.envelope['records']=self.envelope['records']*101
        self.envelope['recordCount']=str(len(self.envelope['records']))
        self.changed_envelope(); self.reject_without_writes('INVALID_ARGUMENT')

    def test_more_than_one_mib(self):
        self.args[6]=' '*1048577
        self.reject_without_writes('INVALID_ARGUMENT')

    def test_checkpoint_leading_zero(self):
        self.args[5]='{"generation":"safe","offset":"01"}'
        self.reject_without_writes('INVALID_ARGUMENT')

    def test_checkpoint_extra_private_field(self):
        self.args[5]='{"generation":"safe","offset":"10","path":"private"}'
        self.reject_without_writes('INVALID_ARGUMENT')

    def test_unchanged_checkpoint_not_a_new_segment(self):
        self.args[4]=self.args[5]
        self.reject_without_writes('INVALID_ARGUMENT')

    def test_checkpoint_backwards(self):
        self.args[4]='{"generation":"safe","offset":"99"}'
        self.client.hset(PREFIX+'checkpoints','source',self.args[4])
        self.reject_without_writes('CHECKPOINT_CONFLICT')

    def test_checkpoint_conflict(self):
        self.client.hset(PREFIX+'checkpoints','source','{"generation":"other","offset":"1"}')
        self.reject_without_writes('CHECKPOINT_CONFLICT')

    def test_lease_lost(self):
        self.args[3]='other-token'
        self.reject_without_writes('LEASE_LOST')

    def test_day_key_conflict(self):
        self.client.hset(PREFIX+'day-key-ids',self.args[1],'other')
        self.reject_without_writes('KEY_ID_CONFLICT')

    def test_existing_batch_never_overwritten(self):
        self.client.set(self.keys[2],'existing-immutable-payload')
        self.reject_without_writes('BATCH_CONFLICT')

    def test_repeat_exact_segment_idempotent(self):
        self.assertEqual(self.store.publish_script(keys=self.keys,args=self.args),'OK')
        before=self.snapshot()
        self.assertEqual(self.store.publish_script(keys=self.keys,args=self.args),'ALREADY_COMMITTED')
        self.assertEqual(self.snapshot(),before)

    def test_foreign_token_cannot_release_or_renew(self):
        for operation in ['RENEW','RELEASE']:
            result=self.store.lease_script(keys=[PREFIX+'lease:source'],args=[operation,'source','foreign','30000'])
            self.assertEqual(result,'LEASE_LOST')
            self.assertEqual(self.client.get(PREFIX+'lease:source'),'immutable-test-token')

    def test_monotonic_heartbeat(self):
        self.store.heartbeat(NOW,'2026-10-28T11:00:00.000+08:00')
        self.store.heartbeat('2026-10-28T10:00:00.000+08:00','2026-10-28T09:00:00.000+08:00')
        self.assertEqual(self.client.hget(PREFIX+'heartbeat','collectorHeartbeatAt'),NOW)


class RuntimeTest(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root=Path(self.tmp.name)
        self.log=self.root/'test.log'
        self.log.write_text('{"@timestamp":"2026-10-28T12:00:00+08:00","uri":"/sample","status":200}\n')
        self.path=self.root/'config.local.json'
        self.path.write_text(json.dumps({'redisUrl':'redis://fake-only.invalid:1/0','sources':[{'alias':'sample','path':str(self.log)}]}))
        self.client=fakeredis.FakeRedis(decode_responses=True)
        self.addCleanup(self.client.close)

    def test_once_flushes_and_releases(self):
        with patch('redis.Redis.from_url',return_value=self.client): run(load_config(self.path),once=True)
        self.assertIsNotNone(self.client.hget(PREFIX+'checkpoints','sample'))
        self.assertIsNone(self.client.get(PREFIX+'lease:sample'))
        self.assertEqual(self.client.hget(PREFIX+'heartbeat','lastEventTime'),NOW)
        self.assertEqual(self.client.scard(PREFIX+'pending:2026-10-28'),1)

    def test_main_entry_no_version_or_mode_switch(self):
        with patch('redis.Redis.from_url',return_value=self.client),patch('sys.argv',['risk','--config',str(self.path),'--once']):
            self.assertEqual(main(),0)
        self.assertFalse(self.client.exists(PREFIX+'revision'))

    def test_config_failure_no_private_value(self):
        self.path.write_text('{"password":"secret-value"}')
        output=io.StringIO()
        with patch('sys.argv',['risk','--config',str(self.path),'--once']),contextlib.redirect_stderr(output):
            self.assertEqual(main(),1)
        self.assertEqual(output.getvalue(),'{"code":"COLLECTOR_STOPPED"}\n')

    def test_migration_required_is_fixed_diagnostic(self):
        self.client.hset(PREFIX+'directory','old','2026-10-28')
        output=io.StringIO()
        with patch('redis.Redis.from_url',return_value=self.client),patch('sys.argv',['risk','--config',str(self.path),'--once']),contextlib.redirect_stderr(output):
            self.assertEqual(main(),1)
        self.assertIn('MIGRATION_REQUIRED',output.getvalue())
        self.assertFalse(self.client.exists(PREFIX+'days'))
        self.assertFalse(self.client.exists(PREFIX+'lease:sample'))

    def test_short_key_fails_before_connection(self):
        key=self.root/'local.key';key.write_bytes(b'short')
        value=json.loads(self.path.read_text());value['hmacKeyFile']=str(key)
        self.path.write_text(json.dumps(value))
        with patch('redis.Redis.from_url') as factory,self.assertRaises(ValueError): run(load_config(self.path),once=True)
        factory.assert_not_called()

    def test_sigterm_flushes_buffer_and_restores_handler(self):
        previous=signal.getsignal(signal.SIGTERM)
        original=RedisStore.heartbeat
        def stop(store,now,event=''):
            original(store,now,event)
            signal.getsignal(signal.SIGTERM)(signal.SIGTERM,None)
        with patch('redis.Redis.from_url',return_value=self.client),patch.object(RedisStore,'heartbeat',stop): run(load_config(self.path))
        self.assertEqual(signal.getsignal(signal.SIGTERM),previous)
        self.assertIsNone(self.client.get(PREFIX+'lease:sample'))
        self.assertIsNotNone(self.client.hget(PREFIX+'checkpoints','sample'))

    def test_missing_optional_geo_unknown_no_external_query(self):
        value=json.loads(self.path.read_text());value['geoDatabase']=str(self.root/'absent.mmdb')
        self.path.write_text(json.dumps(value))
        output=io.StringIO()
        with patch('redis.Redis.from_url',return_value=self.client),contextlib.redirect_stderr(output): run(load_config(self.path),once=True)
        self.assertIn('GEO_UNAVAILABLE',output.getvalue())
        self.assertNotIn('absent.mmdb',output.getvalue())
class SourceAvailabilityTest(unittest.TestCase):
    def setUp(self):
        from risk.config import Config, SourceConfig
        from risk.parsing import PrivacyPolicy
        from risk.service import Collector
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = Path(self.tmp.name) / 'sample.log'
        self.path.write_bytes(b'')
        self.source = SourceConfig('sample', self.path)
        client = fakeredis.FakeRedis(decode_responses=True)
        self.addCleanup(client.close)
        self.client = client
        self.collector = Collector(RedisStore(client), Config((self.source,), PrivacyPolicy(), 65536), clock=lambda: NOW)
        self.addCleanup(self.collector.close)

    def test_first_open_denied_does_not_heartbeat(self):
        from risk.tailer import SourceError
        with patch('risk.tailer.os.open', side_effect=PermissionError('private-path')):
            with self.assertRaises(SourceError) as caught:
                self.collector.tick()
        self.assertEqual(str(caught.exception), 'SOURCE_UNAVAILABLE')
        self.assertEqual(self.client.hgetall(PREFIX + 'heartbeat'), {})
        self.assertIsNone(self.client.hget(PREFIX + 'checkpoints', 'sample'))

    def test_disappears_between_is_file_and_open(self):
        from risk.tailer import SourceError
        with patch('risk.tailer.os.open', side_effect=FileNotFoundError('private-path')):
            with self.assertRaises(SourceError):
                self.collector.tick()
        self.assertEqual(self.client.hgetall(PREFIX + 'heartbeat'), {})

    def test_running_path_missing_stops_heartbeat(self):
        from risk.tailer import SourceError
        self.collector.tick()
        before = self.client.hgetall(PREFIX + 'heartbeat')
        self.path.unlink()
        self.collector.clock = lambda: '2026-10-27T12:01:00.000+08:00'
        self.collector.last_heartbeat = None
        with self.assertRaises(SourceError):
            self.collector.tick()
        self.assertEqual(self.client.hgetall(PREFIX + 'heartbeat'), before)

    def test_rotated_new_target_permission_denied_stops_heartbeat(self):
        from risk.tailer import SourceError
        self.collector.tick()
        before = self.client.hgetall(PREFIX + 'heartbeat')
        self.path.rename(self.path.with_suffix('.1'))
        self.path.write_bytes(b'')
        self.collector.last_heartbeat = None
        with patch('risk.tailer.os.open', side_effect=PermissionError('secret-path')):
            with self.assertRaises(SourceError):
                self.collector.tick()
        self.assertEqual(self.client.hgetall(PREFIX + 'heartbeat'), before)
        self.assertIsNone(self.client.hget(PREFIX + 'checkpoints', 'sample'))

    def test_normal_readable_eof_can_heartbeat(self):
        self.assertFalse(self.collector.tick())
        self.assertEqual(self.client.hget(PREFIX + 'heartbeat', 'collectorHeartbeatAt'), NOW)
