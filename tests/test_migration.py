import contextlib
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import hashlib

import fakeredis
from redis.exceptions import TimeoutError
from risk.algorithms import canonical
from risk.config import Config, SourceConfig
from risk.migrate import checkpoint_value, guard_startup, legacy_plan, main, migrate
from risk.parsing import PrivacyPolicy,PathRule
from risk.protocol import asset
from risk.service import Collector
from risk.storage import RedisStore,StorageError
from risk.tailer import Checkpoint,FileTailer,checkpoint_json,generation


class MigrationTest(unittest.TestCase):
    def setUp(self):
        self.client=fakeredis.FakeRedis(decode_responses=True)
        self.addCleanup(self.client.close)
        self.encoded=checkpoint_json(Checkpoint(generation(1,2),1,2,99))
        self.client.hset('risk:v1:checkpoints','legacy_source',self.encoded)
        self.client.hset('risk:v1:active','2026-10-27:keyId','old-key')

    def snapshot(self): return {key:self.client.dump(key) for key in self.client.keys('*')}

    def test_default_dry_run_no_writes(self):
        before=self.snapshot();result=migrate(self.client)
        self.assertEqual(result,{'mode':'DRY_RUN','checkpointCount':'1','dayKeyIdCount':'1'})
        self.assertEqual(self.snapshot(),before)

    def test_execute_migrates_only_key_id_not_checkpoint(self):
        before=self.client.dump('risk:v1:checkpoints')
        self.assertEqual(migrate(self.client,True)['mode'],'EXECUTED')
        self.assertEqual(self.client.dump('risk:v1:checkpoints'),before)
        self.assertEqual(self.client.hget('risk:v1:day-key-ids','2026-10-27'),'old-key')
        self.assertEqual(self.client.hget('risk:v1:active','2026-10-27:keyId'),'old-key')
        guard_startup(self.client)

    def test_execute_idempotent(self):
        migrate(self.client,True);before=self.snapshot();migrate(self.client,True)
        self.assertEqual(self.snapshot(),before)

    def test_unmigrated_key_id_blocks_startup(self):
        with self.assertRaises(StorageError) as caught: guard_startup(self.client)
        self.assertEqual(caught.exception.code,'MIGRATION_REQUIRED')

    def test_old_pending_directory_blocks(self):
        self.client.hset('risk:v1:directory','old','2026-10-27')
        for action in [lambda:guard_startup(self.client),lambda:migrate(self.client,True)]:
            with self.assertRaises(StorageError) as caught:action()
            self.assertEqual(caught.exception.code,'MIGRATION_REQUIRED')

    def test_old_active_batch_blocks(self):
        self.client.hset('risk:v1:active','2026-10-27','old-batch')
        with self.assertRaises(StorageError):migrate(self.client)

    def test_orphan_old_batch_blocks(self):
        self.client.hset('risk:v1:batch:old:records','record','value')
        with self.assertRaises(StorageError):guard_startup(self.client)

    def test_old_lease_blocks_startup(self):
        self.client.set('risk:v1:lease:legacy_source','old-random-uuid',px=30000)
        with self.assertRaises(StorageError):guard_startup(self.client)

    def test_migration_requires_all_current_collectors_stopped(self):
        self.client.set('risk:v1:lease:source','immutable-current',px=30000)
        with self.assertRaises(StorageError):migrate(self.client,True)

    def test_conflicting_target_not_overwritten(self):
        self.client.hset('risk:v1:day-key-ids','2026-10-27','different')
        before=self.snapshot()
        with self.assertRaises(StorageError) as caught:migrate(self.client,True)
        self.assertEqual(caught.exception.code,'MIGRATION_CONFLICT')
        self.assertEqual(self.snapshot(),before)

    def test_invalid_checkpoint_refused_never_reset(self):
        self.client.hset('risk:v1:checkpoints','legacy_source','{"generation":"safe","offset":"01"}')
        before=self.snapshot()
        with self.assertRaises(StorageError):migrate(self.client,True)
        self.assertEqual(self.snapshot(),before)

    def test_changed_source_between_plan_and_script_rejected_atomically(self):
        plan=legacy_plan(self.client)
        self.client.hset('risk:v1:checkpoints','legacy_source',self.encoded.replace('99','100'))
        result=self.client.register_script(asset('risk-v1/migrate.lua'))(
            keys=['risk:v1:checkpoints','risk:v1:active','risk:v1:directory','risk:v1:day-key-ids'],args=[canonical(plan).decode()])
        self.assertEqual(result,'MIGRATION_SOURCE_CHANGED')
        self.assertFalse(self.client.exists('risk:v1:day-key-ids'))

    def test_response_lost_repeat_safe(self):
        original=self.client.register_script
        def register(script):
            real=original(script)
            def lose(**kwargs):
                real(**kwargs);raise TimeoutError('private')
            return lose
        with patch.object(self.client,'register_script',register):
            with self.assertRaises(StorageError):migrate(self.client,True)
        before=self.client.dump('risk:v1:checkpoints')
        migrate(self.client,True)
        self.assertEqual(self.client.dump('risk:v1:checkpoints'),before)
        guard_startup(self.client)

    def test_wrong_destination_type_no_source_mutation(self):
        self.client.set('risk:v1:day-key-ids','bad-type')
        before=self.snapshot()
        with self.assertRaises(StorageError):migrate(self.client,True)
        self.assertEqual(self.snapshot(),before)

    def test_resume_existing_checkpoint_reads_only_unconsumed_line(self):
        self.client.delete('risk:v1:active','risk:v1:checkpoints')
        key=b'migration-synthetic-only-key-32-bytes'
        key_id=hashlib.sha256(key).hexdigest()[:32]
        with tempfile.TemporaryDirectory() as folder:
            path=Path(folder)/'source.log'
            line=b'{"@timestamp":"2026-10-27T12:00:00+08:00","uri":"/api/example","status":200}\n'
            path.write_bytes(line*2)
            tailer=FileTailer(path);tailer.acknowledge(tailer.prepare());encoded=checkpoint_json(tailer.checkpoint);tailer.close()
            self.client.hset('risk:v1:checkpoints','legacy_source',encoded)
            self.client.hset('risk:v1:active','2026-10-27:keyId',key_id)
            migrate(self.client,True)
            config=Config((SourceConfig('legacy_source',path),),PrivacyPolicy([PathRule('/api/example','/api/example','API')]),65536)
            collector=Collector(RedisStore(self.client),config,key,clock=lambda:'2026-10-28T12:00:00.000+08:00')
            try:
                while collector.tick():pass
                collector.flush_all()
                batch=self.client.smembers('risk:v1:pending:2026-10-27').pop()
                envelope=json.loads(self.client.get('risk:v1:batch:2026-10-27:'+batch))
                self.assertEqual(sum(int(row['requestCount']) for row in envelope['records'] if row['kind']=='COUNTER'),1)
                self.assertEqual(checkpoint_value(self.client.hget('risk:v1:checkpoints','legacy_source'))['offset'],str(len(line)*2))
            finally:collector.close(flush=False)

    def test_cli_dry_run_then_explicit_execute(self):
        with tempfile.TemporaryDirectory() as folder:
            path=Path(folder)/'config.local.json';path.write_text('{"redisUrl":"redis://fake-only.invalid:1/0"}')
            output=io.StringIO()
            with patch('redis.Redis.from_url',return_value=self.client),patch('sys.argv',['migrate','--config',str(path)]),contextlib.redirect_stdout(output):
                self.assertEqual(main(),0)
            self.assertEqual(json.loads(output.getvalue())['mode'],'DRY_RUN')
            self.assertFalse(self.client.exists('risk:v1:day-key-ids'))
            with patch('redis.Redis.from_url',return_value=self.client),patch('sys.argv',['migrate','--config',str(path),'--execute']),contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(main(),0)
            self.assertEqual(self.client.hget('risk:v1:day-key-ids','2026-10-27'),'old-key')
