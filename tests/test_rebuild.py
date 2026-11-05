"""Only synthetic fake Redis; reset must preserve durable cursor and Geo data."""
import contextlib
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import fakeredis
from redis.exceptions import ConnectionError
from tools.rebuild_redis import rebuild,main,target_identity,RebuildError
from risk.config import Config,SourceConfig
from risk.parsing import PrivacyPolicy
from risk.service import Collector
from risk.storage import RedisStore
from test_integration import log


class RebuildTest(unittest.TestCase):
    def setUp(self):
        self.client=fakeredis.FakeRedis(decode_responses=True);self.addCleanup(self.client.close)
        self.deleted={'risk:v1:days','risk:v1:day-key-ids','risk:v1:pending:2026-11-03',
                      'risk:v1:batch:2026-11-03:00000000-0000-0000-0000-000000000001','risk:v1:query:dashboard:2026-11-03'}
        self.kept={'risk:v1:checkpoints','risk:v1:lease:source','risk:v1:heartbeat','geoip:v1:control',
                   'geoip:v1:result:cache:8.8.8.8','geoip:v1:metrics:python','risk:v1:server:target',
                   'stocks:prices','risk:v10:days','risk:v1:pending:invalid','risk:v1:pending:2026-02-30',
                   'risk:v1:batch:2026-11-03:invalid-id','risk:v1:query'}
        for key in self.deleted|self.kept:self.client.set(key,'synthetic')
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        self.config=Path(self.tmp.name)/'config.json'
        self.config.write_text(json.dumps({'redisUrl':'redis://synthetic-user:synthetic-secret@fake.invalid:1/2'}))

    def test_default_preview_and_explicit_bounded_delete_preserve_every_protected_key(self):
        before={k:self.client.dump(k) for k in self.client.keys('*')}
        preview=rebuild(self.client,batch_size=2)
        self.assertEqual(before,{k:self.client.dump(k) for k in self.client.keys('*')})
        self.assertEqual(sum(v['scanEntries'] for v in preview['namespaces'].values()),len(self.deleted))
        with patch.object(self.client,'unlink',wraps=self.client.unlink) as unlink:
            actual=rebuild(self.client,execute=True,writers_stopped=True,batch_size=2)
        self.assertTrue(all(len(call.args)<=2 for call in unlink.call_args_list))
        self.assertEqual(sum(v['deletedKeys'] for v in actual['namespaces'].values()),len(self.deleted))
        self.assertEqual(set(self.client.keys('*')),self.kept)
        self.assertTrue(all(self.client.dump(key)==before[key] for key in self.kept))
        self.assertEqual(sum(v['deletedKeys'] for v in rebuild(self.client,execute=True,writers_stopped=True)['namespaces'].values()),0)

    def test_missing_confirmation_or_explicit_target_mismatch_never_connects(self):
        args=['--config',str(self.config),'--target','redis://fake.invalid:1/2']
        for extra in [['--execute'],['--target','redis://other.invalid:1/2'],['--target','redis://user:synthetic-secret@fake.invalid:1/2'],['--target','redis://fake.invalid:1']]:
            output=io.StringIO()
            with patch('redis.Redis.from_url') as connect,contextlib.redirect_stderr(output):self.assertEqual(main(args+extra),1)
            connect.assert_not_called();self.assertNotIn('synthetic-secret',output.getvalue())

    def test_target_identity_preserves_db_tls_unix_and_rejects_ambiguous_target(self):
        self.assertEqual(target_identity('rediss://user:secret@host:6380/2'),target_identity('rediss://host:6380/2',public_target=True))
        self.assertNotEqual(target_identity('redis://host/2'),target_identity('redis://host/3'))
        self.assertNotEqual(target_identity('redis://host/2'),target_identity('rediss://host/2'))
        self.assertEqual(target_identity('unix:///tmp/synthetic.sock?db=2'),('unix','/tmp/synthetic.sock',2))
        for target in ['redis://host/2?db=2&db=3','redis://host/2?password=synthetic','redis://host:0/2']:
            with self.assertRaises(RebuildError):target_identity(target,public_target=True)

    def test_invalid_scan_or_limit_never_deletes_foreign_keys(self):
        with self.assertRaises(RebuildError):rebuild(self.client,batch_size=0)
        with self.assertRaises(RebuildError):rebuild(self.client,max_scan_calls=1)
        with patch.object(self.client,'scan',return_value=(0,['stocks:prices'])),self.assertRaises(RebuildError):rebuild(self.client,execute=True,writers_stopped=True)
        self.assertEqual(self.client.get('stocks:prices'),'synthetic')

    def test_cli_error_and_preview_never_log_credentials_or_target(self):
        args=['--config',str(self.config),'--target','redis://fake.invalid:1/2']
        output=io.StringIO()
        with patch('redis.Redis.from_url',return_value=self.client),contextlib.redirect_stdout(output):self.assertEqual(main(args),0)
        self.assertEqual(json.loads(output.getvalue())['mode'],'DRY_RUN')
        self.assertNotIn('synthetic-secret',output.getvalue());self.assertNotIn('fake.invalid',output.getvalue())
        output=io.StringIO()
        with patch('redis.Redis.from_url',return_value=self.client),patch.object(self.client,'scan',side_effect=ConnectionError('private-secret')),contextlib.redirect_stderr(output):self.assertEqual(main(args),1)
        self.assertEqual(json.loads(output.getvalue()),{'code':'REBUILD_FAILED'})

    def test_real_collector_continues_preserved_checkpoint_without_rereading_old_log(self):
        self.client=fakeredis.FakeRedis(decode_responses=True);self.addCleanup(self.client.close)
        path=Path(self.tmp.name)/'access.log';path.write_bytes(log()*2)
        config=Config((SourceConfig('source',path),),PrivacyPolicy(direct_peer_trusted=True),65536)
        def collect():
            collector=Collector(RedisStore(self.client),config,clock=lambda:'2026-11-03T12:00:00.000+08:00')
            try:
                while collector.tick():pass
                collector.close()
            finally:collector.close(flush=False)
        collect();checkpoint=self.client.hget('risk:v1:checkpoints','source')
        rebuild(self.client,execute=True,writers_stopped=True)
        self.assertEqual(self.client.hget('risk:v1:checkpoints','source'),checkpoint)
        self.assertEqual(list(self.client.scan_iter('risk:v1:batch:*')),[])
        collect();self.assertEqual(list(self.client.scan_iter('risk:v1:batch:*')),[])
        with path.open('ab') as stream:stream.write(log())
        collect();rows=[]
        for key in self.client.scan_iter('risk:v1:batch:*'):rows+=json.loads(self.client.get(key))['records']
        self.assertEqual(sum(int(row['requestCount']) for row in rows),1)
