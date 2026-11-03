"""No real Redis: safety gates, namespace deletion and real Collector rebuild."""
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
from risk.algorithms import HLL
from risk.protocol import validate_envelope

class RebuildTest(unittest.TestCase):
    def setUp(self):
        self.client=fakeredis.FakeRedis(decode_responses=True);self.addCleanup(self.client.close)
        for i in range(25):
            self.client.set('risk:v1:test:'+str(i),'synthetic')
            self.client.set('geoip:v1:test:'+str(i),'synthetic')
        for key in ['risk:v10:other','risk:v1','geoip:v10:other','stocks:prices','server:target']:
            self.client.set(key,'keep')
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        self.config=Path(self.tmp.name)/'config.json'
        self.config.write_text(json.dumps({'redisUrl':'redis://synthetic-user:synthetic-secret@fake.invalid:1/2'}))

    def test_default_preview_does_not_mutate(self):
        before={k:self.client.dump(k) for k in self.client.keys('*')}
        result=rebuild(self.client,batch_size=3)
        self.assertEqual(result['mode'],'DRY_RUN')
        self.assertEqual(before,{k:self.client.dump(k) for k in self.client.keys('*')})
        self.assertTrue(all(v['deletedKeys']==0 for v in result['namespaces'].values()))

    def test_execute_clears_only_exact_prefixes_in_bounded_unlinks(self):
        with patch.object(self.client,'unlink',wraps=self.client.unlink) as unlink:
            result=rebuild(self.client,execute=True,writers_stopped=True,batch_size=3)
        self.assertTrue(all(len(call.args)<=3 for call in unlink.call_args_list))
        self.assertEqual(sum(v['deletedKeys'] for v in result['namespaces'].values()),50)
        self.assertEqual(set(self.client.keys('*')),{'risk:v10:other','risk:v1','geoip:v10:other','stocks:prices','server:target'})
        self.assertEqual(sum(v['deletedKeys'] for v in rebuild(self.client,execute=True,writers_stopped=True)['namespaces'].values()),0)

    def test_missing_stop_confirmation_target_mismatch_or_credentials_never_connect(self):
        args=['--config',str(self.config),'--target','redis://fake.invalid:1/2']
        for extra in [['--execute'],['--target','redis://other.invalid:1/2'],['--target','redis://user:synthetic-secret@fake.invalid:1/2'],['--target','redis://fake.invalid:1']]:
            output=io.StringIO()
            with patch('redis.Redis.from_url') as connect,contextlib.redirect_stderr(output):
                self.assertEqual(main(args+extra),1)
            connect.assert_not_called();self.assertNotIn('synthetic-secret',output.getvalue())

    def test_cli_preview_and_explicit_execution_only_log_counts(self):
        args=['--config',str(self.config),'--target','redis://fake.invalid:1/2']
        for extra,mode in [([], 'DRY_RUN'),(['--execute','--writers-stopped'],'EXECUTED')]:
            output=io.StringIO()
            with patch('redis.Redis.from_url',return_value=self.client),contextlib.redirect_stdout(output):
                self.assertEqual(main(args+extra),0)
            self.assertEqual(json.loads(output.getvalue())['mode'],mode)
            self.assertNotIn('synthetic-secret',output.getvalue())
            self.assertNotIn('fake.invalid',output.getvalue())

    def test_target_identity_preserves_database_tls_and_unix(self):
        self.assertEqual(target_identity('rediss://user:secret@host:6380/2'),target_identity('rediss://host:6380/2',public_target=True))
        self.assertNotEqual(target_identity('redis://host/2'),target_identity('redis://host/3'))
        self.assertNotEqual(target_identity('redis://host/2'),target_identity('rediss://host/2'))
        self.assertEqual(target_identity('unix:///tmp/synthetic.sock?db=2'),('unix','/tmp/synthetic.sock',2))
        for target in ['redis://host/2?db=2&db=3','redis://host/2?password=synthetic','redis://host:0/2']:
            with self.assertRaises(RebuildError):target_identity(target,public_target=True)

    def test_invalid_limits_and_bad_scan_never_expand_scope(self):
        with self.assertRaises(RebuildError):rebuild(self.client,batch_size=0)
        with self.assertRaises(RebuildError):rebuild(self.client,max_scan_calls=1)
        with patch.object(self.client,'scan',return_value=(0,['stocks:prices'])),self.assertRaises(RebuildError):
            rebuild(self.client,execute=True,writers_stopped=True)
        self.assertEqual(self.client.get('stocks:prices'),'keep')

    def test_scan_failure_is_not_success_or_private_error_dump(self):
        output=io.StringIO()
        with patch('redis.Redis.from_url',return_value=self.client),patch.object(self.client,'scan',side_effect=ConnectionError('synthetic-private-secret')),contextlib.redirect_stderr(output):
            self.assertEqual(main(['--config',str(self.config),'--target','redis://fake.invalid:1/2']),1)
        self.assertEqual(json.loads(output.getvalue()),{'code':'REBUILD_FAILED'})

    def test_current_collector_replays_log_head_then_restart_is_idempotent(self):
        # A reset clears durable checkpoint; it never touches the actual log.
        self.client.hset('risk:v1:checkpoints','source','synthetic-checkpoint')
        rebuild(self.client,execute=True,writers_stopped=True,batch_size=5)
        path=Path(self.tmp.name)/'access.log'
        entries=[{'@timestamp':'2026-11-02T10:00:01+08:00','uri':'/api/test','request_method':'GET','status':'200','request_time':'0.001','remote_addr':'8.8.8.8','body_bytes_sent':'3'} for _ in range(4)]
        data=b''.join(json.dumps(v).encode()+b'\n' for v in entries);path.write_bytes(data)
        cfg=Config((SourceConfig('source',path),),PrivacyPolicy(direct_peer_trusted=True),65536)
        key=b'synthetic-rebuild-hmac-key-at-least-32-bytes'
        for _ in range(2):
            collector=Collector(RedisStore(self.client),cfg,key,clock=lambda:'2026-11-02T10:01:00.000+08:00')
            try:
                while collector.tick():pass
                collector.close()
            finally:collector.close(flush=False)
        self.assertEqual(path.read_bytes(),data)
        rows=[]
        for batch in self.client.smembers('risk:v1:pending:2026-11-02'):
            encoded=self.client.get('risk:v1:batch:2026-11-02:'+batch);env=json.loads(encoded);validate_envelope(env,encoded);rows+=env['records']
        for kind in ['COUNTER','GEO_COUNTER']:
            self.assertEqual(sum(int(r['requestCount']) for r in rows if r['kind']==kind),4)
        sources=HLL()
        for row in rows:
            if row['kind']=='SOURCE':sources.merge(HLL.decode(row['registersBase64']))
            if row['kind']=='COUNTER':self.assertEqual(sum(map(int,row['histogram'])),int(row['requestCount']))
        self.assertEqual(sources.estimate(),1)
