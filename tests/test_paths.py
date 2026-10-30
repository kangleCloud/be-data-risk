"""New path contract; all tests offline, no configured servers or production inputs."""
import copy
import hashlib
import hmac
import json
from pathlib import Path
import re
import tempfile
import unittest

import fakeredis
from risk.aggregation import event_records
from risk.algorithms import HLL,canonical,checksum,record_id
from risk.config import Config,SourceConfig
from risk.parsing import PrivacyPolicy,PathRule,parse_event
from risk.paths import protect_path,valid_stored_path,SSE_PATHS
from risk.protocol import asset,validate_record,validate_envelope
from risk.service import Collector
from risk.storage import RedisStore

DAY='2026-10-30'
KEY=b'synthetic-path-regression-key-at-least-32-bytes'


def event(uri,policy=None,key=KEY,status='200'):
    raw=json.dumps({'uri':uri,'@timestamp':DAY+'T12:00:00+08:00','status':status,
                    'request_method':'GET','request_time':'0.001','body_bytes_sent':'0'}).encode()
    return parse_event(raw,policy or PrivacyPolicy(),hmac_key=key)


class PathsTest(unittest.TestCase):
    def test_centralized_fixtures_produce_same_event_record_and_checksum(self):
        fixture=json.loads(asset('risk-v1/path-fixtures.json'))
        self.assertEqual(fixture['contract'],'risk-path-v1-20261030-r1')
        for case in fixture['cases']:
            with self.subTest(case=case['name']):
                data,expected=case['input'],case['expected']
                key=data['keyUtf8'].encode() if data['keyUtf8'] else None
                policy=PrivacyPolicy([PathRule(row['pattern'],row['template'],row['requestType']) for row in data['pathRules']])
                result=policy.protected_path(data['uri'],data['businessDate'],key)
                self.assertEqual(result.template,expected['pathTemplate'])
                self.assertEqual(result.request_type,expected['requestType'])
                self.assertEqual(list(result.quality),expected['quality'])
                raw=json.dumps({'uri':data['uri'],'@timestamp':data['businessDate']+'T12:00:00+08:00','status':data['status'],'request_method':'GET','request_time':'0.001','body_bytes_sent':'0'}).encode()
                parsed=parse_event(raw,policy,hmac_key=key)
                row=next(row for row in event_records(parsed,'fixture_source',HLL(),'fixture-key') if row['kind']=='COUNTER')
                validate_record(row)
                self.assertEqual(row,expected['record'])
                self.assertEqual(row['recordId'],expected['recordId'])
                self.assertEqual(canonical(row).decode(),expected['canonicalRecord'])
                self.assertEqual(checksum([row]),expected['checksum'])

    def test_hmac_uses_literal_segment_and_existing_daily_key(self):
        secret='SyntheticSecret_42'
        digest=hmac.new(KEY,('risk-path-v1\n'+DAY+'\nsegment\n'+secret).encode(),hashlib.sha256).hexdigest()
        self.assertEqual(event('/api/token/'+secret)['path_template'],'/api/token/{redacted:'+digest+'}')
        next_day=protect_path('/api/token/'+secret,'2026-10-31',KEY)
        self.assertNotIn(digest,next_day.template)

    def test_long_path_digest_uses_redacted_full_path_and_path_purpose(self):
        path='/'+('中'*400)+'/token/SyntheticSecret_42/'+('后'*200)
        seg=hmac.new(KEY,('risk-path-v1\n'+DAY+'\nsegment\nSyntheticSecret_42').encode(),hashlib.sha256).hexdigest()
        redacted='/'+('中'*400)+'/token/{redacted:'+seg+'}/'+('后'*200)
        digest=hmac.new(KEY,('risk-path-v1\n'+DAY+'\npath\n'+redacted).encode(),hashlib.sha256).hexdigest()
        result=protect_path(path,DAY,KEY)
        self.assertTrue(result.template.endswith('/{path:'+digest+'}'))
        self.assertNotIn('SyntheticSecret_42',result.template)
        self.assertLessEqual(len(result.template),512)
        self.assertTrue(valid_stored_path(result.template))
        self.assertNotIn('{redacted:',result.template)  # cut retreated before the marker

    def test_code_point_boundaries_include_non_bmp(self):
        for char in ['中','😀']:
            with self.subTest(char=char):
                exact='/'+char*511
                self.assertEqual(protect_path(exact,DAY,KEY).template,exact)
                over=protect_path('/'+char*512,DAY,KEY).template
                self.assertEqual(len(over),512)
                self.assertTrue(valid_stored_path(over))

    def test_invalid_paths_still_have_safe_counter(self):
        values=[None,123,'http://example.invalid','/api/%ZZ','/api/%FF','/api/%252561','/api/\x00','/api/\u202e','/api/{redacted}','/'+('x'*16384),'/api/\ud800']
        for value in values:
            with self.subTest(value=repr(value)):
                parsed=event(value)
                self.assertEqual(parsed['path_template'],'/__invalid_path__')
                self.assertEqual(parsed['request_type'],'OTHER')
                self.assertIn('UNMATCHED_PATH',parsed['quality'])
                rows=event_records(parsed,'synthetic',HLL(),'synthetic-key')
                self.assertEqual(next(row for row in rows if row['kind']=='COUNTER')['requestCount'],'1')

    def test_all_sensitive_field_names_and_value_forms(self):
        for label in ['password','passwd','pwd','TOKEN','access_token','refresh_token','secret','authorization','cookie','密码','令牌']:
            for separator in ['/','=',':']:
                with self.subTest(label=label,separator=separator):
                    parsed=event('/api/'+label+separator+'SyntheticPrivateValue')
                    self.assertNotIn('SyntheticPrivateValue',json.dumps(parsed))
                    self.assertIn('{redacted:',parsed['path_template'])

    def test_random_boundaries_are_not_free_entropy_choice(self):
        self.assertEqual(protect_path('/api/'+('x'*22+'1'),DAY,KEY).template,'/api/'+('x'*22+'1'))
        self.assertIn('{redacted:',protect_path('/api/'+('x'*23+'1'),DAY,KEY).template)
        self.assertIn('{redacted:',protect_path('/api/'+('a'*24),DAY,KEY).template)
        self.assertEqual(protect_path('/api/'+('hello'*8),DAY,KEY).template,'/api/'+('hello'*8))

    def test_missing_key_never_falls_back_to_original(self):
        for uri in ['/api/token/SyntheticPrivateValue','/api/user/user@example.invalid','/'+('中'*512)]:
            parsed=event(uri,key=None)
            self.assertIn('KEY_UNAVAILABLE',parsed['quality'])
            self.assertNotIn('SyntheticPrivateValue',json.dumps(parsed))
            self.assertNotIn('user@example.invalid',json.dumps(parsed))
            self.assertNotIn('{redacted:',parsed['path_template'])
            self.assertLessEqual(len(parsed['path_template']),512)
        self.assertNotIn('KEY_UNAVAILABLE',event('/unknown/readable',key=None)['quality'])
        raw=json.dumps({'uri':'/api/token/SyntheticPrivateValue','@timestamp':DAY+'T12:00:00+08:00','remote_addr':'10.0.0.1'}).encode()
        combined=parse_event(raw,PrivacyPolicy(direct_peer_trusted=True),hmac_key=None)
        self.assertEqual(combined['quality'].count('KEY_UNAVAILABLE'),1)

    def test_decoding_nfc_and_literal_plus(self):
        for uri,expected in [('/api/%25E8%25AE%25A2%25E5%258D%2595','/api/订单'),('/api/cafe\u0301','/api/café'),('/api/a+b','/api/a+b'),('/api/a%3Ftoken=secret','/api/a'),('/api/a#token=secret','/api/a'),('/api//a/','/api/a/')]:
            self.assertEqual(event(uri)['path_template'],expected)

    def test_fixed_classification_precedence(self):
        values=[('/stock/admin/api/risk/report.js','RISK_INTERNAL'),('/api/client.js','STATIC'),('/static/custom.unknown','STATIC'),('/openapi/api/new/42','API'),('/app/api/new/42','API'),('/stock/app/api/new/42','API'),('/scheduler/api/new/42','API'),('/stock/scheduler/api/new/42','API'),('/internal/jobs/v1/market/refresh','API'),('/stock/admin/api/new','API'),('/missing/404','PAGE'),('/index.html','PAGE'),('/unknown/file.blob','OTHER')]
        for uri,kind in values:
            parsed=event(uri,status='404')
            self.assertEqual(parsed['request_type'],kind)
            self.assertNotIn('UNMATCHED_PATH',parsed['quality'])
        for uri in SSE_PATHS:
            parsed=event(uri+'?token=discard')
            self.assertEqual(parsed['request_type'],'SSE')
            self.assertEqual(parsed['path_template'],uri)
        self.assertEqual(event('/api/fake/stream')['request_type'],'API')

    def test_old_rules_can_group_not_classify_or_leak(self):
        policy=PrivacyPolicy([PathRule('/api/.*','/token/SyntheticPrivateValue','SSE')])
        parsed=event('/api/users/123',policy)
        self.assertEqual(parsed['request_type'],'API')
        self.assertNotIn('SyntheticPrivateValue',str(parsed))
        original=event('/api/token/SyntheticPrivateValue',policy)
        self.assertTrue(original['path_template'].startswith('/api/token/{redacted:'))
        unicode=PrivacyPolicy([PathRule('/api/.*','/订单/{id}','PAGE')])
        self.assertEqual(event('/api/users/123',unicode)['path_template'],'/订单/{id}')
        self.assertEqual(event('/admin/api/risk/dashboard',policy)['request_type'],'RISK_INTERNAL')
        with self.assertRaises(ValueError):PrivacyPolicy([PathRule('/.*','/token/\\1','API')])
        with self.assertRaises(ValueError):PrivacyPolicy([PathRule('/.*','/api/%3Ftoken=secret','API')])
        with self.assertRaises(ValueError):PrivacyPolicy([PathRule('/.*','/token/x'*8,'API')])

    def test_history_and_new_unicode_record_validation(self):
        template=json.loads(asset('risk-v1-fixtures.json'))['record']
        for path in ['UNMATCHED','/订单/😀','/用户/{id}']:
            row=copy.deepcopy(template);row['dimensions']['pathTemplate']=path;row['recordId']=record_id(row['dimensions']);validate_record(row)
        for path in ['/api/{redacted:short}','/api/\x00','/api/%20','/'+('😀'*512),'/cafe\u0301','/api/{open','/api/x{redactedSuffix}x']:
            row=copy.deepcopy(template);row['dimensions']['pathTemplate']=path;row['recordId']=record_id(row['dimensions'])
            with self.assertRaises(ValueError):validate_record(row)
        row=copy.deepcopy(template);row['dimensions']['regionCode']='上海';row['recordId']=record_id(row['dimensions'])
        with self.assertRaises(ValueError):validate_record(row)

    def test_collector_counts_no_rules_and_never_persists_sensitive_values(self):
        samples=['/api/missing/42','/unknown/42','/api/订单','/api/%E8%AE%A2%E5%8D%95','/api/token/SyntheticPrivateValue','/api/user/user@example.invalid','/api/user/+8613800138000','/api/user/12345678-1234-1234-1234-123456789abc','/api/ip/192.0.2.42',*sorted(SSE_PATHS),'/stock/admin/api/risk/dashboard']
        client=fakeredis.FakeRedis(decode_responses=True)
        diagnostics=[]
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/'sample.log'
            path.write_bytes(b''.join(json.dumps({'uri':uri,'@timestamp':DAY+'T12:00:00+08:00','status':'404','request_method':'GET'}).encode()+b'\n' for uri in samples))
            collector=Collector(RedisStore(client),Config((SourceConfig('synthetic',path),),PrivacyPolicy(),65536),KEY,clock=lambda:DAY+'T13:00:00.000+08:00',diagnostic=diagnostics.append)
            try:
                while collector.tick():pass
                collector.flush_all()
                envelopes=[json.loads(client.get('risk:v1:batch:'+DAY+':'+batch)) for batch in client.smembers('risk:v1:pending:'+DAY)]
                for env in envelopes:validate_envelope(env)
                counters=[row for env in envelopes for row in env['records'] if row['kind']=='COUNTER']
                self.assertEqual(sum(int(row['requestCount']) for row in counters),len(samples))
                self.assertEqual(sum(int(row['requestCount']) for row in counters if row['dimensions']['requestType']=='SSE'),9)
                wire=json.dumps(envelopes)+json.dumps(diagnostics)
                for secret in ['SyntheticPrivateValue','user@example.invalid','13800138000','12345678-1234-1234-1234-123456789abc','192.0.2.42']:
                    self.assertNotIn(secret,wire)
                self.assertFalse(any(row['dimensions'].get('reasonCode')=='UNMATCHED_PATH' for env in envelopes for row in env['records']))
            finally:collector.close(flush=False);client.close()

    def test_draft_2020_12_validates_old_and_new_fixtures_and_literal_markers(self):
        from jsonschema import Draft202012Validator,FormatChecker
        schema=json.loads(asset('risk-v1/record.schema.json'))
        Draft202012Validator.check_schema(schema)
        validator=Draft202012Validator(schema,format_checker=FormatChecker())
        old=json.loads(asset('risk-v1-fixtures.json'))['record']
        records=[old]
        records += [case['expected']['record'] for case in json.loads(asset('risk-v1/path-fixtures.json'))['cases']]
        records += [row for batch in json.loads(asset('risk-v1-batches.json'))['batches'] for row in batch['records']]
        for record in records:
            self.assertTrue(validator.is_valid(record),record['recordId'])
        for path in ['/订单/😀','/'+('😀'*511),'/api/token/{redacted}','/api/token={redacted:'+('a'*64)+'}','/'+('中'*400)+'/{path:'+('b'*64)+'}','/用户/{UserId}']:
            row=copy.deepcopy(old);row['dimensions']['pathTemplate']=path
            self.assertTrue(validator.is_valid(row))
        for path in ['/'+('😀'*512),'/api/{redacted:short}','/api/{redacted:'+('A'*64)+'}','/api/{path:plain}','/api/{broken','/api/\x85','/api/%20']:
            row=copy.deepcopy(old);row['dimensions']['pathTemplate']=path
            self.assertFalse(validator.is_valid(row),repr(path))
        for field,value in [('requestType','api'),('method','get'),('regionCode','cn-SH'),('status','unknown')]:
            row=copy.deepcopy(old);row['dimensions'][field]=value
            self.assertFalse(validator.is_valid(row))
