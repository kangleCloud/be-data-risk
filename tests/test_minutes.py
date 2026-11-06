"""Current API-only wire and real Collector filtering/boundary behavior."""
import copy
from datetime import datetime
import json
from pathlib import Path
import unittest
from unittest.mock import Mock
from risk.aggregation import merge
from risk.algorithms import canonical
from risk.parsing import PrivacyPolicy, PathRule, Rejected, parse_observation
from risk.paths import valid_stored_path
from risk.protocol import validate_record, validate_envelope, make_envelope, MAX_COUNT
from risk.geo import GeoOutcome
from test_assets import asset
import test_integration as persistence
from test_integration import log, NOW


class MinuteProtocolTest(unittest.TestCase):
    def setUp(self):
        self.fixture=json.loads(asset('risk-v1/batches.json'))
        self.row=copy.deepcopy(self.fixture['batches'][0]['records'][0])

    def test_actual_collector_fixture_counts_status_ip_city_and_boundaries(self):
        rows=[]
        for env,encoded in zip(self.fixture['batches'],self.fixture['canonicalEnvelopes']):
            validate_envelope(env,encoded);rows+=env['records']
        n=lambda predicate:sum(int(row['requestCount']) for row in rows if predicate(row))
        expected=self.fixture['expected']
        self.assertEqual(str(n(lambda r:True)),expected['requestCount'])
        self.assertEqual(str(n(lambda r:200<=r['httpStatus']<400)),expected['successCount'])
        self.assertEqual(str(n(lambda r:400<=r['httpStatus']<600)),expected['failureCount'])
        self.assertEqual(str(n(lambda r:r['httpStatus']<200)),expected['otherCount'])
        self.assertEqual(str(len({r['sourceIp'] for r in rows if r['sourceIp']})),expected['sourceCount'])
        self.assertEqual(str(len({(r['method'],r['pathTemplate']) for r in rows})),expected['interfaceCount'])
        self.assertEqual({env['businessDate'] for env in self.fixture['batches']},{'2026-11-02','2026-11-03','2026-11-04'})
        self.assertTrue(any(row['cityCode']=='110000' and row['cityName']=='北京市' for row in rows))
        self.assertTrue(any(row['sourceIp']=='2001:4860:4860::8888' for row in rows))
        self.assertTrue(any(row['sourceIp']=='192.0.2.1' and row['regionCode']=='INTERNAL' for row in rows))
        self.assertTrue(any(row['sourceIp'] is None for row in rows))
        self.assertNotIn('synthetic-secret',canonical(self.fixture['batches']).decode())

    def test_unknown_fields_numeric_count_and_signed_overflow_reject(self):
        for changes in ({'extra':'private'},{'requestCount':0},{'requestCount':'0'}, {'requestCount':'01'},
                        {'requestCount':str(MAX_COUNT+1)},{'httpStatus':True},{'httpStatus':99},{'httpStatus':600}):
            with self.subTest(changes=changes),self.assertRaises(ValueError):validate_record(dict(self.row,**changes))
        validate_record(dict(self.row,requestCount=str(MAX_COUNT)))
        with self.assertRaises(ValueError):merge(dict(self.row,requestCount=str(MAX_COUNT)),self.row)

    def test_duplicate_natural_rows_day_time_and_extra_envelope_reject(self):
        env=copy.deepcopy(self.fixture['batches'][0])
        for mutate in (lambda e:e['records'].append(e['records'][0]),lambda e:e.update(businessDate='2026-11-03'),
                       lambda e:e.update(extra='private'),lambda e:e.update(schemaVersion=True),
                       lambda e:e.update(batchId=e['batchId'].upper()+'X'),lambda e:e.update(records={})):
            changed=copy.deepcopy(env);mutate(changed)
            with self.assertRaises(ValueError):validate_envelope(changed)
        for instant in ('2026-02-30T10:00:00.000+08:00','2026-11-02T10:01:01.000+08:00','2026-11-02T10:00:00.000Z'):
            with self.assertRaises(ValueError):validate_record(dict(self.row,minuteAt=instant))
        validate_envelope(make_envelope(env['batchId'],env['businessDate'],env['createdAt'],[]))

    def test_ip_canonicality_and_geo_shape_reject_whole_row(self):
        for changes in ({'sourceIp':'::FFFF:C000:0201'},{'sourceIp':'8.8.8.8\n'}, {'sourceIp':None},
                        {'cityName':None},{'countryCode':'US'},{'provinceName':'x\u200by'},
                        {'provinceName':'x'*513},{'countryCode':''}):
            with self.subTest(changes=changes),self.assertRaises(ValueError):validate_record(dict(self.row,**changes))

    def test_merge_keeps_valid_geo_on_lookup_failure_updates_complete_success(self):
        old=self.row
        delta=dict(old,regionCode='UNKNOWN',countryCode=None,provinceCode=None,provinceName=None,cityCode=None,cityName=None)
        output=merge(old,delta)
        self.assertEqual(output['requestCount'],'2');self.assertEqual(output['cityName'],old['cityName'])
        delta=dict(old,countryCode='GB',regionCode='GB',provinceCode=None,provinceName='England',cityCode=None,cityName=None)
        output=merge(old,delta)
        self.assertEqual(output['provinceName'],'England');self.assertIsNone(output['cityCode'])


class PrivacyParsingTest(unittest.TestCase):
    def parse(self,uri,**updates):
        return parse_observation(log(uri=uri,**updates),PrivacyPolicy(direct_peer_trusted=True))[0]

    def test_query_double_decode_nfc_and_sensitive_fixed_placeholders(self):
        for uri in ['/api/token/secret-text','/api/password=secret-text','/api/13800138000','/api/person/test@example.com']:
            row=self.parse(uri);self.assertIn('{redacted}',row['path_template']);self.assertNotIn('secret-text',row['path_template'])
        self.assertEqual(self.parse('/api/%25E4%25B8%25AD?a=secret#x')['path_template'],'/api/中')
        self.assertEqual(self.parse('/api/e\u0301')['path_template'],'/api/é')
        self.assertEqual(self.parse('/api/58.209.110.186/江苏省/中国电信/1234567890123456789012345')['path_template'],'/api/58.209.110.186/江苏省/中国电信/1234567890123456789012345')
        self.assertEqual(self.parse('/api/token/secret-text',**{'@timestamp':'2026-11-03T11:00:00+08:00'})['path_template'],self.parse('/api/token/secret-text')['path_template'])

    def test_path_unicode_limit_and_invalid_controls(self):
        for path in ['/api/'+'𠮷'*507,'/api/'+'中'*600]:
            protected=self.parse(path)['path_template'];self.assertLessEqual(len(protected),512);self.assertTrue(valid_stored_path(protected))
        for uri in ['/api/%ZZ','/api/%FF','/api/\u200b','/api/{raw}','/api/<script>','/api/%25252f']:
            self.assertEqual(self.parse(uri)['request_type'],'OTHER')

    def test_rules_do_not_change_api_scope_or_bypass_redaction(self):
        policy=PrivacyPolicy([PathRule('/api/items/[0-9]+','/api/items/{id}'),PathRule('/index','/api/page')])
        self.assertEqual(policy.path('/api/items/123'),('/api/items/{id}','API'))
        self.assertEqual(policy.path('/index'),('/api/page','PAGE'))
        for path in ['/market/dashboard/stream','/openapi/api/market/dashboard/stream','/stock/openapi/api/etf-monitor/v1/stream']:
            self.assertNotEqual(self.parse(path)['request_type'],'API')

    def test_timestamp_alias_and_invalid_json_safe(self):
        row=log(**{'@timestamp':'2026-11-03T03:00:00Z','time_iso8601':'2026-11-03T11:00:00+08:00'})
        self.assertEqual(parse_observation(row,PrivacyPolicy())[0]['event_at'],'2026-11-03T11:00:00.000+08:00')
        for raw in [b'{"x":1,"x":2}',b'{"private":"synthetic",}',log(**{'time_iso8601':'2026-11-03T11:01:00+08:00'})]:
            with self.assertRaises(Rejected) as caught:parse_observation(raw,PrivacyPolicy())
            self.assertNotIn('synthetic',str(caught.exception))


class ApiCollectorTest(persistence.CollectorTest):
    def test_filter_before_geo_and_filtered_only_checkpoint(self):
        lines=[log(uri=uri) for uri in ['/','/assets/main.js','/market/dashboard/stream']]
        self.path.write_bytes(b''.join(lines));self.collector.stage_limit=100
        self.collector.geo=Mock();self.drain();self.collector.flush_all()
        self.collector.geo.resolve_many.assert_not_called()
        self.assertEqual(self.batches()[0]['records'],[])
        self.assertEqual(json.loads(self.store.checkpoint(self.source.alias))['offset'],str(sum(map(len,lines))))

    def test_risk_backend_counted_and_geo_endpoint_does_not_recurse(self):
        paths=['/stock/admin/api/risk/dashboard','/scheduler/api/internal/risk/geo/resolve-batch',
               '/stock/scheduler/api/internal/risk/geo/resolve-batch']
        self.path.write_bytes(b''.join(log(uri=path,remote_addr='8.8.8.8') for path in paths))
        self.collector.stage_limit=100
        self.collector.geo=Mock()
        self.collector.geo.resolve_many.return_value={}
        self.drain();self.collector.flush_all()
        self.assertEqual(self.count(),3)
        self.assertEqual({row['pathTemplate'] for env in self.batches() for row in env['records']},set(paths))
        self.collector.geo.resolve_many.assert_called_once()
        self.assertEqual(self.collector.geo.resolve_many.call_args.args[0],['8.8.8.8'])

    def test_invalid_or_missing_status_counts_other_without_losing_api(self):
        statuses=[0,100,199,200,399,400,499,599,None,'-',True,600,'invalid']
        self.path.write_bytes(b''.join(log(status=status) for status in statuses))
        self.drain();self.collector.flush_all()
        self.assertEqual(self.count(),len(statuses))
        rows=[row for env in self.batches() for row in env['records']]
        self.assertEqual(sum(int(row['requestCount']) for row in rows if row['httpStatus']==0),6)
        self.assertEqual(sum(int(row['requestCount']) for row in rows if 400<=row['httpStatus']<=599),3)

    def test_geo_batched_api_only_failure_keeps_counts_and_diagnostics(self):
        self.path.write_bytes(log(uri='/')+log(remote_addr='8.8.8.8')*3)
        self.collector.stage_limit=100;self.collector.geo=Mock();self.collector.geo.resolve_many.side_effect=OSError('private-token')
        diagnostics=[];self.collector.diagnostic=diagnostics.append
        self.drain();self.collector.flush_all()
        self.assertEqual(self.count(),3)
        self.assertEqual(self.collector.geo.resolve_many.call_args.args[0],['8.8.8.8']*3)
        self.assertLessEqual(self.collector.geo.resolve_many.call_args.kwargs['budget'],.3)
        self.assertEqual(sum(int(d['count']) for d in diagnostics if d['code']=='GEO_SERVICE_UNAVAILABLE'),3)
        self.assertNotIn('private-token',json.dumps(diagnostics))

    def test_real_one_mib_flush_without_count_loss(self):
        base=json.loads(asset('risk-v1/batches.json'))['batches'][0]['records'][0]
        class Geo:
            def resolve_many(self,addresses,**kwargs):
                return {address:GeoOutcome('CN-11',(),dict(base,provinceName='省'*512,cityName='市'*512)) for address in addresses}
        self.collector.geo=Geo();self.collector.stage_limit=100
        self.path.write_bytes(b''.join(log(uri='/api/'+str(i)+'/'+'中'*500,remote_addr='114.247.50.2') for i in range(400)))
        self.drain();self.collector.flush_all()
        self.assertEqual(self.count(),400);self.assertGreater(len(self.batches()),1)
        self.assertTrue(all(len(canonical(env))<=1048576 for env in self.batches()))

# Reuse helper methods, while running original persistence regressions only once.
for _name in persistence.CollectorTest.__dict__:
    if _name.startswith('test_') and _name not in ApiCollectorTest.__dict__:
        setattr(ApiCollectorTest,_name,None)
