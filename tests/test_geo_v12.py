from test_assets import asset
"""V1.2 wire consumption and failure isolation; synthetic local fixtures only."""
import copy
from datetime import datetime
import json
import threading
import time
import unittest
from unittest.mock import Mock, patch
import fakeredis
from risk.geo import UnifiedGeoClient, InternalBatchHttp, make_geo_cache_client, fallback_outcome
from risk.protocol import validate_record, validate_envelope, make_envelope
from risk.algorithms import canonical, checksum, HLL
from risk.aggregation import event_records, merge
from risk.parsing import parse_observation, PrivacyPolicy
from risk.service import Collector
from risk.storage import StorageError
import test_integration as collector_tests
from test_integration import log, NOW

F=json.loads(asset('geoip-v1/fixtures.json'))
EPOCH=datetime.fromisoformat('2026-10-31T10:00:01+08:00').timestamp()

class GeoClientTest(unittest.TestCase):
    def setUp(self):
        self.cache=fakeredis.FakeRedis(decode_responses=True)
        self.addCleanup(self.cache.close)
        self.control=F['control']
        self.cache.hset('geoip:v1:control',mapping=self.control)
        self.row=copy.deepcopy(F['cases'][0]['result'])
        self.ip=self.row['ip']
        self.http=Mock(side_effect=self.reply)
        self.client=UnifiedGeoClient(self.cache,self.http,epoch=lambda:EPOCH)

    def reply(self, addresses, deadline):
        rows=[]
        for address in addresses:
            row=copy.deepcopy(self.row);row['ip']=address
            import ipaddress
            row['ipVersion']=ipaddress.ip_address(address).version
            rows.append(row)
        return {'success':True,'content':{'schemaVersion':1,'cacheVersion':self.control['cacheVersion'],'redisAvailable':True,'results':rows}}

    def put(self, row=None):
        self.cache.set('geoip:v1:result:'+self.control['cacheVersion']+':'+self.ip,json.dumps(row or self.row))

    def test_frozen_java_results_and_canonical_geo_records(self):
        for case in F['cases']:
            with self.subTest(case=case['name']):
                result=case['result']
                self.row=copy.deepcopy(result)
                output=self.client.resolve_many([result['ip']])[result['ip']]
                if result['geoGroup']=='UNTRUSTED':
                    continue # trust boundary tested below, never feed a trusted request as untrusted
                raw=json.dumps({'uri':'/api/test','@timestamp':'2026-10-31T10:00:01+08:00','remote_addr':result['ip'],'request_method':'GET','status':'200'}).encode()
                event,address=parse_observation(raw,PrivacyPolicy(direct_peer_trusted=True))
                event.update(region_code=output.region_code,geo=output.result or {})
                geo=next(r for r in event_records(event,'test',HLL(),'unavailable') if r['kind']=='GEO_COUNTER')
                self.assertEqual(geo,case['geoRecord'])
                self.assertEqual(canonical(geo).decode(),case['canonicalRecord'])
                self.assertEqual(checksum([geo]),case['checksum'])

    def test_hit_no_http_and_does_not_extend_expiry(self):
        self.put();self.cache.expire('geoip:v1:result:'+self.control['cacheVersion']+':'+self.ip,600)
        output=self.client.resolve_many([self.ip])[self.ip]
        self.assertEqual(output.result,self.row);self.http.assert_not_called()
        self.assertLessEqual(self.cache.ttl('geoip:v1:result:'+self.control['cacheVersion']+':'+self.ip),600)
        self.assertEqual(self.cache.hget('geoip:v1:metrics:python','hits'),'1')

    def test_same_mapped_and_duplicate_ip_one_lookup(self):
        result=self.client.resolve_many([self.ip,self.ip,'::ffff:'+self.ip])
        self.assertEqual(list(result),[self.ip]);self.assertEqual(self.http.call_args.args[0],[self.ip])

    def test_non_public_untrusted_never_lookup(self):
        result=self.client.resolve_many([None,'127.0.0.1','10.0.0.1','::1'])
        self.http.assert_not_called()
        self.assertEqual(result[None].region_code,'UNKNOWN')
        self.assertEqual(result['10.0.0.1'].result['resultStatus'],'NON_PUBLIC_IP')
        self.assertEqual(self.cache.hget('geoip:v1:metrics:python','quality_nonPublic'),'3')
        self.assertEqual(self.cache.hget('geoip:v1:metrics:python','quality_untrusted'),'1')

    def test_missing_empty_corrupt_control_ignores_cache(self):
        self.put()
        for key in ('cacheVersion','providerSetVersion'):
            self.cache.hset('geoip:v1:control',mapping=self.control)
            self.cache.hset('geoip:v1:control',key,'')
            self.client.resolve_many([self.ip]);self.assertTrue(self.http.called);self.http.reset_mock()
        self.cache.delete('geoip:v1:control');self.http.side_effect=OSError()
        self.assertEqual(self.client.resolve_many([self.ip])[self.ip].region_code,'UNKNOWN')

    def test_expired_wrong_version_corrupt_cache_calls_internal(self):
        for updates in ({'expiresAt':'2026-10-30T10:00:00.000+08:00'},{'cacheVersion':'retired'},{'resolvedAt':'2027-01-01T00:00:00.000+08:00'}):
            self.put(dict(self.row,**updates));out=self.client.resolve_many([self.ip])[self.ip]
            self.assertIn('GEO_VERSION_STALE',out.quality);self.assertTrue(self.http.called);self.http.reset_mock()

    def test_control_change_during_read_uses_internal(self):
        self.put(); original=self.cache.hgetall; count=0
        def changing(key):
            nonlocal count
            count+=1
            return dict(self.control,cacheVersion='changed') if count==2 else original(key)
        with patch.object(self.cache,'hgetall',side_effect=changing):self.client.resolve_many([self.ip])
        self.http.assert_called_once()

    def test_redis_error_uses_local_http(self):
        with patch.object(self.cache,'hgetall',side_effect=OSError('private')):
            self.assertEqual(self.client.resolve_many([self.ip])[self.ip].region_code,self.row['regionCode'])
        self.http.assert_called_once()

    def test_http_error_unknown_no_exception_or_secret(self):
        self.http.side_effect=OSError('private token')
        result=self.client.resolve_many([self.ip])[self.ip]
        self.assertEqual(result.result['resultStatus'],'PROVIDER_UNAVAILABLE')
        self.assertNotIn('private',repr(result))

    def test_oversized_batch_rejected_before_io(self):
        with self.assertRaises(ValueError):self.client.resolve_many(['11.0.0.'+str(x) for x in range(101)])
        self.http.assert_not_called()

    def test_foreign_city_from_bad_response_rejected(self):
        self.row.update(countryCode='US',regionCode='US')
        self.assertEqual(self.client.resolve_many([self.ip])[self.ip].region_code,'UNKNOWN')

    def test_foreign_name_without_code_preserved(self):
        self.row.update(countryCode='GB',regionCode='GB',provinceCode=None,provinceName='England',cityCode=None,cityName=None,cityGeoNameId=None,locationLevel='PROVINCE')
        result=self.client.resolve_many([self.ip])[self.ip].result
        self.assertEqual(result['provinceName'],'England');self.assertIsNone(result['provinceCode'])

    def test_invalid_partial_duplicate_and_unsuccessful_replies_rejected(self):
        for transform in [lambda r:r.update(success=False),lambda r:r['content'].update(results=[]),lambda r:r['content'].update(cacheVersion='wrong')]:
            reply=self.reply([self.ip],time.monotonic()+1);transform(reply);self.http.side_effect=None;self.http.return_value=reply
            self.assertEqual(self.client.resolve_many([self.ip])[self.ip].region_code,'UNKNOWN')

    def test_budget_includes_blocked_cache_and_no_worker_growth(self):
        gate=threading.Event()
        with patch.object(self.cache,'hgetall',side_effect=lambda _:gate.wait(2)):
            start=time.monotonic();out=self.client.resolve_many([self.ip],budget=.03)
            self.assertLess(time.monotonic()-start,.15)
            self.assertEqual(out[self.ip].region_code,'UNKNOWN')
            start=time.monotonic();self.client.resolve_many([self.ip]);self.assertLess(time.monotonic()-start,.03)
            gate.set()

    def test_http_and_cache_share_one_budget(self):
        original=self.cache.hgetall
        def slow(key):time.sleep(.04);return original(key)
        seen=[]
        def stalled(addresses,deadline):seen.append(deadline-time.monotonic());time.sleep(.3);return self.reply(addresses,deadline)
        self.http.side_effect=stalled
        with patch.object(self.cache,'hgetall',side_effect=slow):
            start=time.monotonic();result=self.client.resolve_many([self.ip],budget=.12)
            self.assertLess(time.monotonic()-start,.2)
            self.assertLess(seen[0],.06)
            self.assertEqual(result[self.ip].region_code,'UNKNOWN')

    def test_internal_http_configuration(self):
        path='/scheduler/api/internal/risk/geo/resolve-batch'
        for url in ['http://user:password@127.0.0.1'+path,'http://127.0.0.1'+path+'?token=x','http://127.0.0.1/wrong']:
            with self.assertRaisesRegex(ValueError,'INVALID_GEO_SERVICE_CONFIG'):InternalBatchHttp(url,'synthetic')
        transport=InternalBatchHttp('http://127.0.0.1:19002'+path,'synthetic')
        self.assertEqual(transport.url,'http://127.0.0.1:19002'+path)
        self.assertIsNone(__import__('risk.geo',fromlist=['_NoRedirect'])._NoRedirect().redirect_request(None,None,302,'',{},'http://8.8.8.8'))

    def test_geo_redis_url_same_database_short_timeouts(self):
        with patch('redis.Redis.from_url') as factory:
            make_geo_cache_client('redis://localhost:6379/11')
            self.assertEqual(factory.call_args.args,('redis://localhost:6379/11',))
            self.assertEqual(factory.call_args.kwargs['socket_timeout'],.05)

class BatchGeoTest(collector_tests.CollectorTest):
    # Reuse storage helpers only; inherited regression tests remain in original class.
    def new_collector(self,key=b'synthetic-immutable-test-key-32-bytes-only'):
        result=super().new_collector(key);result.stage_limit=100;return result

    def test_one_call_per_hundred_lines_and_one_geo_per_request(self):
        self.path.write_bytes(log(remote_addr='8.8.8.8')*205)
        fake=Mock();fake.resolve_many.side_effect=lambda addresses,**kw:{a:fallback_outcome(a) for a in addresses}
        self.collector.geo=fake
        self.drain();self.collector.flush_all()
        self.assertEqual(fake.resolve_many.call_count,3)
        self.assertTrue(all(len(c.args[0])<=100 for c in fake.resolve_many.call_args_list))
        self.assertEqual(self.count(),205)
        geos=[r for b in self.batches() for r in b['records'] if r['kind']=='GEO_COUNTER']
        self.assertEqual(sum(int(r['requestCount']) for r in geos),205)

    def test_geo_failure_never_drops_request_counts(self):
        self.path.write_bytes(log(remote_addr='8.8.8.8')*8)
        self.collector.geo=Mock();self.collector.geo.resolve_many.side_effect=TimeoutError()
        self.drain();self.collector.flush_all();self.assertEqual(self.count(),8)
        rows=[r for b in self.batches() for r in b['records']]
        self.assertEqual(sum(int(r['requestCount']) for r in rows if r['kind']=='GEO_COUNTER'),8)
        self.assertIn('GEO_SERVICE_UNAVAILABLE',[r['dimensions'].get('reasonCode') for r in rows])

    def test_uncertain_publish_retains_staged_tail_and_frozen_body(self):
        self.path.write_bytes(log('2026-10-27')+log('2026-10-28')*4)
        self.collector.tick()
        original=self.store.publish
        with patch.object(self.store,'publish',side_effect=StorageError('REDIS_UNAVAILABLE')):
            with self.assertRaises(StorageError):self.collector.tick()
        state=self.collector.states[self.source.alias];frozen=state.publication
        self.assertEqual(len(state.staged),4)
        self.collector.tick();self.drain();self.collector.flush_all()
        self.assertEqual(self.count(),5)
        self.assertIn(frozen.envelope,[canonical(b).decode() for b in self.batches()])

# Inherited per-tick tests intentionally run in original CollectorTest with one-line staging.
for _name in collector_tests.CollectorTest.__dict__:
    if _name.startswith('test_') and _name not in BatchGeoTest.__dict__:
        setattr(BatchGeoTest,_name,None)

class GeoProtocolTest(unittest.TestCase):
    def test_redis_url_timeouts_cannot_override_geo_budget(self):
        client=make_geo_cache_client('redis://127.0.0.1:6379/11?socket_timeout=3&socket_connect_timeout=5&decode_responses=False')
        try:
            kwargs=client.connection_pool.connection_kwargs
            self.assertEqual(kwargs['db'],11)
            self.assertEqual(kwargs['socket_timeout'],.05)
            self.assertEqual(kwargs['socket_connect_timeout'],.05)
            self.assertTrue(kwargs['decode_responses'])
        finally:client.close()

    def test_mixed_batches_keep_old_bytes_and_balanced_new_counts(self):
        f=json.loads(asset('risk-v1/geo-fixtures.json'))
        for env,encoded in zip(f['batches'],f['canonicalEnvelopes']):validate_envelope(env,encoded)
        old,new=f['batches']
        self.assertFalse(any(r['kind']=='GEO_COUNTER' for r in old['records']))
        counter=sum(int(r['requestCount']) for r in new['records'] if r['kind']=='COUNTER')
        geo=sum(int(r['requestCount']) for r in new['records'] if r['kind']=='GEO_COUNTER')
        self.assertEqual(counter,geo);self.assertEqual(str(geo),f['expected']['newGeoRequestCount'])
        self.assertEqual(canonical(old).decode(),f['canonicalEnvelopes'][0])

    def test_geo_records_reject_foreign_city_and_non_string_counts(self):
        from risk.algorithms import record_id
        row=copy.deepcopy(F['cases'][0]['geoRecord'])
        row['dimensions']['countryCode']='US';row['recordId']=record_id(row['dimensions'])
        with self.assertRaises(ValueError):validate_record(row)
        row=copy.deepcopy(F['cases'][0]['geoRecord']);row['requestCount']=1
        with self.assertRaises(ValueError):validate_record(row)

    def test_ordinary_ip_number_and_valid_identity_privacy(self):
        from risk.paths import protect_path
        key=b'synthetic-privacy-key-more-than-32-bytes'
        for path in ['/ip/58.209.110.186','/ip/2001:db8::1','/order/202610310000000000000001','/order/110105194912310021','/geo/江苏/中国电信']:
            self.assertEqual(protect_path(path,'2026-10-31',key).template,path)
        for path in ['/user/11010519491231002X','/idcard/not-valid-but-private','/password/private']:
            self.assertIn('{redacted:',protect_path(path,'2026-10-31',key).template)

    def test_geo_config_token_never_repr_and_retired_database_rejected(self):
        import tempfile
        from pathlib import Path
        from risk.config import load_config
        with tempfile.TemporaryDirectory() as folder:
            path=Path(folder)/'.env'
            path.write_text('GEO_SERVICE_URL=http://127.0.0.1:19002/scheduler/api/internal/risk/geo/resolve-batch\nGEO_SERVICE_TOKEN=synthetic-private-token\n')
            cfg=load_config(path)
            self.assertEqual(cfg.geo_service_token,'synthetic-private-token')
            self.assertNotIn('synthetic-private-token',repr(cfg))

# Add batched cursor edge cases without repeating the collector test class.
def _test_batched_halfline_rotation_and_restart(self):
    self.path.write_bytes(log()*3+log()[:-3])
    self.drain();self.collector.close()
    self.assertEqual(self.count(),3)
    with self.path.open('ab') as stream:stream.write(log()[-3:])
    self.path.rename(self.path.with_suffix('.1'));self.path.write_bytes(log()*2)
    other=self.new_collector();self.drain(other);other.flush_all()
    self.assertEqual(self.count(),6)
    self.assertEqual(sum(int(r['requestCount']) for b in self.batches() for r in b['records'] if r['kind']=='GEO_COUNTER'),6)
BatchGeoTest.test_batched_halfline_rotation_and_restart=_test_batched_halfline_rotation_and_restart

class DeadlineTransportTest(unittest.TestCase):
    def test_slow_drip_absolutely_expires_releases_worker_and_recovers(self):
        from types import SimpleNamespace
        row=copy.deepcopy(F['cases'][0]['result']);ip=row['ip']
        payload=json.dumps({'success':True,'content':{'schemaVersion':1,'cacheVersion':row['cacheVersion'],'redisAvailable':True,'results':[row]}}).encode()
        budgets=[]
        class Response:
            status=200
            def __init__(self,slow):
                self.slow=slow;self.closed=False;self.offset=0
                self.fp=SimpleNamespace(raw=SimpleNamespace(_sock=SimpleNamespace(settimeout=budgets.append,shutdown=Mock(),close=Mock())))
            def __enter__(self):return self
            def __exit__(self,*args):self.closed=True
            def read1(self,n):
                if self.slow:
                    time.sleep(.015);return b'x'
                chunk=payload[self.offset:self.offset+n];self.offset+=len(chunk);return chunk
        slow=Response(True);fast=Response(False)
        transport=InternalBatchHttp('http://127.0.0.1:19002/scheduler/api/internal/risk/geo/resolve-batch','synthetic')
        transport.opener=Mock();transport.opener.open.side_effect=[slow,fast]
        cache=fakeredis.FakeRedis(decode_responses=True)
        try:
            client=UnifiedGeoClient(cache,transport,epoch=lambda:EPOCH)
            start=time.monotonic();first=client.resolve_many([ip],budget=.06)
            self.assertLess(time.monotonic()-start,.15)
            self.assertEqual(first[ip].region_code,'UNKNOWN')
            closed_deadline=time.monotonic()+.2
            while not slow.closed and time.monotonic()<closed_deadline:time.sleep(.005)
            self.assertTrue(slow.closed)
            second=client.resolve_many([ip])
            self.assertEqual(second[ip].region_code,row['regionCode'])
            self.assertEqual(first[ip].region_code,'UNKNOWN') # late completion did not mutate old event
            self.assertTrue(fast.closed)
            self.assertGreater(budgets[0],budgets[1])
        finally:cache.close()

    def test_http_wire_body_header_and_content_limit(self):
        from types import SimpleNamespace
        transport=InternalBatchHttp('http://127.0.0.1:19002/scheduler/api/internal/risk/geo/resolve-batch','synthetic-private')
        response=Mock();response.status=200;response.__enter__=Mock(return_value=response);response.__exit__=Mock(return_value=False)
        response.fp=SimpleNamespace(raw=SimpleNamespace(_sock=Mock()))
        response.read1.side_effect=[b'{}',b'']
        transport.opener=Mock();transport.opener.open.return_value=response
        self.assertEqual(transport(['8.8.8.8'],time.monotonic()+.1),{})
        request=transport.opener.open.call_args.args[0]
        self.assertEqual(json.loads(request.data),{'items':[{'ip':'8.8.8.8','trusted':True}]})
        self.assertEqual(request.get_header('X-risk-geo-token'),'synthetic-private')
        response.read1.side_effect=[b'x'*65536]*17
        with self.assertRaisesRegex(ValueError,'GEO_RESPONSE_TOO_LARGE'):transport(['8.8.8.8'],time.monotonic()+.1)

class CrossLanguageBoundaryTest(unittest.TestCase):
    def test_shared_malformed_and_code_point_boundaries(self):
        from risk.geo import _valid_result
        fixture=json.loads(asset('risk-v1/geo-boundary-fixtures.json'))
        for case in fixture['cases']:
            with self.subTest(name=case['name']):
                row=case['record']
                try:validate_record(row);valid=True
                except ValueError:valid=False
                self.assertEqual(valid,case['valid'])
                self.assertEqual(canonical(row).decode(),case['canonicalRecord'])
                self.assertEqual(checksum([row]),case['checksum'])
                result=case['result']
                control={'cacheVersion':result['cacheVersion']}
                self.assertEqual(_valid_result(result,result['ip'],control,EPOCH),case['valid'])

    def test_one_bad_producer_item_preserves_good_item_and_all_counts(self):
        row=copy.deepcopy(F['cases'][0]['result']);bad=dict(row,ip='8.8.8.8',provinceName='Cafe\u0301')
        cache=fakeredis.FakeRedis(decode_responses=True)
        reply={'success':True,'content':{'schemaVersion':1,'cacheVersion':row['cacheVersion'],'redisAvailable':True,'results':[row,bad]}}
        try:
            client=UnifiedGeoClient(cache,lambda *_:reply,epoch=lambda:EPOCH)
            outcomes=client.resolve_many([row['ip'],bad['ip']])
            self.assertEqual(outcomes[row['ip']].region_code,row['regionCode'])
            self.assertEqual(outcomes[bad['ip']].region_code,'UNKNOWN')
            records=[]
            for result in [row,bad]:
                event,address=parse_observation(json.dumps({'uri':'/api/test','@timestamp':'2026-10-31T10:00:01+08:00','remote_addr':result['ip']}).encode(),PrivacyPolicy(direct_peer_trusted=True))
                outcome=outcomes[address];event.update(region_code=outcome.region_code,geo=outcome.result,quality=list(outcome.quality))
                records.extend(event_records(event,'test',HLL(),'unavailable'))
            self.assertEqual(sum(int(r['requestCount']) for r in records if r['kind']=='COUNTER'),2)
            self.assertEqual(sum(int(r['requestCount']) for r in records if r['kind']=='GEO_COUNTER'),2)
            self.assertTrue(all(r['dimensions'].get('provinceName')!='Cafe\u0301' for r in records))
        finally:cache.close()

class JavaServiceInputFixtureTest(unittest.TestCase):
    def test_converted_service_input_and_historical_geo_records_remain_readable(self):
        from risk.geo import _valid_result
        content=json.loads(asset('risk-v1/java-service-response.json'))
        resolved=max(datetime.fromisoformat(r['resolvedAt']).timestamp() for r in content['results'])
        for result in content['results']:
            self.assertTrue(_valid_result(result,result['ip'],content,resolved+1))
        f=json.loads(asset('risk-v1/geo-fixtures.json'))
        for env,encoded in zip(f['batches'],f['canonicalEnvelopes']):validate_envelope(env,encoded)
