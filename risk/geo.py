"""Read-only unified Java GeoIP consumer. Never calls providers or writes Geo cache."""
from dataclasses import dataclass
from datetime import datetime
import ipaddress
import json
import re
import threading
import time
from urllib.parse import urlsplit
from urllib.request import Request, build_opener, HTTPRedirectHandler, ProxyHandler

from jsonschema import Draft202012Validator
from .ip_address import canonical_ip, public_ip
from .parsing import strict_json
from .protocol import asset
from .geo_dimensions import valid_geo_dimensions

_RESULT = Draft202012Validator(json.loads(asset('geoip-v1/result.schema.json')))
_CONTROL = Draft202012Validator(json.loads(asset('geoip-v1/control.schema.json')))

BUDGET_SECONDS = 0.300
MAX_IPS = 100
MAX_REPLY = 1048576
GEO_QUALITY = frozenset({'GEO_LOCAL_DEGRADED','GEO_SERVICE_UNAVAILABLE','GEO_VERSION_STALE','GEO_CODE_CONFLICT'})

@dataclass(frozen=True)
class GeoOutcome:
    region_code: str = 'UNKNOWN'
    quality: tuple[str, ...] = ('GEO_SERVICE_UNAVAILABLE',)
    result: dict | None = None


def fallback_outcome(address):
    if address is None:
        return GeoOutcome('UNKNOWN', ('UNTRUSTED_IP',), {'resultStatus':'UNKNOWN'})
    if not public_ip(address):
        return GeoOutcome('INTERNAL', (), {'resultStatus':'NON_PUBLIC_IP'})
    return GeoOutcome(result={'resultStatus':'PROVIDER_UNAVAILABLE'})


def _time(value):
    if not re.fullmatch(r'\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}\+08:00',value):
        raise ValueError('INVALID_GEO_TIME')
    instant = datetime.fromisoformat(value)
    if instant.tzinfo is None:
        raise ValueError('INVALID_GEO_TIME')
    return instant.timestamp()


def _control(value):
    return _CONTROL.is_valid(value) and all(isinstance(value.get(k), str) and value[k] for k in ('cacheVersion','providerSetVersion'))


def _valid_result(result, address, control, now):
    # Java owns administrative validation. Here only validate the frozen wire and cache binding.
    if not _RESULT.is_valid(result):
        return False
    if result['ip'] != address or result['ipVersion'] != ipaddress.ip_address(address).version:
        return False
    if not re.fullmatch(r'(?:[A-Z]{2}|CN-[0-9]{2}|UNKNOWN|INTERNAL)',result['regionCode']):
        return False
    if result['cacheVersion'] != control['cacheVersion']:
        return False
    if _time(result['expiresAt']) <= now or _time(result['resolvedAt']) > now or _time(result['resolvedAt']) > _time(result['expiresAt']):
        return False
    dimensions = {key: result[key] or '' for key in ('countryCode','provinceCode','provinceName','cityCode','cityName')}
    dimensions['locationLevel'] = result['locationLevel']
    if not valid_geo_dimensions(dimensions):
        return False
    if result['countryCode'] != 'CN' and result['cityGeoNameId'] is not None:
        return False
    return True


def _outcome(result):
    quality=set()
    if result['resultStatus']=='CONFLICT': quality.add('GEO_CODE_CONFLICT')
    if result['resultStatus']=='PROVIDER_UNAVAILABLE': quality.add('GEO_SERVICE_UNAVAILABLE')
    if result.get('errorCode') in GEO_QUALITY: quality.add(result['errorCode'])
    if result['regionCode']=='UNKNOWN' and not quality: quality.add('GEO_UNAVAILABLE')
    return GeoOutcome(result['regionCode'],tuple(sorted(quality)),result)


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class InternalBatchHttp:
    def __init__(self, url, token):
        parsed=urlsplit(url or '')
        host=parsed.hostname
        if host=='localhost': host='127.0.0.1'
        try:
            address=ipaddress.ip_address(host)
            valid=not (address.is_multicast or address.is_unspecified or address.is_reserved)
        except (ValueError,TypeError):
            valid=False
        if not valid or parsed.scheme not in {'http','https'} or parsed.username or parsed.password or parsed.query or parsed.fragment or parsed.path not in {'/scheduler/api/internal/risk/geo/resolve-batch','/stock/scheduler/api/internal/risk/geo/resolve-batch'} or not isinstance(token,str) or not token.strip() or '\n' in token or '\r' in token:
            raise ValueError('INVALID_GEO_SERVICE_CONFIG')
        # A literal internal destination avoids unbounded DNS and environment proxy credential leaks.
        port=parsed.port or (443 if parsed.scheme=='https' else 80)
        host_text='['+str(address)+']' if address.version==6 else str(address)
        self.url=parsed.scheme+'://'+host_text+':'+str(port)+parsed.path
        self.token=token
        self.opener=build_opener(ProxyHandler({}),_NoRedirect())

    def __call__(self, addresses, deadline):
        remaining=deadline-time.monotonic()
        if remaining<=0: raise TimeoutError()
        body=json.dumps({'items':[{'ip':address,'trusted':True} for address in addresses]},separators=(',',':')).encode()
        req=Request(self.url,data=body,method='POST',headers={'Content-Type':'application/json','Accept':'application/json','Accept-Encoding':'identity','X-Risk-Geo-Token':self.token})
        with self.opener.open(req,timeout=remaining) as response:
            if response.status!=200: raise ValueError('GEO_HTTP_FAILED')
            sock=getattr(getattr(getattr(response,'fp',None),'raw',None),'_sock',None)
            if sock is None:raise ValueError('GEO_RESPONSE_SOCKET_UNAVAILABLE')
            def expire():
                try:
                    sock.shutdown(2)
                    sock.close()
                except OSError:
                    pass
            # Absolute shutdown also bounds chunk framing/trailers inside read1.
            timer=threading.Timer(max(0,deadline-time.monotonic()),expire)
            timer.daemon=True
            timer.start()
            try:
                chunks=[];size=0
                while True:
                    remaining=deadline-time.monotonic()
                    if remaining<=0:raise TimeoutError('GEO_DEADLINE')
                    sock.settimeout(remaining)
                    chunk=response.read1(min(65536,MAX_REPLY+1-size))
                    if time.monotonic()>=deadline:raise TimeoutError('GEO_DEADLINE')
                    if not chunk:break
                    size+=len(chunk)
                    if size>MAX_REPLY:raise ValueError('GEO_RESPONSE_TOO_LARGE')
                    chunks.append(chunk)
                payload=b''.join(chunks)
            finally:
                timer.cancel()
        return strict_json(payload)


def make_geo_cache_client(redis_url):
    import redis
    from redis.backoff import NoBackoff
    from redis.retry import Retry
    client=redis.Redis.from_url(redis_url,decode_responses=True,socket_timeout=0.05,socket_connect_timeout=0.05,
                                retry=Retry(NoBackoff(),0),retry_on_timeout=False)
    # redis-py URL options take precedence over kwargs. Preserve endpoint/auth/DB,
    # but enforce this reader's short budgets even for a URL containing timeout options.
    client.connection_pool.connection_kwargs.update(socket_timeout=.05,socket_connect_timeout=.05,
        retry=Retry(NoBackoff(),0),retry_on_timeout=False,retry_on_error=[],decode_responses=True)
    return client


class UnifiedGeoClient:
    def __init__(self, cache, transport=None, *, monotonic=time.monotonic, epoch=time.time):
        self.cache,self.transport=cache,transport
        self.monotonic,self.epoch=monotonic,epoch
        self._slot=threading.BoundedSemaphore(1)

    def resolve_many(self, addresses, budget=BUDGET_SECONDS):
        unique=list(dict.fromkeys(canonical_ip(value) if value is not None else None for value in addresses))
        if len(unique)>MAX_IPS: raise ValueError('GEO_BATCH_TOO_LARGE')
        if not unique:return {}
        eligible=[value for value in unique if value is not None and public_ip(value)]
        output={value:fallback_outcome(value) for value in unique if value not in eligible}
        output.update({value:fallback_outcome(value) for value in eligible})
        if budget<=0 or not self._slot.acquire(blocking=False):return output
        deadline=self.monotonic()+min(BUDGET_SECONDS,budget)
        done=threading.Event();holder={}
        def work():
            try:
                holder.update(self._resolve(unique,deadline))
            except Exception:
                pass  # No exception object/request/credential is logged or retained.
            finally:
                done.set();self._slot.release()
        threading.Thread(target=work,name='risk-geo-local-batch',daemon=True).start()
        if done.wait(max(0,deadline-self.monotonic())) and self.monotonic()<=deadline:
            output.update(holder)
        # A late result cannot write any already aggregated event; at most one worker may remain.
        return output

    def _resolve(self, addresses, deadline):
        all_addresses=addresses
        addresses=[a for a in all_addresses if a is not None and public_ip(a)]
        results={a:fallback_outcome(a) for a in all_addresses if a not in addresses}
        miss=list(addresses);stale=set()
        try:
            control=self.cache.hgetall('geoip:v1:control') if addresses else {}
            if _control(control) and self.monotonic()<deadline:
                payloads=self.cache.mget(['geoip:v1:result:'+control['cacheVersion']+':'+value for value in addresses])
                if self.cache.hgetall('geoip:v1:control')!=control:
                    raise ValueError('GEO_CONTROL_CHANGED')
                miss=[]
                for address,payload in zip(addresses,payloads):
                    try:
                        cached=strict_json(payload.encode()) if payload is not None else None
                        if not _valid_result(cached,address,control,self.epoch()):raise ValueError()
                        results[address]=_outcome(cached)
                    except Exception:
                        miss.append(address)
                        if payload is not None:stale.add(address)
        except Exception:
            results={};miss=list(addresses)
        if miss and self.transport is not None and self.monotonic()<deadline:
            try:
                reply=self.transport(miss,deadline)
                content=reply['content']
                if reply.get('success') is not True or (type(content.get('schemaVersion')) is not int or content['schemaVersion']!=1) or not isinstance(content.get('redisAvailable'),bool):raise ValueError()
                if set(content)!={'schemaVersion','cacheVersion','redisAvailable','results'} or not isinstance(content.get('cacheVersion'),str) or not content['cacheVersion']:raise ValueError()
                rows=content['results']
                if not isinstance(rows,list) or len(rows)!=len(miss):raise ValueError()
                found={}
                for row in rows:
                    address=row['ip']
                    if address not in miss or address in found:raise ValueError()
                    # One malformed producer item must not invalidate other trusted items.
                    try:
                        valid = _valid_result(row,address,content,self.epoch())
                    except (ValueError,TypeError,KeyError):
                        valid = False
                    found[address]=_outcome(row) if valid else fallback_outcome(address)
                results.update(found)
            except Exception:
                pass
        for address in stale:
            result=results.get(address,fallback_outcome(address))
            results[address]=GeoOutcome(result.region_code,tuple(sorted(set(result.quality)|{'GEO_VERSION_STALE'})),result.result)
        if self.monotonic()<deadline:
            try:
                from collections import Counter
                metrics=Counter(hits=len(addresses)-len(miss),misses=len(miss),stale=len(stale))
                for address in all_addresses:
                    outcome=results.get(address,fallback_outcome(address))
                    metrics['quality_total']+=1
                    metrics['level_'+(outcome.result or {}).get('locationLevel','UNKNOWN')]+=1
                    if outcome.region_code=='UNKNOWN':metrics['quality_unknown']+=1
                    if address is None:metrics['quality_untrusted']+=1
                    elif not public_ip(address):metrics['quality_nonPublic']+=1
                    for reason,field in [('GEO_SERVICE_UNAVAILABLE','serviceUnavailable'),('GEO_CODE_CONFLICT','conflicts'),('GEO_LOCAL_DEGRADED','localDegraded'),('GEO_VERSION_STALE','versionStale')]:
                        if reason in outcome.quality:metrics['quality_'+field]+=1
                pipe=self.cache.pipeline(transaction=False)
                for key,value in metrics.items():pipe.hincrby('geoip:v1:metrics:python',key,value)
                from .parsing import SHANGHAI
                pipe.hset('geoip:v1:metrics:python','reportedAt',datetime.now(SHANGHAI).isoformat(timespec='milliseconds'))
                pipe.execute()
            except Exception:
                pass
        return results
