"""Strict input parsing; returned events contain no raw identifying fields."""
from dataclasses import dataclass
from datetime import datetime
from decimal import Decimal, InvalidOperation
import ipaddress
import json
import re
from zoneinfo import ZoneInfo
from .algorithms import micros, number

SHANGHAI = ZoneInfo('Asia/Shanghai')
REASONS = frozenset({'INVALID_JSON', 'INVALID_TIME', 'INVALID_NUMBER', 'UNMATCHED_PATH',
                     'UNTRUSTED_IP', 'GEO_UNAVAILABLE', 'HTTP_5XX', 'HTTP_4XX',
                     'CLIENT_ABORT', 'UPSTREAM_FAILURE', 'SOURCE_TRUNCATED', 'KEY_UNAVAILABLE'})


class Rejected(ValueError):
    """Only a fixed safe reason may cross the ingestion boundary."""
    def __init__(self, reason):
        self.reason = reason if reason in REASONS else 'INVALID_JSON'
        super().__init__(self.reason)


def _pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError('INVALID_JSON')
        result[key] = value
    return result


def strict_json(raw):
    try:
        text = raw.decode('utf-8', errors='strict')
    except UnicodeDecodeError:
        raise Rejected('INVALID_JSON') from None
    try:
        value = json.loads(text, parse_float=Decimal, parse_int=int,
                           parse_constant=lambda _: (_ for _ in ()).throw(ValueError()), object_pairs_hook=_pairs)
    except (ValueError, RecursionError):
        raise Rejected('INVALID_JSON') from None
    if not isinstance(value, dict):
        raise Rejected('INVALID_JSON')
    return value


@dataclass(frozen=True)
class PathRule:
    pattern: str
    template: str
    request_type: str


class PrivacyPolicy:
    def __init__(self, rules=(), trusted_proxies=(), direct_peer_trusted=False, geo=None):
        self.rules = [(re.compile(rule.pattern), rule.template, rule.request_type) for rule in rules]
        if any(not isinstance(template, str) or len(template) > 512 or not re.fullmatch(r'(/[A-Za-z0-9_/{}/:.*-]*|UNMATCHED)', template) for _, template, _ in self.rules):
            raise ValueError('INVALID_TEMPLATE')
        if any(kind not in {'API', 'STATIC', 'PAGE', 'SSE', 'RISK_INTERNAL', 'OTHER'} for _, _, kind in self.rules):
            raise ValueError('INVALID_RULE')
        self.networks = tuple(ipaddress.ip_network(value) for value in trusted_proxies)
        self.direct_peer_trusted = direct_peer_trusted
        self.geo = geo

    def path(self, value):
        if not isinstance(value, str):
            return 'UNMATCHED', 'OTHER'
        path = value.partition('?')[0]
        if re.fullmatch(r'/(?:stock/)?admin/api/risk(?:/.*)?', path):
            return '/admin/api/risk/{endpoint}', 'RISK_INTERNAL'
        # Internal rules have priority regardless of configuration order.
        for pattern, template, kind in sorted(self.rules, key=lambda rule: rule[2] != 'RISK_INTERNAL'):
            if pattern.fullmatch(path):
                return template, kind
        return 'UNMATCHED', 'OTHER'

    def source(self, peer, forwarded=None):
        if not self.direct_peer_trusted and not self.networks:
            return None
        try:
            address = ipaddress.ip_address(peer)
            if self.networks and any(address in network for network in self.networks):
                if forwarded:
                    if not isinstance(forwarded, str):
                        return None
                    chain = [ipaddress.ip_address(item.strip()) for item in forwarded.split(',')]
                    for candidate in reversed(chain):
                        address = candidate
                        if not any(candidate in network for network in self.networks):
                            break
            elif not self.direct_peer_trusted:
                return None
            return address.compressed.lower()
        except (ValueError, TypeError):
            return None

    def region(self, address):
        if address is None:
            return 'UNKNOWN'
        parsed = ipaddress.ip_address(address)
        if parsed.is_private or parsed.is_loopback or parsed.is_link_local:
            return 'INTERNAL'
        if self.geo is None:
            return 'UNKNOWN'
        try:
            result = self.geo(address)
            return result if isinstance(result, str) and re.fullmatch(r'(?:[A-Z]{2}|CN-[A-Z0-9]{2})', result) else 'UNKNOWN'
        except Exception:
            return 'UNKNOWN'


def ua_class(value):
    if not isinstance(value, str) or not value:
        return 'UNKNOWN'
    lowered = value.lower()
    if any(token in lowered for token in ('bot', 'spider', 'crawler')):
        return 'BOT'
    return 'MOBILE' if any(token in lowered for token in ('mobile', 'android', 'iphone')) else 'DESKTOP'


def _integer(value):
    parsed = number(value)
    if parsed is None:
        return None
    if parsed != parsed.to_integral_value():
        raise ValueError('INVALID_NUMBER')
    return int(parsed)


def parse_event(raw, policy, hll=None, hmac_key=None):
    data = strict_json(raw)
    try:
        timestamp = data.get('@timestamp', data.get('time_iso8601'))
        if not isinstance(timestamp, str):
            raise Rejected('INVALID_TIME')
        try:
            instant = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
            if instant.tzinfo is None:
                raise ValueError()
            instant = instant.astimezone(SHANGHAI)
            if '@timestamp' in data and 'time_iso8601' in data:
                alternate = data['time_iso8601']
                if not isinstance(alternate, str):
                    raise ValueError()
                alternate_instant = datetime.fromisoformat(alternate.replace('Z', '+00:00'))
                if alternate_instant.tzinfo is None or alternate_instant != instant:
                    raise ValueError()
        except (ValueError, OverflowError):
            raise Rejected('INVALID_TIME') from None
        quality = set()
        def numeric(value, convert):
            try:
                return convert(value)
            except (ValueError, TypeError, InvalidOperation):
                quality.add('INVALID_NUMBER')
                return None
        status = numeric(data.get('status'), _integer)
        if status is not None and not 100 <= status <= 599:
            status = None
            quality.add('INVALID_NUMBER')
        template, kind = policy.path(data.get('uri'))
        method = data.get('request_method')
        method = method if method in {'GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'HEAD', 'OPTIONS', 'CONNECT', 'TRACE'} else 'UNKNOWN'
        address = policy.source(data.get('remote_addr'), data.get('http_x_forwarded_for'))
        region = policy.region(address)
        if template == 'UNMATCHED':
            quality.add('UNMATCHED_PATH')
        if address is None:
            quality.add('UNTRUSTED_IP')
        elif region == 'UNKNOWN':
            quality.add('GEO_UNAVAILABLE')
        if address is not None and not hmac_key:
            quality.add('KEY_UNAVAILABLE')
        event = {'event_at': instant.isoformat(timespec='milliseconds'), 'business_date': instant.date().isoformat(),
                 'path_template': template, 'request_type': kind, 'method': method,
                 'status': status, 'bytes_sent': numeric(data.get('body_bytes_sent'), _integer),
                 'duration_micros': numeric(data.get('request_time'), micros), 'region_code': region,
                 'ua_class': ua_class(data.get('http_user_agent')), 'upstream_failure_count': 0}
        upstream = data.get('upstream_status')
        if upstream not in (None, '-'):
            if not isinstance(upstream, (str, int)) or isinstance(upstream, bool):
                quality.add('INVALID_NUMBER')
            else:
                tokens = re.split(r'\s*[:,]\s*', str(upstream).strip())
                if any(not re.fullmatch(r'[1-5][0-9]{2}|-', token) for token in tokens):
                    quality.add('INVALID_NUMBER')
                else:
                    event['upstream_failure_count'] = sum(token != '-' and int(token) >= 500 for token in tokens)
        # Update HLL only after every field passes validation; address never escapes.
        if address is not None and hll is not None and hmac_key:
            hll.add(hmac_key, event['business_date'], address)
        event['quality'] = sorted(quality)
        return event
    except Rejected:
        raise
    except (ValueError, TypeError, InvalidOperation):
        raise Rejected('INVALID_NUMBER') from None
