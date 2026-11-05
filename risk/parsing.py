"""Strict log parsing with trusted canonical source IP and protected paths."""
from dataclasses import dataclass
from datetime import datetime
from decimal import Decimal
import ipaddress
import json
import re
from zoneinfo import ZoneInfo
from .ip_address import canonical_ip, public_ip
from .paths import protect_path, validate_template

SHANGHAI = ZoneInfo('Asia/Shanghai')
REASONS = frozenset({'INVALID_JSON', 'INVALID_TIME', 'INVALID_NUMBER', 'UNMATCHED_PATH', 'UNTRUSTED_IP', 'SOURCE_TRUNCATED'})


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


class PrivacyPolicy:
    def __init__(self, rules=(), trusted_proxies=(), direct_peer_trusted=False):
        self.rules = [(re.compile(rule.pattern), rule.template) for rule in rules]
        for _, template in self.rules:
            validate_template(template)
        self.networks = tuple(ipaddress.ip_network(value) for value in trusted_proxies)
        self.direct_peer_trusted = direct_peer_trusted

    def protected_path(self, value, business_date):
        return protect_path(value, business_date, self.rules)

    def path(self, value, business_date='1970-01-01'):
        result = self.protected_path(value, business_date)
        return result.template, result.request_type

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
            return canonical_ip(address.compressed.lower())
        except (ValueError, TypeError):
            return None

    def region(self, address):
        if address is None:
            return 'UNKNOWN'
        return 'UNKNOWN' if public_ip(address) else 'INTERNAL'


def parse_observation(raw, policy):
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
        status = data.get('status')
        if type(status) is int or (isinstance(status, str) and re.fullmatch(r'(?:0|[1-5][0-9]{2})', status)):
            status = int(status)
            if status != 0 and not 100 <= status <= 599:
                status = 0
                quality.add('INVALID_NUMBER')
        else:
            if status not in (None, '-'):
                quality.add('INVALID_NUMBER')
            status = 0
        protected = policy.protected_path(data.get('uri'), instant.date().isoformat())
        template, kind = protected.template, protected.request_type
        quality.update(protected.quality)
        method = data.get('request_method')
        method = method if method in {'GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'HEAD', 'OPTIONS', 'CONNECT', 'TRACE'} else 'UNKNOWN'
        address = policy.source(data.get('remote_addr'), data.get('http_x_forwarded_for'))
        region = policy.region(address)
        if address is None:
            quality.add('UNTRUSTED_IP')
        event = {'event_at': instant.isoformat(timespec='milliseconds'), 'business_date': instant.date().isoformat(),
                 'path_template': template, 'request_type': kind, 'method': method,
                 'status': status, 'region_code': region, 'source_ip': address}
        event['quality'] = sorted(quality)
        return event, address
    except Rejected:
        raise
    except (ValueError, TypeError):
        raise Rejected('INVALID_NUMBER') from None


def parse_event(raw, policy):
    """Offline parsing convenience without external lookup."""
    return parse_observation(raw, policy)[0]
