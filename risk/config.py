"""Explicit local configuration. Secrets never appear in diagnostics."""
from dataclasses import dataclass, field
from pathlib import Path
import re
import json
import shlex
from urllib.parse import quote
import ipaddress
from .parsing import PathRule, PrivacyPolicy, strict_json


@dataclass(frozen=True)
class SourceConfig:
    alias: str
    path: Path


@dataclass(frozen=True)
class Config:
    sources: tuple[SourceConfig, ...]
    privacy: PrivacyPolicy
    max_line_bytes: int
    redis_url: str | None = field(default=None, repr=False)
    hmac_key: str | None = field(default=None, repr=False)
    geo_database: Path | None = None
    poll_millis: int = 200


def _local_path(value):
    if value is None:
        return None
    if not isinstance(value, str) or not Path(value).is_absolute():
        raise ValueError('PATH_MUST_BE_ABSOLUTE')
    return Path(value)


_ENV_FIELDS = {
    'RISK_SOURCES': ('sources', True),
    'RISK_REDIS_URL': ('redisUrl', False),
    'RISK_GEO_DATABASE': ('geoDatabase', False),
    'RISK_PATH_RULES': ('pathRules', True),
    'RISK_TRUSTED_PROXIES': ('trustedProxies', True),
    'RISK_DIRECT_PEER_TRUSTED': ('directPeerTrusted', True),
    'RISK_MAX_LINE_BYTES': ('maxLineBytes', True),
    'RISK_POLL_MILLIS': ('pollMillis', True),
    'HMAC_KEY': ('hmacKey', False),
    'GEO_DATABASE': ('geoDatabase', False),
    'PATH_RULES': ('pathRules', True),
    'DIRECT_PEER_TRUSTED': ('directPeerTrusted', True),
    'MAX_LINE_BYTES': ('maxLineBytes', True),
    'POLL_MILLIS': ('pollMillis', True),
}


_FLAT_FIELDS = frozenset({'REDIS_URL', 'REDIS_PASSWORD', 'REDIS_USERNAME', 'REDIS_PORT', 'REDIS_DB',
                          'SOURCE_ID', 'SOURCE_LOG_PATH', 'TRUSTED_PROXIES'})
_REDIS_FIELDS = frozenset({'REDIS_URL', 'REDIS_PASSWORD', 'REDIS_USERNAME', 'REDIS_PORT', 'REDIS_DB'})


def _flat_redis(values):
    host = values.get('REDIS_URL', '')
    if not host:
        raise ValueError()
    if ':' in host:
        if host.startswith('[') and host.endswith(']'):
            host = host[1:-1]
        host = '[' + str(ipaddress.IPv6Address(host)) + ']'
    elif not re.fullmatch(r'[A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?', host):
        raise ValueError()
    port, database = values.get('REDIS_PORT', '6379'), values.get('REDIS_DB', '2')
    if not re.fullmatch(r'[0-9]+', port) or not 1 <= int(port) <= 65535 or not re.fullmatch(r'[0-9]+', database):
        raise ValueError()
    username, password = values.get('REDIS_USERNAME', ''), values.get('REDIS_PASSWORD', '')
    auth = quote(username, safe='') + ':' + quote(password, safe='') + '@' if username or password else ''
    return 'redis://' + auth + host + ':' + str(int(port)) + '/' + str(int(database))


def _env_config(raw):
    """Read single-line assignments only; never execute shell or expand variables."""
    result, seen, flat = {}, set(), {}
    try:
        for line in raw.decode('utf-8', errors='strict').splitlines():
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            name, separator, literal = line.partition('=')
            name = name.strip()
            if not separator or name not in (_ENV_FIELDS.keys() | _FLAT_FIELDS) or name in seen:
                raise ValueError()
            seen.add(name)
            parts = shlex.split(literal.strip(), comments=True, posix=True)
            if len(parts) > 1:
                raise ValueError()
            text = parts[0] if parts else ''
            if name in _FLAT_FIELDS:
                flat[name] = text
            else:
                field_name, structured = _ENV_FIELDS[name]
                if field_name in result:
                    raise ValueError()
                result[field_name] = json.loads(text) if structured else (text or None)
        if _REDIS_FIELDS & flat.keys():
            if 'redisUrl' in result:
                raise ValueError()
            result['redisUrl'] = _flat_redis(flat)
        if flat.get('SOURCE_LOG_PATH'):
            if 'sources' in result:
                raise ValueError()
            result['sources'] = [{'alias': flat.get('SOURCE_ID', 'nginx_access'), 'path': flat['SOURCE_LOG_PATH']}]
        if 'TRUSTED_PROXIES' in flat:
            if 'trustedProxies' in result:
                raise ValueError()
            result['trustedProxies'] = [item.strip() for item in flat['TRUSTED_PROXIES'].split(',') if item.strip()]
        return result
    except (ValueError, UnicodeError):
        # Parsing exceptions often contain the literal secret; expose no original context.
        raise ValueError('INVALID_ENV_CONFIG') from None


def load_config(path):
    file = Path(path)
    raw = file.read_bytes()
    value = _env_config(raw) if file.name.startswith('.env') or file.suffix == '.env' else strict_json(raw)
    if set(value) - {'sources', 'pathRules', 'trustedProxies', 'directPeerTrusted', 'maxLineBytes',
                     'redisUrl', 'hmacKey', 'geoDatabase', 'pollMillis'}:
        raise ValueError('UNKNOWN_CONFIG_FIELD')
    sources = []
    entries = value.get('sources', [])
    if not isinstance(entries, list):
        raise ValueError('INVALID_SOURCE_CONFIG')
    for item in entries:
        if not isinstance(item, dict) or set(item) != {'alias', 'path'}:
            raise ValueError('INVALID_SOURCE_CONFIG')
        alias, filename = item['alias'], item['path']
        if not isinstance(alias, str) or not re.fullmatch(r'[A-Za-z0-9_-]{1,80}', alias):
            raise ValueError('INVALID_SOURCE_ALIAS')
        filename = _local_path(filename)
        if filename is None:
            raise ValueError('SOURCE_PATH_MUST_BE_ABSOLUTE')
        sources.append(SourceConfig(alias, filename))
    if len({source.alias for source in sources}) != len(sources) or len({source.path.resolve() for source in sources}) != len(sources):
        raise ValueError('DUPLICATE_SOURCE')
    identities = []
    for source in sources:
        if source.path.is_file():
            stat = source.path.stat()
            identities.append((stat.st_dev, stat.st_ino))
    if len(set(identities)) != len(identities):
        raise ValueError('DUPLICATE_SOURCE')
    direct = value.get('directPeerTrusted', False)
    limit = value.get('maxLineBytes', 65536)
    poll = value.get('pollMillis', 200)
    if type(direct) is not bool or type(limit) is not int or not 1 <= limit <= 1048576 or type(poll) is not int or not 10 <= poll <= 10000:
        raise ValueError('INVALID_CONFIG_VALUE')
    rules = []
    entries = value.get('pathRules', [])
    if not isinstance(entries, list):
        raise ValueError('INVALID_PATH_RULE')
    for item in entries:
        if not isinstance(item, dict) or set(item) != {'pattern', 'template', 'requestType'} or not all(isinstance(entry, str) for entry in item.values()):
            raise ValueError('INVALID_PATH_RULE')
        rules.append(PathRule(item['pattern'], item['template'], item['requestType']))
    proxies = value.get('trustedProxies', [])
    if not isinstance(proxies, list) or not all(isinstance(entry, str) for entry in proxies):
        raise ValueError('INVALID_TRUSTED_PROXY_CONFIG')
    redis_url = value.get('redisUrl')
    if redis_url is not None and (not isinstance(redis_url, str) or not redis_url.startswith(('redis://', 'rediss://', 'unix://'))):
        raise ValueError('INVALID_REDIS_CONFIG')
    hmac_key = value.get('hmacKey')
    if hmac_key is not None:
        if not isinstance(hmac_key, str):
            raise ValueError('INVALID_HMAC_KEY')
        if not hmac_key:
            hmac_key = None
        else:
            try:
                if len(hmac_key.encode('utf-8')) < 32:
                    raise ValueError()
            except (ValueError, UnicodeError):
                raise ValueError('INVALID_HMAC_KEY') from None
    return Config(tuple(sources), PrivacyPolicy(rules, proxies, direct), limit, redis_url,
                  hmac_key, _local_path(value.get('geoDatabase')), poll)
