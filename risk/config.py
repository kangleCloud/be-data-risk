"""Explicit local configuration. Secrets never appear in diagnostics."""
from dataclasses import dataclass, field
from pathlib import Path
import re
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
    hmac_key_file: Path | None = field(default=None, repr=False)
    geo_database: Path | None = None
    poll_millis: int = 200


def _local_path(value):
    if value is None:
        return None
    if not isinstance(value, str) or not Path(value).is_absolute():
        raise ValueError('PATH_MUST_BE_ABSOLUTE')
    return Path(value)


def load_config(path):
    value = strict_json(Path(path).read_bytes())
    if set(value) - {'sources', 'pathRules', 'trustedProxies', 'directPeerTrusted', 'maxLineBytes',
                     'redisUrl', 'hmacKeyFile', 'geoDatabase', 'pollMillis'}:
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
    return Config(tuple(sources), PrivacyPolicy(rules, proxies, direct), limit, redis_url,
                  _local_path(value.get('hmacKeyFile')), _local_path(value.get('geoDatabase')), poll)
