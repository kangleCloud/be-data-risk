"""Versioned complete monitor configuration from Redis; no local configuration cache."""
from dataclasses import dataclass
from datetime import datetime
import ipaddress
import re
from redis.exceptions import RedisError

from .parsing import Rejected, strict_json, SHANGHAI

CONFIG_KEY = 'risk:monitor:config'
COLLECTOR_RE = re.compile(r'^[A-Za-z0-9_-]{1,80}$')
TARGET_RE = re.compile(r'^[1-9][0-9]{0,18}$')
SOURCE_RE = re.compile(r'^[A-Za-z0-9_-]{1,80}$')
VERSION_RE = re.compile(r'^(?:0|[1-9][0-9]{0,19})$')
USER_RE = re.compile(r'^[A-Za-z_][A-Za-z0-9_.-]{0,31}$')
ALIAS_RE = re.compile(r'^[A-Za-z0-9_.-]{1,80}$')
HOST_RE = re.compile(r'^(?=.{1,253}$)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)*[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$')
MAX_TARGETS = 1000


class MonitorConfigError(ValueError):
    def __init__(self, code='CONFIG_INVALID'):
        self.code = code
        super().__init__(code)


def decimal_compare(left, right):
    """Compare non-negative decimal strings without float conversion."""
    if not isinstance(left, str) or not isinstance(right, str) or not VERSION_RE.fullmatch(left) or not VERSION_RE.fullmatch(right):
        raise ValueError('INVALID_DECIMAL')
    if len(left) != len(right):
        return -1 if len(left) < len(right) else 1
    return (left > right) - (left < right)


def _time(value):
    if not isinstance(value, str) or len(value) > 40:
        raise MonitorConfigError()
    try:
        instant = datetime.fromisoformat(value)
    except ValueError:
        raise MonitorConfigError() from None
    if instant.tzinfo is None:
        raise MonitorConfigError()
    return instant


def _host(value):
    if not isinstance(value, str) or not value or value != value.strip():
        return False
    if value.startswith('-') or any(ord(char) < 33 or ord(char) > 126 for char in value):
        return False
    try:
        address = ipaddress.ip_address(value)
        return not (address.is_multicast or address.is_unspecified)
    except ValueError:
        return bool(HOST_RE.fullmatch(value))


@dataclass(frozen=True)
class TargetConnection:
    host: str
    port: int
    username: str
    credential_alias: str


@dataclass(frozen=True)
class MonitorTarget:
    target_id: str
    type: str
    enabled: bool
    collector_id: str
    interval_seconds: int
    connection: TargetConnection | None
    log_source_id: str | None

    @property
    def local(self):
        return self.type == 'LOCAL'


@dataclass(frozen=True)
class MonitorConfig:
    version: str | None
    payload: str | None
    published_at: str | None
    targets: tuple[MonitorTarget, ...] = ()
    generated_at: str | None = None

    @property
    def empty(self):
        return self.version is None and not self.targets

    def by_id(self):
        return {target.target_id: target for target in self.targets}

    def for_collector(self, collector_id, enabled_only=True):
        return tuple(target for target in self.targets
                     if target.collector_id == collector_id and (target.enabled or not enabled_only))


EMPTY_CONFIG = MonitorConfig(None, None, None, ())


@dataclass
class ConfigStatus:
    config: MonitorConfig | None = None
    loaded: bool = False
    stale: bool = False
    error: str | None = None
    conflict: bool = False


def _connection(value):
    if not isinstance(value, dict) or set(value) != {'host', 'port', 'username', 'credentialAlias'}:
        raise MonitorConfigError()
    host, port, username, alias = value['host'], value['port'], value['username'], value['credentialAlias']
    if not _host(host) or type(port) is not int or not 1 <= port <= 65535:
        raise MonitorConfigError()
    if not isinstance(username, str) or not USER_RE.fullmatch(username):
        raise MonitorConfigError()
    if not isinstance(alias, str) or not ALIAS_RE.fullmatch(alias):
        raise MonitorConfigError()
    return TargetConnection(host, port, username, alias)


def _target(value):
    if not isinstance(value, dict) or set(value) != {'targetId', 'type', 'enabled', 'collectorId',
                                                       'intervalSeconds', 'connection', 'logSourceId'}:
        raise MonitorConfigError()
    target_id, kind, enabled, collector_id = value['targetId'], value['type'], value['enabled'], value['collectorId']
    interval, connection, source = value['intervalSeconds'], value['connection'], value['logSourceId']
    if not isinstance(target_id, str) or not TARGET_RE.fullmatch(target_id):
        raise MonitorConfigError()
    if len(target_id) == 19 and target_id > '9223372036854775807':
        raise MonitorConfigError()
    if kind not in {'LOCAL', 'REMOTE'} or type(enabled) is not bool:
        raise MonitorConfigError()
    if not isinstance(collector_id, str) or not COLLECTOR_RE.fullmatch(collector_id):
        raise MonitorConfigError()
    if type(interval) is not int or not 1 <= interval <= 86400:
        raise MonitorConfigError()
    if kind == 'LOCAL':
        if connection is not None or (source is not None and (not isinstance(source, str) or not SOURCE_RE.fullmatch(source))):
            raise MonitorConfigError()
        parsed_connection = None
    else:
        if source is not None:
            raise MonitorConfigError()
        parsed_connection = _connection(connection)
    return MonitorTarget(target_id, kind, enabled, collector_id, interval, parsed_connection, source)


def parse_config(raw):
    if not raw:
        raise MonitorConfigError('CONFIG_UNAVAILABLE')
    if set(raw) != {'version', 'payload', 'publishedAt'}:
        raise MonitorConfigError()
    version, payload, published = raw['version'], raw['payload'], raw['publishedAt']
    if not isinstance(version, str) or not VERSION_RE.fullmatch(version):
        raise MonitorConfigError()
    if not isinstance(published, str):
        raise MonitorConfigError()
    _time(published)
    if not isinstance(payload, str) or payload == '':
        # A missing or empty payload is unavailable, not a valid empty snapshot.
        raise MonitorConfigError('CONFIG_UNAVAILABLE')
    try:
        value = strict_json(payload.encode('utf-8'))
    except (Rejected, UnicodeError):
        raise MonitorConfigError() from None
    if set(value) != {'schemaVersion', 'configVersion', 'generatedAt', 'targets'}:
        raise MonitorConfigError()
    if type(value['schemaVersion']) is not int or value['schemaVersion'] != 2:
        raise MonitorConfigError()
    if value['configVersion'] != version:
        raise MonitorConfigError()
    _time(value['generatedAt'])
    entries = value['targets']
    if not isinstance(entries, list) or len(entries) > MAX_TARGETS:
        raise MonitorConfigError()
    targets = tuple(_target(entry) for entry in entries)
    if len({target.target_id for target in targets}) != len(targets):
        raise MonitorConfigError()
    used = [target.log_source_id for target in targets if target.enabled and target.local and target.log_source_id is not None]
    if len(set(used)) != len(used):
        raise MonitorConfigError()
    return MonitorConfig(version, payload, published, targets, value['generatedAt'])


class MonitorConfigSync:
    """Read the complete snapshot periodically and retain the last good in-process value."""

    def __init__(self, client, clock=None, poll_seconds=5):
        self.client = client
        self.status = ConfigStatus()
        self.poll_seconds = poll_seconds
        self.clock = clock or (lambda: datetime.now(SHANGHAI).isoformat(timespec='milliseconds'))
        self.last_read_at = 0.0
        self.observed_version = None

    @property
    def current(self):
        return self.status.config or EMPTY_CONFIG

    def _now(self):
        return self.clock()

    def refresh(self, monotonic_now=None, force=False):
        if not force and monotonic_now is not None and monotonic_now - self.last_read_at < self.poll_seconds:
            return False
        python_now = monotonic_now
        self.last_read_at = python_now if python_now is not None else self.last_read_at
        try:
            raw = self.client.hgetall(CONFIG_KEY)
        except RedisError:
            self.status.stale = True
            self.status.error = 'CONFIG_UNAVAILABLE'
            self.status.conflict = False
            return False
        try:
            candidate = parse_config(raw)
        except MonitorConfigError as exc:
            self.status.stale = True
            self.status.error = exc.code
            self.status.conflict = False
            return False
        self.observed_version = candidate.version
        previous = self.status.config
        if previous is None:
            self.status.config = candidate
            self.status.loaded = True
            self.status.stale = False
            self.status.error = None
            self.status.conflict = False
            return True
        order = decimal_compare(candidate.version, previous.version)
        if order < 0:
            self.status.stale = True
            self.status.error = 'CONFIG_VERSION_OUTDATED'
            self.status.conflict = False
            return False
        if order == 0:
            if candidate.payload != previous.payload:
                self.status.stale = True
                self.status.error = 'CONFIG_VERSION_CONFLICT'
                self.status.conflict = True
                return False
            self.status.stale = False
            self.status.error = None
            self.status.conflict = False
            return False
        self.status.config = candidate
        self.status.loaded = True
        self.status.stale = False
        self.status.error = None
        self.status.conflict = False
        return True
