"""Read per-target monitor configuration from Redis."""
from dataclasses import dataclass, field
from datetime import datetime
import ipaddress
import re
from redis.exceptions import RedisError

from .parsing import Rejected, strict_json

CONFIG_KEY = 'risk:monitor:targets'
INITIALIZED_FIELD = '@initialized'
COLLECTOR_RE = re.compile(r'^[A-Za-z0-9_-]{1,80}$')
TARGET_RE = re.compile(r'^[1-9][0-9]{0,18}$')
USER_RE = re.compile(r'^[A-Za-z_][A-Za-z0-9_.-]{0,31}$')
HOST_RE = re.compile(r'^(?=.{1,253}$)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)*[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$')


class MonitorConfigError(ValueError):
    def __init__(self, code='CONFIG_INVALID'):
        self.code = code
        super().__init__(code)


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
    password_ciphertext: str | None = field(repr=False)


@dataclass(frozen=True)
class MonitorTarget:
    target_id: str
    type: str
    enabled: bool
    collector_id: str
    interval_seconds: int
    connection: TargetConnection | None

    @property
    def local(self):
        return self.type == 'LOCAL'


@dataclass(frozen=True)
class MonitorConfig:
    initialized_time: str | None
    targets: tuple[MonitorTarget, ...] = ()

    @property
    def empty(self):
        return self.initialized_time is None

    def by_id(self):
        return {target.target_id: target for target in self.targets}

    def for_collector(self, collector_id, enabled_only=True):
        return tuple(target for target in self.targets
                     if target.collector_id == collector_id and (target.enabled or not enabled_only))


EMPTY_CONFIG = MonitorConfig(None)


@dataclass
class ConfigStatus:
    config: MonitorConfig | None = None
    stale: bool = False
    error: str | None = None


def _connection(value):
    if not isinstance(value, dict) or set(value) != {'host', 'port', 'username', 'passwordCiphertext'}:
        raise MonitorConfigError()
    host, port, username, ciphertext = value['host'], value['port'], value['username'], value['passwordCiphertext']
    if not _host(host) or type(port) is not int or not 1 <= port <= 65535:
        raise MonitorConfigError()
    if not isinstance(username, str) or not USER_RE.fullmatch(username):
        raise MonitorConfigError()
    if ciphertext is not None and (not isinstance(ciphertext, str) or not 1 <= len(ciphertext) <= 2048):
        raise MonitorConfigError()
    return TargetConnection(host, port, username, ciphertext)


def _target(value):
    if not isinstance(value, dict) or set(value) != {'targetId', 'type', 'enabled', 'collectorId',
                                                       'intervalSeconds', 'connection'}:
        raise MonitorConfigError()
    target_id, kind, enabled, collector_id = value['targetId'], value['type'], value['enabled'], value['collectorId']
    interval, connection = value['intervalSeconds'], value['connection']
    if not isinstance(target_id, str) or not TARGET_RE.fullmatch(target_id):
        raise MonitorConfigError()
    if len(target_id) == 19 and target_id > '9223372036854775807':
        raise MonitorConfigError()
    if kind not in ('LOCAL', 'REMOTE') or type(enabled) is not bool:
        raise MonitorConfigError()
    if not isinstance(collector_id, str) or not COLLECTOR_RE.fullmatch(collector_id):
        raise MonitorConfigError()
    if type(interval) is not int or not 1 <= interval <= 86400:
        raise MonitorConfigError()
    if kind == 'LOCAL':
        if connection is not None:
            raise MonitorConfigError()
        parsed_connection = None
    else:
        parsed_connection = _connection(connection)
    return MonitorTarget(target_id, kind, enabled, collector_id, interval, parsed_connection)


def parse_config(raw):
    if INITIALIZED_FIELD not in raw:
        raise MonitorConfigError('CONFIG_UNAVAILABLE')
    initialized = raw[INITIALIZED_FIELD]
    _time(initialized)
    targets = []
    for field, value in raw.items():
        if field == INITIALIZED_FIELD:
            continue
        if not isinstance(value, str):
            raise MonitorConfigError()
        try:
            target = _target(strict_json(value.encode('utf-8')))
        except (Rejected, UnicodeError):
            raise MonitorConfigError() from None
        if field != target.target_id or not target.enabled:
            raise MonitorConfigError()
        targets.append(target)
    return MonitorConfig(initialized, tuple(targets))


class MonitorConfigSync:
    """Poll target entries and retain the last good in-process configuration."""

    def __init__(self, client, poll_seconds=5):
        self.client = client
        self.status = ConfigStatus()
        self.poll_seconds = poll_seconds
        self.last_read_time = 0.0

    @property
    def current(self):
        return self.status.config or EMPTY_CONFIG

    def refresh(self, monotonic_now=None, force=False):
        if not force and monotonic_now is not None and monotonic_now - self.last_read_time < self.poll_seconds:
            return False
        if monotonic_now is not None:
            self.last_read_time = monotonic_now
        try:
            raw = self.client.hgetall(CONFIG_KEY)
        except RedisError:
            self.status.stale = True
            self.status.error = 'CONFIG_UNAVAILABLE'
            return False
        try:
            candidate = parse_config(raw)
        except MonitorConfigError as exc:
            self.status.stale = True
            self.status.error = exc.code
            return False
        previous = self.status.config
        self.status.config = candidate
        self.status.stale = False
        self.status.error = None
        return previous is None or candidate.by_id() != previous.by_id()
