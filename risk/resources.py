"""Bounded local/remote resource sampling and atomic Redis delivery."""
from dataclasses import dataclass
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from decimal import Decimal, InvalidOperation
import json
import os
import re
import time

from jsonschema import Draft202012Validator, FormatChecker
from redis.exceptions import RedisError

from .algorithms import canonical
from .parsing import SHANGHAI
from .protocol import asset
from .storage import StorageError

RESOURCE_PREFIX = 'risk:monitor:resource:'
MAX_REMOTE_OUTPUT = 524288
REMOTE_PROBE_COMMAND = (
    "for f in /proc/stat /proc/meminfo /proc/net/dev /proc/loadavg /proc/uptime "
    "/proc/sys/kernel/random/boot_id; do printf '### %s\\n' \"$f\"; cat \"$f\"; done; "
    "printf '### df\\n'; df -Pk / 2>/dev/null"
)
UNAVAILABLE_REASONS = frozenset({
    'CPU_FIRST_SAMPLE', 'CPU_COUNTER_RESET', 'MEMORY_UNAVAILABLE', 'DISK_UNAVAILABLE',
    'NETWORK_FIRST_SAMPLE', 'NETWORK_COUNTER_RESET', 'MACHINE_RESTART', 'LOAD_UNAVAILABLE',
    'UPTIME_UNAVAILABLE', 'NOT_SUPPORTED', 'SSH_BINDING_UNAVAILABLE', 'SSH_KEY_UNAVAILABLE',
    'SSH_KEY_PERMISSIONS', 'SSH_KNOWN_HOSTS_UNAVAILABLE', 'SSH_HOST_KEY_MISMATCH',
    'SSH_CONNECT_TIMEOUT', 'SSH_COMMAND_TIMEOUT', 'SSH_CONNECTION_FAILED',
    'SSH_OUTPUT_TOO_LARGE', 'SAMPLE_TIMEOUT', 'SSHPASS_UNAVAILABLE',
    'SSH_AUTH_REJECTED', 'SSH_HOST_KEY_UNKNOWN', 'SSH_HOST_KEY_VERIFICATION_FAILED',
    'SSH_NETWORK_FAILED',
})
_SAMPLE_VALIDATOR = Draft202012Validator(
    json.loads(asset('monitor/resource-sample.schema.json')), format_checker=FormatChecker())


class ProbeFailure(RuntimeError):
    def __init__(self, code):
        self.code = code if code in UNAVAILABLE_REASONS else 'NOT_SUPPORTED'
        super().__init__(self.code)


@dataclass(frozen=True)
class MetricsSnapshot:
    cpu_total: int | None = None
    cpu_idle: int | None = None
    memory_used: int | None = None
    memory_total: int | None = None
    disk_used: int | None = None
    disk_total: int | None = None
    net_receive: int | None = None
    net_transmit: int | None = None
    load1: str | None = None
    uptime_seconds: float | None = None
    boot_id: str | None = None


def _read(path, limit=1048576):
    try:
        with open(path, 'rb') as stream:
            return stream.read(limit)
    except (OSError, ValueError):
        return None


def _proc_snapshot():
    values = {}
    for name in ('stat', 'meminfo', 'net/dev', 'loadavg', 'uptime', 'sys/kernel/random/boot_id'):
        values[name] = _read('/proc/' + name)
    return values


def parse_proc(values):
    """Parse fixed Linux /proc text plus optional df output. Missing fields stay None."""
    def text(name):
        raw = values.get(name)
        return raw.decode('utf-8', errors='strict') if raw is not None else None

    cpu_total = cpu_idle = None
    try:
        first = (text('stat') or '').splitlines()[0].split()
        if first and first[0] == 'cpu' and len(first) >= 5:
            numbers = [int(value) for value in first[1:]]
            # guest/guest_nice are already included in user/nice by Linux.
            cpu_total = sum(numbers[:8])
            cpu_idle = numbers[3] + (numbers[4] if len(numbers) > 4 else 0)
    except (ValueError, IndexError):
        pass

    memory_used = memory_total = None
    try:
        fields = {}
        for line in (text('meminfo') or '').splitlines():
            key, _, rest = line.partition(':')
            if key in {'MemTotal', 'MemAvailable', 'MemFree'} and rest:
                fields[key] = int(rest.split()[0]) * 1024
        if fields.get('MemTotal'):
            memory_total = fields['MemTotal']
            available = fields.get('MemAvailable', fields.get('MemFree'))
            if available is not None:
                memory_used = max(0, memory_total - available)
    except (ValueError, IndexError):
        pass

    net_receive = net_transmit = None
    try:
        lines = (text('net/dev') or '').splitlines()
        receive = transmit = 0
        for line in lines[2:]:
            interface, separator, rest = line.partition(':')
            if not separator or interface.strip() == 'lo':
                continue
            columns = rest.split()
            if len(columns) >= 9:
                receive += int(columns[0])
                transmit += int(columns[8])
        if len(lines) > 2:
            net_receive, net_transmit = receive, transmit
    except (ValueError, IndexError):
        pass

    load1 = None
    try:
        candidate = (text('loadavg') or '').split()[0]
        if re.fullmatch(r'[0-9]+(?:\.[0-9]+)?', candidate):
            load1 = candidate
    except (ValueError, IndexError):
        pass

    uptime = None
    try:
        uptime = float((text('uptime') or '').split()[0])
    except (ValueError, IndexError):
        pass

    boot_id = None
    try:
        candidate = (text('sys/kernel/random/boot_id') or '').strip().lower()
        if re.fullmatch(r'[a-f0-9-]{8,64}', candidate):
            boot_id = candidate
    except ValueError:
        pass

    disk_used = disk_total = None
    try:
        for line in (text('df') or '').splitlines()[1:]:
            columns = line.split()
            if len(columns) >= 4 and columns[5] == '/':
                disk_total = int(columns[1]) * 1024
                disk_used = int(columns[2]) * 1024
                break
    except (ValueError, IndexError):
        pass
    return MetricsSnapshot(cpu_total, cpu_idle, memory_used, memory_total, disk_used, disk_total,
                           net_receive, net_transmit, load1, uptime, boot_id)


class LocalProbe:
    """Fixed local probes. No arbitrary path or command is accepted."""

    def snapshot(self):
        snapshot = parse_proc(_proc_snapshot())
        try:
            stat = os.statvfs('/')
            total = stat.f_frsize * stat.f_blocks
            used = total - stat.f_frsize * stat.f_bfree
            snapshot = MetricsSnapshot(**{**snapshot.__dict__, 'disk_used': used, 'disk_total': total})
        except (OSError, AttributeError, ValueError):
            pass
        if snapshot.load1 is None:
            try:
                load = os.getloadavg()[0]
                snapshot = MetricsSnapshot(**{**snapshot.__dict__, 'load1': str(load)})
            except (OSError, AttributeError):
                pass
        return snapshot


class RemoteProbe:
    def __init__(self, runner, binding, timeout=30):
        self.runner, self.binding, self.timeout = runner, binding, timeout

    def snapshot(self):
        result = self.runner(self.binding, REMOTE_PROBE_COMMAND, self.timeout)
        if not result.ok:
            raise ProbeFailure(result.failure_code or 'SSH_CONNECTION_FAILED')
        sections, current = {}, None
        for line in result.output.splitlines(keepends=True):
            if line.startswith('### '):
                current = line[4:].strip()
                if current:
                    sections[current] = b''
                continue
            if current is not None:
                sections[current] += line.encode('utf-8')
        if not sections:
            raise ProbeFailure('SSH_CONNECTION_FAILED')
        values = {
            'stat': sections.get('/proc/stat'),
            'meminfo': sections.get('/proc/meminfo'),
            'net/dev': sections.get('/proc/net/dev'),
            'loadavg': sections.get('/proc/loadavg'),
            'uptime': sections.get('/proc/uptime'),
            'sys/kernel/random/boot_id': sections.get('/proc/sys/kernel/random/boot_id'),
            'df': sections.get('df'),
        }
        return parse_proc(values)


def _decimal_text(value, places):
    try:
        decimal = Decimal(str(value))
        if not decimal.is_finite() or decimal < 0:
            return None
        quantized = decimal.quantize(Decimal(1).scaleb(-places))
    except (InvalidOperation, ValueError):
        return None
    text = format(quantized, 'f')
    if '.' in text:
        text = text.rstrip('0').rstrip('.')
    return text or '0'


def _integer_text(value):
    return None if value is None else str(int(value))


@dataclass(frozen=True)
class Sample:
    target_id: str
    body: str


def build_sample(target, collector_id, sampled_time, snapshot, previous=None, elapsed=None,
                 failure=None):
    reasons = {}
    boot_changed = bool(previous and snapshot.boot_id and previous[0].boot_id
                        and snapshot.boot_id != previous[0].boot_id)
    uptime_dropped = bool(previous and snapshot.uptime_seconds is not None
                          and previous[0].uptime_seconds is not None
                          and snapshot.uptime_seconds < previous[0].uptime_seconds)
    restarted = boot_changed or uptime_dropped
    overall = ('SAMPLE_TIMEOUT' if failure in {'SSH_CONNECT_TIMEOUT', 'SSH_COMMAND_TIMEOUT', 'SAMPLE_TIMEOUT'}
               else 'SAMPLE_FAILED') if failure else None
    cpu = None
    if overall:
        reasons['cpu'] = overall
    elif snapshot.cpu_total is None or snapshot.cpu_idle is None:
        reasons['cpu'] = 'READ_FAILED'
    elif restarted:
        reasons['cpu'] = 'HOST_RESTART'
    elif previous is None or previous[0].cpu_total is None or previous[0].cpu_idle is None:
        reasons['cpu'] = 'FIRST_SAMPLE'
    else:
        total = snapshot.cpu_total - previous[0].cpu_total
        idle = snapshot.cpu_idle - previous[0].cpu_idle
        if total <= 0 or idle < 0 or idle > total:
            reasons['cpu'] = 'COUNTER_RESET'
        else:
            cpu = _decimal_text(Decimal(100) * Decimal(total - idle) / Decimal(total), 2)

    receive = transmit = None
    if overall:
        reasons['networkRate'] = overall
    elif snapshot.net_receive is None or snapshot.net_transmit is None:
        reasons['networkRate'] = 'READ_FAILED'
    elif restarted:
        reasons['networkRate'] = 'HOST_RESTART'
    elif previous is None or previous[0].net_receive is None or previous[0].net_transmit is None or not elapsed or elapsed <= 0:
        reasons['networkRate'] = 'FIRST_SAMPLE'
    else:
        rx = snapshot.net_receive - previous[0].net_receive
        tx = snapshot.net_transmit - previous[0].net_transmit
        if rx < 0 or tx < 0:
            reasons['networkRate'] = 'COUNTER_RESET'
        else:
            receive = str(int(rx / elapsed))
            transmit = str(int(tx / elapsed))

    memory_used, memory_total = _integer_text(snapshot.memory_used), _integer_text(snapshot.memory_total)
    if memory_used is None or memory_total is None:
        reasons['memory'] = overall or 'READ_FAILED'
    disk_used, disk_total = _integer_text(snapshot.disk_used), _integer_text(snapshot.disk_total)
    if disk_used is None or disk_total is None:
        reasons['disk'] = overall or 'READ_FAILED'
    load1 = _decimal_text(snapshot.load1, 6) if snapshot.load1 is not None else None
    if load1 is None:
        reasons['load'] = overall or 'READ_FAILED'
    uptime = str(int(snapshot.uptime_seconds)) if snapshot.uptime_seconds is not None else None
    if uptime is None:
        reasons['uptime'] = overall or 'READ_FAILED'

    present = [cpu, memory_used, memory_total, disk_used, disk_total, receive, transmit, load1, uptime]
    status = 'FAILED' if not any(value is not None for value in present) else ('PARTIAL' if reasons else 'SUCCEEDED')
    body = {
        'schemaVersion': 2, 'targetId': target.target_id,
        'collectorId': collector_id, 'configVersion': '', 'sampledTime': sampled_time, 'writtenTimeMillis': '0',
        'status': status, 'cpuPercent': cpu,
        'memoryUsedBytes': memory_used, 'memoryTotalBytes': memory_total,
        'diskUsedBytes': disk_used, 'diskTotalBytes': disk_total,
        'networkReceiveBytesPerSecond': receive, 'networkTransmitBytesPerSecond': transmit,
        'load1': load1, 'uptimeSeconds': uptime, 'unavailableReasons': reasons,
    }
    validate_sample(body)
    return Sample(target.target_id, canonical(body).decode())


def validate_sample(body):
    if not _SAMPLE_VALIDATOR.is_valid(body):
        raise ValueError('INVALID_RESOURCE_SAMPLE')
    groups = {'cpu': ('cpuPercent',), 'memory': ('memoryUsedBytes', 'memoryTotalBytes'),
              'disk': ('diskUsedBytes', 'diskTotalBytes'), 'networkRate': ('networkReceiveBytesPerSecond', 'networkTransmitBytesPerSecond'),
              'load': ('load1',), 'uptime': ('uptimeSeconds',)}
    for group, fields in groups.items():
        if any(body[field] is None for field in fields) != (group in body['unavailableReasons']):
            raise ValueError('INVALID_RESOURCE_SAMPLE')
    if body['status'] not in {'SUCCEEDED', 'PARTIAL', 'FAILED'}:
        raise ValueError('INVALID_RESOURCE_SAMPLE')
    if body['status'] == 'SUCCEEDED' and body['unavailableReasons']:
        raise ValueError('INVALID_RESOURCE_SAMPLE')
    return True


class ResourceStore:
    def __init__(self, client):
        self.client = client

    def publish(self, sample, interval_seconds):
        body = json.loads(sample.body)
        try:
            seconds, micros = self.client.time()
            body['writtenTimeMillis'] = str(seconds * 1000 + micros // 1000)
            self.client.set(RESOURCE_PREFIX + 'current:' + sample.target_id,
                            canonical(body).decode(), ex=2 * (2 * interval_seconds + 10))
        except RedisError:
            raise StorageError('REDIS_UNAVAILABLE') from None


class ResourceScheduler:
    def __init__(self, store, collector_id, targets, *, clock=None,
                 monotonic=time.monotonic, local_probe=None, remote_probe_factory=None, diagnostic=None,
                 asynchronous=False, max_workers=4):
        self.store = store
        self.collector_id = collector_id
        self.clock = clock or (lambda: datetime.now(SHANGHAI).isoformat(timespec='milliseconds'))
        self.monotonic = monotonic
        self.local_probe = local_probe or LocalProbe()
        self.remote_probe_factory = remote_probe_factory
        self.diagnostic = diagnostic or (lambda value: None)
        self.targets, self.next_due, self.previous = {}, {}, {}
        self.executor = ThreadPoolExecutor(max_workers=max_workers, thread_name_prefix='risk-resource') if asynchronous else None
        self.max_workers = max_workers
        self.inflight = {}
        self.update_config(targets)

    def update_config(self, targets):
        active = {target.target_id: target for target in targets if target.enabled}
        now = self.monotonic()
        for target_id, target in active.items():
            if self.targets.get(target_id) != target:
                self.next_due[target_id] = now
                self.previous.pop(target_id, None)
        for target_id in self.targets.keys() - active.keys():
            self.next_due.pop(target_id, None)
            self.previous.pop(target_id, None)
        for target_id, (target, future) in self.inflight.items():
            if target != active.get(target_id):
                # Let the worker finish, but discard its result after a target change.
                self.inflight[target_id] = (None, future)
        self.targets = active

    def _probe(self, target):
        if target.type == 'LOCAL':
            return self.local_probe
        if self.remote_probe_factory is None:
            raise ProbeFailure('SSH_BINDING_UNAVAILABLE')
        return self.remote_probe_factory(target)

    def sample_target(self, target):
        sampled_time = self.clock()
        now = self.monotonic()
        previous = self.previous.get(target.target_id)
        elapsed = now - previous[1] if previous is not None else None
        try:
            snapshot = self._probe(target).snapshot()
        except ProbeFailure as exc:
            self.previous.pop(target.target_id, None)
            return build_sample(target, self.collector_id, sampled_time,
                                MetricsSnapshot(), None, None, exc.code), exc.code
        except Exception:
            self.previous.pop(target.target_id, None)
            return build_sample(target, self.collector_id, sampled_time,
                                MetricsSnapshot(), None, None, 'SAMPLE_FAILED'), 'SAMPLE_FAILED'
        self.previous[target.target_id] = (snapshot, now)
        return build_sample(target, self.collector_id, sampled_time,
                            snapshot, previous, elapsed), None

    def _deliver(self, target, sample, failure):
        if failure:
            self.diagnostic({'code': failure, 'collectorId': self.collector_id, 'targetId': target.target_id})
        try:
            self.store.publish(sample, target.interval_seconds)
        except StorageError as exc:
            self.diagnostic({'code': exc.code, 'collectorId': self.collector_id, 'targetId': target.target_id})
        self.next_due[target.target_id] = self.monotonic() + target.interval_seconds

    def tick(self):
        """Publish only current samples; failed writes are dropped until the next cycle."""
        progress = False
        for target_id, (target, future) in list(self.inflight.items()):
            if not future.done():
                continue
            self.inflight.pop(target_id)
            if target is None:
                self.previous.pop(target_id, None)
                continue
            sample, failure = future.result()
            self._deliver(target, sample, failure)
            progress = True
        for target_id, target in self.targets.items():
            if target_id in self.inflight or self.monotonic() < self.next_due.get(target_id, 0):
                continue
            if self.executor is not None:
                if len(self.inflight) < self.max_workers:
                    self.inflight[target_id] = (target, self.executor.submit(self.sample_target, target))
                    progress = True
            else:
                sample, failure = self.sample_target(target)
                self._deliver(target, sample, failure)
                progress = True
        return progress

    def close(self):
        if self.executor is not None:
            self.executor.shutdown(wait=False, cancel_futures=True)
