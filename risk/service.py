"""Per-source ten-second memory segments and immutable atomic V1 publication."""
from dataclasses import dataclass, field
from datetime import datetime
import hashlib
import json
import signal
import sys
import threading
import time
import uuid

from .aggregation import event_records, quality_record, merge
from .algorithms import HLL, canonical
from .parsing import Rejected, SHANGHAI, parse_event
from .protocol import MAX_BYTES, MAX_RECORDS, make_envelope
from .storage import RedisStore, StorageError, Publication
from .tailer import FileTailer, SourceError, checkpoint_json, restore_checkpoint


def now_iso():
    return datetime.now(SHANGHAI).isoformat(timespec='milliseconds')


@dataclass
class SourceState:
    token: str
    reader: FileTailer
    checkpoint: str | None
    renewed_at: float
    rows: dict = field(default_factory=dict)
    day: str | None = None
    batch_id: str | None = None
    started_at: float | None = None
    end_checkpoint: str | None = None
    last_event: str = ''
    publication: Publication | None = None
    diagnostics: dict = field(default_factory=dict)


class Collector:
    def __init__(self, store, config, key=None, clock=now_iso, monotonic=time.monotonic, diagnostic=None):
        self.store, self.config, self.key = store, config, key
        self.key_id = hashlib.sha256(key).hexdigest()[:32] if key else 'unavailable'
        self.clock, self.monotonic = clock, monotonic
        self.states = {}
        self.last_event = ''
        self.last_heartbeat = None
        self.checked_migration = False
        self.diagnostic = diagnostic or (lambda value: None)

    def _discard(self, source):
        state = self.states.pop(source.alias, None)
        if state is not None:
            state.reader.close()

    def _renew(self, source, state, force=False):
        current = self.monotonic()
        if force or current - state.renewed_at >= 10:
            try:
                self.store.lease('RENEW', source.alias, state.token)
            except StorageError:
                self._discard(source)
                raise
            state.renewed_at = current

    def _state(self, source):
        state = self.states.get(source.alias)
        if state is not None:
            self._renew(source, state)
            return state
        token = 'immutable-' + str(uuid.uuid4())
        if not self.store.acquire(source.alias, token):
            raise StorageError('LEASE_LOST')
        try:
            encoded = self.store.checkpoint(source.alias)
            checkpoint = restore_checkpoint(encoded) if encoded is not None else None
            if checkpoint is None and not source.path.is_file():
                raise SourceError()
            reader = FileTailer(source.path, checkpoint, self.config.max_line_bytes)
        except Exception:
            self.store.lease('RELEASE', source.alias, token)
            raise
        state = SourceState(token, reader, encoded, self.monotonic())
        self.states[source.alias] = state
        return state

    def _flush(self, source, state):
        if state.end_checkpoint is None:
            return False
        self._renew(source, state)
        if state.publication is None:
            now = self.clock()
            envelope = make_envelope(state.batch_id, state.day, self.key_id, now, list(state.rows.values()))
            state.publication = Publication(source.alias, state.token, state.checkpoint or '',
                                            state.end_checkpoint, canonical(envelope).decode(),
                                            state.batch_id, state.day, now, state.last_event)
        try:
            self.store.publish(state.publication)
        except StorageError as exc:
            if exc.code in {'LEASE_LOST', 'CHECKPOINT_CONFLICT'}:
                self._discard(source)
            raise
        state.checkpoint = state.end_checkpoint
        self.last_event = max(self.last_event, state.last_event)
        for reason, info in state.diagnostics.items():
            self.diagnostic({'code': reason, 'sourceId': source.alias, **info})
        state.rows.clear()
        state.diagnostics.clear()
        state.day = state.batch_id = state.started_at = state.end_checkpoint = state.publication = None
        state.last_event = ''
        return True

    def flush_all(self):
        for source in self.config.sources:
            state = self.states.get(source.alias)
            if state is not None:
                self._flush(source, state)

    def _prospective(self, state, day, rows, now):
        merged = dict(state.rows)
        for row in rows:
            merged[row['recordId']] = merge(merged.get(row['recordId']), row)
        if len(merged) > MAX_RECORDS:
            raise ValueError('RECORD_TOO_LARGE')
        # All changed records were validated by merge; avoid re-running every schema per line.
        # Hash/UUID/time widths are fixed, so placeholders give the EXACT final byte length.
        envelope = {'schemaVersion': 1, 'batchId': state.batch_id or '00000000-0000-4000-8000-000000000000',
                    'businessDate': day, 'keyId': self.key_id, 'createdAt': now,
                    'recordCount': str(len(merged)), 'checksum': '0' * 64, 'records': list(merged.values())}
        if len(canonical(envelope)) > MAX_BYTES:
            raise ValueError('RECORD_TOO_LARGE')
        return merged

    def step(self, source):
        state = self._state(source)
        if state.publication is not None:
            self._flush(source, state)  # uncertain result: retry identical bytes before reading any more.
        if state.started_at is not None and self.monotonic() - state.started_at >= 10:
            self._flush(source, state)
        candidate = state.reader.prepare()
        if candidate is None:
            return False
        now, event_at = self.clock(), ''
        day = now[:10]
        rows = []
        if candidate.reason:
            reason = {'SOURCE_ROTATED': None, 'ROTATED_PARTIAL_LINE': 'INVALID_JSON',
                      'LINE_TOO_LONG': 'INVALID_JSON'}.get(candidate.reason, candidate.reason)
            if reason:
                rows = [quality_record(day, source.alias, reason)]
        else:
            hll = HLL()
            try:
                event = parse_event(candidate.raw, self.config.privacy, hll, self.key)
                day, event_at = event['business_date'], event['event_at']
                rows = event_records(event, source.alias, hll, self.key_id)
            except Rejected as exc:
                rows = [quality_record(day, source.alias, exc.reason)]
        transition = candidate.before.generation != candidate.after.generation
        if state.day is not None and (state.day != day or transition):
            self._flush(source, state)
        try:
            prospective = self._prospective(state, day, rows, now)
        except ValueError as exc:
            if str(exc) != 'RECORD_TOO_LARGE':
                raise
            if state.end_checkpoint is not None:
                self._flush(source, state)
            try:
                prospective = self._prospective(state, day, rows, now)
            except ValueError:
                raise StorageError('RECORD_TOO_LARGE') from None
        if state.day is None:
            state.day, state.batch_id, state.started_at = day, str(uuid.uuid4()), self.monotonic()
        state.rows = prospective
        state.end_checkpoint = checkpoint_json(candidate.after)
        state.last_event = max(state.last_event, event_at)
        for row in rows:
            if row['kind'] == 'QUALITY' and row['dimensions']['reasonCode'] in {'INVALID_JSON', 'INVALID_TIME', 'INVALID_NUMBER', 'SOURCE_TRUNCATED'}:
                info = state.diagnostics.setdefault(row['dimensions']['reasonCode'],
                                                     {'generation': candidate.before.generation, 'offset': str(candidate.before.offset), 'count': '0'})
                info['count'] = str(int(info['count']) + 1)
        # This advances only the in-memory read cursor, NEVER the durable checkpoint.
        state.reader.acknowledge(candidate)
        if transition or len(state.rows) == MAX_RECORDS or self.monotonic() - state.started_at >= 10:
            self._flush(source, state)
        return True

    def tick(self):
        if not self.checked_migration:
            from .migrate import guard_startup
            guard_startup(self.store.client)
            self.checked_migration = True
        progress = False
        for source in self.config.sources:
            progress = self.step(source) or progress
        current = self.monotonic()
        if self.last_heartbeat is None or current - self.last_heartbeat >= 10:
            self.store.heartbeat(self.clock(), self.last_event)
            self.last_heartbeat = current
        return progress

    def wait_seconds(self):
        current = self.monotonic()
        limits = [self.config.poll_millis / 1000]
        if self.last_heartbeat is not None:
            limits.append(max(0, self.last_heartbeat + 10 - current))
        for state in self.states.values():
            limits.append(max(0, state.renewed_at + 10 - current))
            if state.started_at is not None:
                limits.append(max(0, state.started_at + 10 - current))
        return min(limits)

    def close(self, flush=True):
        failure = None
        for source in self.config.sources:
            state = self.states.get(source.alias)
            if state is None:
                continue
            try:
                if flush and state.end_checkpoint is not None:
                    self._renew(source, state, force=True)
                    self._flush(source, state)
            except Exception as exc:
                failure = failure or exc
            finally:
                state.reader.close()
                try:
                    self.store.lease('RELEASE', source.alias, state.token)
                except StorageError:
                    pass  # only token-owned release; otherwise lease expires.
        self.states.clear()
        if failure is not None:
            raise failure


def run(config, once=False):
    if not config.sources or not config.redis_url:
        raise ValueError('SERVICE_CONFIG_REQUIRED')
    import redis
    from .protocol import verify_assets
    verify_assets()
    key = config.hmac_key.encode('utf-8') if config.hmac_key else None
    if key is not None and len(key) < 32:
        raise ValueError('HMAC_KEY_TOO_SHORT')
    def diagnostic(value):
        print(json.dumps(value, sort_keys=True), file=sys.stderr, flush=True)
    geo = None
    if config.geo_database is not None:
        try:
            from .geo import OfflineGeo
            geo = OfflineGeo(config.geo_database)
        except Exception:
            diagnostic({'code': 'GEO_UNAVAILABLE'})
        config.privacy.geo = geo
    client = redis.Redis.from_url(config.redis_url, decode_responses=True, socket_timeout=3, socket_connect_timeout=3)
    stop = threading.Event()
    previous_handlers = {}
    for signum in (signal.SIGTERM, signal.SIGINT):
        previous_handlers[signum] = signal.signal(signum, lambda *_: stop.set())
    collector = Collector(RedisStore(client), config, key, diagnostic=diagnostic)
    try:
        while not stop.is_set():
            try:
                progress = collector.tick()
                if once and not progress:
                    return  # finally flushes the remaining partial segment.
                if not progress:
                    stop.wait(collector.wait_seconds())
            except SourceError as exc:
                diagnostic({'code': exc.code})
                raise
            except StorageError as exc:
                diagnostic({'code': exc.code})
                if once or exc.code != 'REDIS_UNAVAILABLE':
                    raise
                stop.wait(1)
    finally:
        try:
            collector.close()
        finally:
            client.close()
            if geo is not None:
                geo.close()
            for signum, previous in previous_handlers.items():
                signal.signal(signum, previous)
