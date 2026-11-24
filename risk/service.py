"""Aggregate short in-memory HTTP windows and enqueue independent rows."""
from dataclasses import dataclass, field, replace
from collections import deque
from datetime import datetime, timedelta
import json
import signal
import sys
import threading
import time

from .aggregation import event_records, identity, merge
from .algorithms import canonical
from .parsing import Rejected, SHANGHAI, parse_observation
from .protocol import MAX_RECORDS
from .storage import StorageError, qps_expiry
from .tailer import FileTailer, SourceError, checkpoint_json, restore_checkpoint

MAX_QPS_POLL_GAP = 30


def now_iso():
    return datetime.now(SHANGHAI).isoformat(timespec='milliseconds')


@dataclass
class SourceState:
    reader: FileTailer
    durable_checkpoint: str | None
    rows: dict = field(default_factory=dict)
    qps_counts: dict[int, int] = field(default_factory=dict)
    observed_through: float | None = None
    day: str | None = None
    started_time: float | None = None
    end_checkpoint: str | None = None
    last_event: str = ''
    diagnostics: dict = field(default_factory=dict)
    staged: deque = field(default_factory=deque)


class Collector:
    def __init__(self, store, config, clock=now_iso, monotonic=time.monotonic, diagnostic=None, geo=None):
        self.store, self.config = store, config
        self.geo = geo
        self.stage_limit = 100
        self.clock, self.monotonic = clock, monotonic
        self.states = {}
        self.last_event = ''
        self.last_heartbeat = None
        self.diagnostic = diagnostic or (lambda value: None)
        self.qps_clean_since = None
        self.qps_last_tick = None
        self.qps_last_ready = None

    def _state(self, source):
        state = self.states.get(source.alias)
        if state is None:
            encoded = self.store.checkpoint(source.alias)
            checkpoint = restore_checkpoint(encoded) if encoded is not None else None
            if checkpoint is None and not source.path.is_file():
                raise SourceError()
            state = SourceState(FileTailer(source.path, checkpoint, self.config.max_line_bytes), encoded)
            self.states[source.alias] = state
        return state

    def prepare_sources(self):
        for source in self.config.sources:
            self._state(source)

    def _flush(self, source, state):
        if state.end_checkpoint is None:
            return False
        records = [canonical(dict(row, sourceId=source.alias)).decode() for row in state.rows.values()]
        now = datetime.fromisoformat(self.clock()).timestamp()
        counts = {minute: count for minute, count in state.qps_counts.items() if qps_expiry(minute) > now}
        history_delivered, recovered = self.store.publish(
            source.alias, state.durable_checkpoint, state.end_checkpoint, records, counts)
        if recovered:
            self.qps_last_tick = None
            self.diagnostic({'code': 'HTTP_CHECKPOINT_RECOVERED', 'sourceId': source.alias,
                             'recordCount': len(records)})
        elif not history_delivered:
            self.diagnostic({'code': 'HTTP_QUEUE_DELIVERY_UNCERTAIN', 'sourceId': source.alias,
                             'recordCount': len(records)})
        state.durable_checkpoint = state.end_checkpoint
        self.last_event = max(self.last_event, state.last_event)
        for reason, info in state.diagnostics.items():
            self.diagnostic({'code': reason, 'sourceId': source.alias, **info})
        state.rows.clear()
        state.qps_counts.clear()
        state.diagnostics.clear()
        state.day = state.started_time = state.end_checkpoint = None
        state.last_event = ''
        return True

    def flush_all(self):
        for source in self.config.sources:
            state = self.states.get(source.alias)
            if state is not None:
                while state.staged:
                    self.step(source)
                self._flush(source, state)

    def _merge_rows(self, state, rows):
        merged = dict(state.rows)
        for row in rows:
            key = identity(row)
            merged[key] = merge(merged.get(key), row)
        return merged

    def _stage(self, source, state):
        cutoff = (datetime.fromisoformat(self.clock()).date() - timedelta(days=29)).isoformat()
        frames = []
        addresses = []
        started = self.monotonic()
        try:
            for _ in range(self.stage_limit):
                scanned_at = self.clock()
                candidate = state.reader.prepare()
                if candidate is None:
                    # A successful read reached the end of the available log, not just the batch limit.
                    if state.reader.at_end:
                        state.observed_through = datetime.fromisoformat(scanned_at).timestamp()
                    break
                now, event_time = scanned_at, ''
                day, event, address = now[:10], None, None
                qps_minute = None
                rows, reasons = [], []
                if candidate.reason:
                    if candidate.reason in {'SOURCE_TRUNCATED', 'ROTATED_PARTIAL_LINE'}:
                        self.qps_last_tick = None
                    reason = {'SOURCE_ROTATED': None, 'ROTATED_PARTIAL_LINE': 'INVALID_JSON',
                              'LINE_TOO_LONG': 'INVALID_JSON'}.get(candidate.reason, candidate.reason)
                    if reason:
                        reasons = [reason]
                else:
                    try:
                        event, address = parse_observation(candidate.raw, self.config.privacy)
                        day, event_time = event['business_date'], event['event_time']
                        if day < cutoff or day > now[:10]:
                            event = None
                        else:
                            event_seconds = datetime.fromisoformat(event_time).timestamp()
                            now_seconds = datetime.fromisoformat(now).timestamp()
                            minute = int(event_seconds // 60)
                            if event_seconds <= now_seconds < qps_expiry(minute):
                                qps_minute = minute
                            if not event['geo_internal']:
                                addresses.append(address)
                    except Rejected as exc:
                        reasons = [exc.reason]
                # Retain sanitized event fields only; raw lines never enter staged memory.
                frame = (replace(candidate, raw=None), day, event_time, event, address, rows, reasons, qps_minute)
                frames.append(frame)
                state.reader.acknowledge(candidate)
                if candidate.before.generation != candidate.after.generation:
                    break
        except SourceError:
            self.qps_last_tick = None
            if not frames:
                raise
        if not frames:
            return
        budget = min(.300, max(0, 10 - (self.monotonic() - (state.started_time if state.started_time is not None else started))))
        from .geo import fallback_outcome
        try:
            outcomes = self.geo.resolve_many(addresses, budget=budget) if self.geo is not None and addresses else {}
        except Exception:
            outcomes = {}
        for candidate, day, event_time, event, address, rows, reasons, qps_minute in frames:
            if event is not None:
                outcome = fallback_outcome(address) if event['geo_internal'] else outcomes.get(address, fallback_outcome(address))
                event['region_code'] = outcome.region_code
                event['geo'] = outcome.result or {}
                event['quality'] = sorted(set(event['quality']) | set(outcome.quality))
                rows = event_records(event)
                reasons = event['quality']
            state.staged.append((candidate, day, event_time, rows, reasons, qps_minute))
        if frames and state.started_time is None:
            state.started_time = started

    def step(self, source):
        state = self._state(source)
        if state.started_time is not None and self.monotonic() - state.started_time >= 10:
            self._flush(source, state)
        if not state.staged:
            self._stage(source, state)
        if not state.staged:
            return False
        candidate, day, event_time, rows, reasons, qps_minute = state.staged[0]
        transition = candidate.before.generation != candidate.after.generation
        if state.day is not None and (state.day != day or transition):
            self._flush(source, state)
        prospective = self._merge_rows(state, rows)
        if len(prospective) > MAX_RECORDS:
            self._flush(source, state)
            prospective = self._merge_rows(state, rows)
        if state.day is None:
            state.day = day
            if state.started_time is None:
                state.started_time = self.monotonic()
        state.rows = prospective
        if qps_minute is not None:
            state.qps_counts[qps_minute] = state.qps_counts.get(qps_minute, 0) + 1
        state.end_checkpoint = checkpoint_json(candidate.after)
        state.last_event = max(state.last_event, event_time)
        for reason in reasons:
            info = state.diagnostics.setdefault(reason, {'generation': candidate.before.generation,
                                                         'offset': str(candidate.before.offset), 'count': '0'})
            info['count'] = str(int(info['count']) + 1)
        # This advances only the in-memory read cursor, NEVER the durable checkpoint.
        state.staged.popleft()
        if transition or len(state.rows) == MAX_RECORDS or self.monotonic() - state.started_time >= 10:
            self._flush(source, state)
        return True

    def _finish_qps_minute(self, now):
        current_minute = int(now // 60)
        previous_minute = current_minute - 1
        if (not self.config.sources or self.qps_last_tick is None or self.qps_last_ready == previous_minute
                or self.qps_clean_since > previous_minute * 60):
            return
        for state in self.states.values():
            if state.staged or state.observed_through is None or state.observed_through < current_minute * 60:
                return
        # The minute cannot be zero while a counted row is still waiting for its checkpoint commit.
        for source in self.config.sources:
            self._flush(source, self.states[source.alias])
        if self.qps_last_tick is None:
            return
        checkpoints = {alias: state.durable_checkpoint for alias, state in self.states.items()}
        if self.store.ready_minute(previous_minute, checkpoints):
            self.qps_last_ready = previous_minute
        else:
            self.qps_last_tick = None
            self.diagnostic({'code': 'HTTP_CHECKPOINT_RECOVERED', 'recordCount': 0})

    def tick(self):
        now = datetime.fromisoformat(self.clock()).timestamp()
        current = self.monotonic()
        if (self.qps_last_tick is None or current - self.qps_last_tick[0] > MAX_QPS_POLL_GAP
                or not 0 <= now - self.qps_last_tick[1] <= MAX_QPS_POLL_GAP):
            self.qps_clean_since = now
        self.qps_last_tick = (current, now)
        progress = False
        try:
            for source in self.config.sources:
                progress = self.step(source) or progress
            if self.last_heartbeat is None or current - self.last_heartbeat >= 10:
                self.store.heartbeat(self.clock(), self.last_event)
                self.last_heartbeat = current
            self._finish_qps_minute(now)
        except (SourceError, StorageError):
            self.qps_last_tick = None
            raise
        return progress

    def wait_seconds(self):
        current = self.monotonic()
        limits = [self.config.poll_millis / 1000]
        if self.last_heartbeat is not None:
            limits.append(max(0, self.last_heartbeat + 10 - current))
        for state in self.states.values():
            if state.started_time is not None:
                limits.append(max(0, state.started_time + 10 - current))
        return min(limits)

    def close(self, flush=True):
        failure = None
        for source in self.config.sources:
            state = self.states.get(source.alias)
            if state is None:
                continue
            try:
                if flush:
                    while state.staged:
                        self.step(source)
                if flush and state.end_checkpoint is not None:
                    self._flush(source, state)
            except Exception as exc:
                failure = failure or exc
            finally:
                state.reader.close()
        self.states.clear()
        if failure is not None:
            raise failure
