"""Monitor runtime: config hot reload and resource sampling."""
from dataclasses import dataclass, replace
from datetime import datetime
import json
import signal
import sys
import threading
import time

from .config import SourceConfig
from .monitor_config import MonitorConfigSync, MonitorConfigError
from .parsing import SHANGHAI
from .redis_keys import key_segment
from .resources import ProbeFailure, RemoteProbe, ResourceScheduler, ResourceStore
from .service import Collector
from .ssh import SshBindingError, SshRunner, decrypt_binding
from .storage import RedisStore, StorageError
from .algorithms import canonical


class MonitorRuntimeError(RuntimeError):
    def __init__(self, code):
        self.code = code
        super().__init__(code)


@dataclass(frozen=True)
class LocalPlan:
    has_config: bool
    sources: tuple[SourceConfig, ...]
    signature: tuple
    monitor_targets: tuple = ()


def _build_plan(config, monitor):
    targets = monitor.for_collector(config.collector_id)
    sources = config.sources
    signature = tuple((source.alias, str(source.path)) for source in sources)
    return LocalPlan(not monitor.empty, sources, signature, targets)


class MonitorRuntime:
    def __init__(self, config, client, *, store=None, sync=None, runner=None,
                 geo=None, clock=None, monotonic=time.monotonic,
                 diagnostic=None, sleep=time.sleep, local_probe=None):
        if not config.collector_id:
            raise MonitorRuntimeError('COLLECTOR_ID_REQUIRED')
        self.config = config
        self.client = client
        self.store = store or RedisStore(client)
        self.sync = sync or MonitorConfigSync(client)
        self.runner = runner or SshRunner()
        self.geo = geo
        self.clock = clock or (lambda: datetime.now(SHANGHAI).isoformat(timespec='milliseconds'))
        self.monotonic = monotonic
        self.diagnostic = diagnostic or (lambda value: None)
        self.sleep = sleep
        self.local_probe = local_probe
        self.collector = None
        self.resources = None
        self.local_signature = None
        self.pending_plan = None
        self.last_sync_error = None
        self.last_status = None
        self.last_status_time = None
        self.config_applied = False
        self.applied_sources = ()
        self.apply_error = None

    def _publish_status(self, force=False):
        from redis.exceptions import RedisError
        status = self.sync.status
        config_error = self.apply_error or status.error
        if not self.config_applied:
            state = 'UNAVAILABLE'
        elif status.stale or self.apply_error or self.pending_plan is not None:
            state = 'STALE'
        else:
            state = 'APPLIED'
        value = {'schemaVersion': 2, 'collectorId': self.config.collector_id,
                 'updatedTimeMillis': '0',
                 'configState': state, 'appliedConfigVersion': '',
                 'observedConfigVersion': '', 'configError': config_error,
                 'sources': [{'sourceId': source,
                              'coverageFromMillis': None, 'coverageThroughMillis': None,
                              'continuity': 'UNKNOWN'} for source in sorted(self.applied_sources)]}
        body = canonical(value).decode()
        now = self.monotonic()
        if not force and body == self.last_status and self.last_status_time is not None and now - self.last_status_time < 10:
            return
        try:
            seconds, micros = self.client.time()
            value['updatedTimeMillis'] = str(seconds * 1000 + micros // 1000)
            self.client.hset('risk:heartbeat', 'monitor:' + key_segment(self.config.collector_id, max_bytes=80),
                             canonical(value).decode())
        except RedisError:
            raise StorageError('REDIS_UNAVAILABLE') from None
        self.last_status = body
        self.last_status_time = now

    def _report_sync(self):
        status = self.sync.status
        if status.stale and status.error and status.error != self.last_sync_error:
            self.diagnostic({'code': status.error, 'stale': True})
            self.last_sync_error = status.error
        elif not status.stale:
            self.last_sync_error = None

    def _remote_probe(self, target):
        try:
            binding = decrypt_binding(target.connection, self.config.sm4_key)
        except SshBindingError as exc:
            raise ProbeFailure(exc.code) from None
        return RemoteProbe(self.runner, binding, timeout=30)

    def _restart(self, plan):
        if self.collector is not None:
            # Preserve any unsent local rows until the source checkpoint can be stored.
            self.collector.flush_all()
            self.collector.close(flush=False)
            self.collector = None
        self.local_signature = None
        if not plan.sources:
            self.local_signature = plan.signature
            return
        collector = Collector(self.store, replace(self.config, sources=plan.sources),
                              clock=self.clock, monotonic=self.monotonic,
                              diagnostic=self.diagnostic, geo=self.geo)
        try:
            collector.prepare_sources()
        except Exception:
            collector.close(flush=False)
            raise
        self.collector = collector
        self.local_signature = plan.signature

    def _activate(self, plan):
        self._restart(plan)
        if self.resources is None:
            self.resources = ResourceScheduler(
                ResourceStore(self.client), self.config.collector_id,
                plan.monitor_targets, clock=self.clock,
                monotonic=self.monotonic, remote_probe_factory=self._remote_probe,
                local_probe=self.local_probe, diagnostic=self.diagnostic, asynchronous=True)
        else:
            self.resources.update_config(plan.monitor_targets)
        self.pending_plan = None
        self.config_applied = plan.has_config
        self.applied_sources = tuple(source.alias for source in plan.sources)
        self.apply_error = None

    def start(self):
        self.sync.refresh(force=True)
        self._report_sync()
        try:
            plan = _build_plan(self.config, self.sync.current)
        except MonitorConfigError as exc:
            self.apply_error = exc.code
            self._publish_status(force=True)
            raise MonitorRuntimeError(exc.code) from None
        self._activate(plan)
        self._publish_status(force=True)

    def _apply_config_change(self):
        try:
            plan = _build_plan(self.config, self.sync.current)
        except MonitorConfigError as exc:
            self.diagnostic({'code': exc.code, 'stale': True})
            self.pending_plan = None
            self.apply_error = exc.code
            return
        if plan.signature == self.local_signature:
            if self.resources is not None:
                self.resources.update_config(plan.monitor_targets)
            self.pending_plan = None
            self.config_applied = plan.has_config
            self.applied_sources = tuple(source.alias for source in plan.sources)
            self.apply_error = None
            return
        self.pending_plan = plan

    def _retry_pending(self):
        if self.pending_plan is None:
            return False
        try:
            self._activate(self.pending_plan)
        except StorageError as exc:
            if exc.code != 'REDIS_UNAVAILABLE':
                self.diagnostic({'code': exc.code})
            return False
        return True

    def tick(self):
        changed = self.sync.refresh(monotonic_now=self.monotonic())
        self._report_sync()
        if changed:
            self._apply_config_change()
        progress = self._retry_pending()
        if self.collector is not None:
            progress = self.collector.tick() or progress
        if self.resources is not None:
            progress = self.resources.tick() or progress
        self._publish_status()
        return progress

    def wait_seconds(self):
        return min(0.2, max(0.01, self.config.poll_millis / 1000))

    def close(self):
        failure = None
        try:
            if self.collector is not None:
                self.collector.close()
        except Exception as exc:
            failure = exc
            self.diagnostic({'code': getattr(exc, 'code', 'COLLECTOR_STOPPED')})
        finally:
            self.collector = None
            if self.resources is not None:
                if self.resources.inflight:
                    self.diagnostic({'code': 'RESOURCE_SAMPLING_INTERRUPTED',
                                     'collectorId': self.config.collector_id})
                self.resources.close()
                self.resources = None
            self.local_signature = None
        if failure is not None:
            raise failure


def run_monitor(config, once=False):
    if not config.redis_url or not config.collector_id:
        raise MonitorRuntimeError('MONITOR_CONFIG_REQUIRED')
    import redis
    from redis.backoff import NoBackoff
    from redis.retry import Retry
    from .protocol import verify_assets
    verify_assets()
    def diagnostic(value):
        print(json.dumps(value, sort_keys=True), file=sys.stderr, flush=True)
    from .geo import UnifiedGeoClient, InternalBatchHttp, make_geo_cache_client
    geo_cache = make_geo_cache_client(config.redis_url)
    transport = InternalBatchHttp(config.geo_service_url, config.geo_service_token) if config.geo_service_url else None
    geo = UnifiedGeoClient(geo_cache, transport)
    client = redis.Redis.from_url(config.redis_url, decode_responses=True, socket_timeout=3, socket_connect_timeout=3, retry=Retry(NoBackoff(), 0))
    stop = threading.Event()
    previous_handlers = {}
    for signum in (signal.SIGTERM, signal.SIGINT):
        previous_handlers[signum] = signal.signal(signum, lambda *_: stop.set())
    runtime = MonitorRuntime(config, client, geo=geo, diagnostic=diagnostic)
    try:
        runtime.start()
        while not stop.is_set():
            try:
                progress = runtime.tick()
                if once and not progress and not (runtime.resources and runtime.resources.inflight):
                    break
                if not progress:
                    stop.wait(runtime.wait_seconds())
            except StorageError as exc:
                if once or exc.code != 'REDIS_UNAVAILABLE':
                    raise
                diagnostic({'code': exc.code})
                stop.wait(1)
    finally:
        try:
            runtime.close()
        finally:
            client.close()
            geo_cache.close()
            for signum, previous in previous_handlers.items():
                signal.signal(signum, previous)
