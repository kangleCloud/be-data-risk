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
from .resources import ProbeFailure, RemoteProbe, ResourceScheduler, ResourceStore
from .service import Collector
from .ssh import SshAllowlist, SshBindingError, SshRunner
from .storage import RedisStore, StorageError
from .ownership import CollectorOwnership
from .protocol import asset
from .algorithms import canonical


class MonitorRuntimeError(RuntimeError):
    def __init__(self, code):
        self.code = code
        super().__init__(code)


@dataclass(frozen=True)
class LocalPlan:
    version: str | None
    sources: tuple[SourceConfig, ...]
    targets: dict
    signature: tuple
    monitor_targets: tuple = ()


def _build_plan(config, monitor):
    source_by_alias = {source.alias: source for source in config.sources}
    targets = monitor.for_collector(config.collector_id)
    mapping = {}
    for target in targets:
        if target.local and target.log_source_id is not None:
            if target.log_source_id not in source_by_alias:
                raise MonitorConfigError('CONFIG_TARGET_INVALID')
            mapping[target.log_source_id] = target.target_id
    sources = tuple(source for source in config.sources if source.alias in mapping)
    signature = (tuple(sorted(mapping.items())), tuple(source.alias for source in sources))
    return LocalPlan(monitor.version, sources, mapping, signature, targets)


class MonitorRuntime:
    def __init__(self, config, client, *, store=None, sync=None, allowlist=None, runner=None,
                 geo=None, clock=None, monotonic=time.monotonic,
                 diagnostic=None, sleep=time.sleep, local_probe=None, lease_wait=35):
        if not config.collector_id:
            raise MonitorRuntimeError('COLLECTOR_ID_REQUIRED')
        self.config = config
        self.client = client
        self.ownership = CollectorOwnership(client, config.collector_id)
        self.store = store or RedisStore(client, self.ownership)
        self.store.ownership = self.ownership
        self.status_script = client.register_script(asset('monitor/collector-status.lua'))
        self.sync = sync or MonitorConfigSync(client)
        self.allowlist = allowlist or SshAllowlist(())
        self.runner = runner or SshRunner()
        self.geo = geo
        self.clock = clock or (lambda: datetime.now(SHANGHAI).isoformat(timespec='milliseconds'))
        self.monotonic = monotonic
        self.diagnostic = diagnostic or (lambda value: None)
        self.sleep = sleep
        self.local_probe = local_probe
        self.lease_wait = lease_wait
        self.collector = None
        self.resources = None
        self.local_signature = None
        self.pending_plan = None
        self.last_sync_error = None
        self.last_renewed = None
        self.last_status = None
        self.last_status_at = None
        self.applied_version = None
        self.applied_targets = {}
        self.apply_error = None

    def _renew_owner(self):
        now = self.monotonic()
        if self.last_renewed is None or now - self.last_renewed >= 10:
            self.ownership.renew()
            self.last_renewed = now

    def _publish_status(self, force=False):
        from redis.exceptions import RedisError
        status = self.sync.status
        observed = self.sync.observed_version
        config_error = self.apply_error or status.error
        if self.applied_version is None:
            state = 'UNAVAILABLE'
        elif status.stale or self.apply_error or self.pending_plan is not None:
            state = 'STALE'
        else:
            state = 'APPLIED'
        value = {'schemaVersion': 2, 'collectorId': self.config.collector_id,
                 'epoch': self.ownership.epoch, 'updatedAtMillis': '0',
                 'configState': state, 'appliedConfigVersion': self.applied_version,
                 'observedConfigVersion': observed, 'configError': config_error,
                 'sources': [{'sourceId': source, 'targetId': target,
                              'coverageFromMillis': None, 'coverageThroughMillis': None,
                              'continuity': 'UNKNOWN'} for source, target in sorted(self.applied_targets.items())]}
        body = canonical(value).decode()
        now = self.monotonic()
        if not force and body == self.last_status and self.last_status_at is not None and now - self.last_status_at < 10:
            return
        keys, args = self.ownership.keys_args()
        try:
            result = self.status_script(keys=keys, args=args + [body])
        except RedisError:
            raise StorageError('REDIS_UNAVAILABLE') from None
        try:
            json.loads(result)
        except (ValueError, TypeError):
            if result == 'COLLECTOR_LEASE_LOST':
                self.ownership.valid = False
            raise StorageError(result) from None
        self.last_status = canonical(value).decode()
        self.last_status_at = now

    def _report_sync(self):
        status = self.sync.status
        if status.stale and status.error and status.error != self.last_sync_error:
            self.diagnostic({'code': status.error, 'stale': True})
            self.last_sync_error = status.error
        elif not status.stale:
            self.last_sync_error = None

    def _remote_probe(self, target):
        try:
            binding = self.allowlist.resolve(target.connection)
        except SshBindingError as exc:
            raise ProbeFailure(exc.code) from None
        return RemoteProbe(self.runner, binding, timeout=30)

    def _restart(self, plan):
        if self.collector is not None:
            # Flush first; if Redis is unavailable the old collector and exact publication stay intact.
            self.collector.flush_all()
            self.collector.close(flush=False)
            self.collector = None
        self.local_signature = None
        if not plan.sources:
            self.local_signature = plan.signature
            return
        collector = Collector(self.store, replace(self.config, sources=plan.sources),
                              clock=self.clock, monotonic=self.monotonic,
                              diagnostic=self.diagnostic, geo=self.geo,
                              targets=plan.targets)
        try:
            deadline = self.monotonic() + self.lease_wait
            while True:
                try:
                    collector.prepare_sources()
                    break
                except StorageError as exc:
                    if exc.code != 'LEASE_LOST' or self.monotonic() >= deadline:
                        raise
                    self._renew_owner()
                    collector.renew_leases()
                    self.sleep(min(1, max(0, deadline - self.monotonic())))
        except Exception:
            collector.release_leases()
            raise
        self.collector = collector
        self.local_signature = plan.signature

    def _activate(self, plan):
        self._restart(plan)
        if self.resources is None:
            self.resources = ResourceScheduler(
                ResourceStore(self.client, self.ownership), self.config.collector_id, plan.version or '0',
                plan.monitor_targets, clock=self.clock,
                monotonic=self.monotonic, remote_probe_factory=self._remote_probe,
                local_probe=self.local_probe, diagnostic=self.diagnostic, asynchronous=True)
        else:
            self.resources.update_config(plan.version or '0', plan.monitor_targets)
        self.pending_plan = None
        self.applied_version = plan.version
        self.applied_targets = dict(plan.targets)
        self.apply_error = None

    def start(self):
        self.ownership.acquire()
        self.last_renewed = self.monotonic()
        self.sync.refresh(force=True)
        self._report_sync()
        if not self.sync.status.loaded:
            self._publish_status(force=True)
            raise MonitorRuntimeError('CONFIG_UNAVAILABLE')
        try:
            plan = _build_plan(self.config, self.sync.current)
        except MonitorConfigError as exc:
            self.apply_error = exc.code
            self._publish_status(force=True)
            raise MonitorRuntimeError(exc.code) from None
        # Create independent delivery workers even for an empty valid config.
        if self.resources is None:
            self.resources = ResourceScheduler(
                ResourceStore(self.client, self.ownership), self.config.collector_id, plan.version or '0', (),
                clock=self.clock, monotonic=self.monotonic,
                remote_probe_factory=self._remote_probe, local_probe=self.local_probe,
                diagnostic=self.diagnostic, asynchronous=True)
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
                self.resources.update_config(plan.version or '0',
                                             tuple(target for target in self.sync.current.for_collector(self.config.collector_id)))
            self.pending_plan = None
            self.applied_version = plan.version
            self.applied_targets = dict(plan.targets)
            self.apply_error = None
            return
        self.pending_plan = plan

    def _retry_pending(self):
        if self.pending_plan is None:
            return False
        try:
            self._activate(self.pending_plan)
        except StorageError as exc:
            if exc.code == 'COLLECTOR_LEASE_LOST':
                raise
            if exc.code != 'REDIS_UNAVAILABLE':
                self.diagnostic({'code': exc.code})
            return False
        return True

    def tick(self):
        self._renew_owner()
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
                self.collector.close(flush=self.ownership.valid)
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
            try:
                self.ownership.release()
            except StorageError:
                pass
        if failure is not None:
            raise failure


def run_monitor(config, once=False):
    if not config.redis_url or not config.collector_id:
        raise MonitorRuntimeError('MONITOR_CONFIG_REQUIRED')
    import redis
    from .protocol import verify_assets
    verify_assets()
    def diagnostic(value):
        print(json.dumps(value, sort_keys=True), file=sys.stderr, flush=True)
    from .geo import UnifiedGeoClient, InternalBatchHttp, make_geo_cache_client
    geo_cache = make_geo_cache_client(config.redis_url)
    transport = InternalBatchHttp(config.geo_service_url, config.geo_service_token) if config.geo_service_url else None
    geo = UnifiedGeoClient(geo_cache, transport)
    allowlist = SshAllowlist(config.ssh_servers)
    client = redis.Redis.from_url(config.redis_url, decode_responses=True, socket_timeout=3, socket_connect_timeout=3)
    stop = threading.Event()
    previous_handlers = {}
    for signum in (signal.SIGTERM, signal.SIGINT):
        previous_handlers[signum] = signal.signal(signum, lambda *_: stop.set())
    runtime = MonitorRuntime(config, client, allowlist=allowlist, geo=geo, diagnostic=diagnostic)
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
