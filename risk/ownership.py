"""Fail-closed collector ownership with a Redis-issued fencing epoch."""
import uuid
from redis.exceptions import RedisError
from .protocol import asset
from .redis_keys import key_segment
from .storage import StorageError


class CollectorOwnership:
    def __init__(self, client, collector_id):
        self.collector_id = collector_id
        self.segment = key_segment(collector_id, max_bytes=80)
        self.key = 'risk:monitor:lease:' + self.segment
        self.epoch_field = 'monitorEpoch:' + self.segment
        self.token = str(uuid.uuid4())
        self.epoch = None
        self.valid = False
        self.script = client.register_script(asset('monitor/collector-lease.lua'))

    def _call(self, operation):
        try:
            return self.script(keys=[self.key, 'risk:heartbeat'],
                               args=[operation, self.collector_id, self.token, self.epoch or ''])
        except RedisError:
            self.valid = False
            raise StorageError('REDIS_UNAVAILABLE') from None

    def acquire(self):
        if self.epoch is not None:
            raise StorageError('COLLECTOR_LEASE_LOST')
        result = self._call('ACQUIRE')
        if not isinstance(result, str) or not result.isdigit() or result.startswith('0'):
            raise StorageError(result)
        self.epoch = result
        self.valid = True

    def renew(self):
        self.require()
        result = self._call('RENEW')
        if result != 'OK':
            self.valid = False
            raise StorageError(result)

    def release(self):
        if not self.valid:
            return
        try:
            self._call('RELEASE')
        finally:
            self.valid = False

    def require(self):
        if not self.valid or not self.epoch:
            raise StorageError('COLLECTOR_LEASE_LOST')

    def keys_args(self):
        self.require()
        return [self.key, 'risk:heartbeat'], [self.collector_id, self.token, self.epoch]
