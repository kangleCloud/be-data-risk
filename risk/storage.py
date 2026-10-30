"""V1 immutable publication. No old batch reads, global revision or archive scripts."""
from dataclasses import dataclass
from redis.exceptions import RedisError
from .protocol import asset, validate_envelope

PREFIX = 'risk:v1:'


class StorageError(RuntimeError):
    def __init__(self, code):
        self.code = code
        super().__init__(code)


@dataclass(frozen=True)
class Publication:
    source: str
    token: str
    expected_checkpoint: str
    new_checkpoint: str
    envelope: str
    batch_id: str
    day: str
    now: str
    last_event: str


class RedisStore:
    def __init__(self, client):
        self.client = client
        self.publish_script = client.register_script(asset('risk-v1/publish.lua'))
        self.lease_script = client.register_script(asset('risk-v1/lease.lua'))
        self.heartbeat_script = client.register_script(asset('risk-v1/heartbeat.lua'))

    def acquire(self, source, token):
        try:
            return bool(self.client.set(PREFIX + 'lease:' + source, token, nx=True, px=30000))
        except RedisError:
            raise StorageError('REDIS_UNAVAILABLE') from None

    def lease(self, operation, source, token):
        try:
            result = self.lease_script(keys=[PREFIX + 'lease:' + source], args=[operation, source, token, '30000'])
        except RedisError:
            raise StorageError('REDIS_UNAVAILABLE') from None
        if result != 'OK':
            raise StorageError(result)

    def checkpoint(self, source):
        try:
            return self.client.hget(PREFIX + 'checkpoints', source)
        except RedisError:
            raise StorageError('REDIS_UNAVAILABLE') from None

    def heartbeat(self, now, last_event=''):
        try:
            result = self.heartbeat_script(keys=[PREFIX + 'heartbeat'], args=[now, last_event or ''])
        except RedisError:
            raise StorageError('REDIS_UNAVAILABLE') from None
        if result != 'OK':
            raise StorageError(result)

    def publish(self, publication):
        keys = [PREFIX + 'days', PREFIX + 'pending:' + publication.day,
                PREFIX + 'batch:' + publication.day + ':' + publication.batch_id,
                PREFIX + 'checkpoints', PREFIX + 'day-key-ids',
                PREFIX + 'lease:' + publication.source, PREFIX + 'heartbeat']
        args = [publication.batch_id, publication.day, publication.source, publication.token,
                publication.expected_checkpoint, publication.new_checkpoint, publication.envelope,
                publication.now, publication.last_event]
        try:
            result = self.publish_script(keys=keys, args=args)
        except RedisError:
            # Keep the same immutable Publication; next attempt can confirm ALREADY_COMMITTED.
            raise StorageError('REDIS_UNAVAILABLE') from None
        if result not in {'OK', 'ALREADY_COMMITTED'}:
            raise StorageError(result)
        return result
