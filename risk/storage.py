"""Immutable publication with lease, checkpoint and heartbeat keys."""
from dataclasses import dataclass
from redis.exceptions import RedisError
from .protocol import asset, validate_envelope
from .redis_keys import key_segment

PREFIX = 'risk:'


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
    def __init__(self, client, ownership=None):
        self.client = client
        self.ownership = ownership
        self.publish_script = client.register_script(asset('risk/publish.lua'))
        self.lease_script = client.register_script(asset('risk/lease.lua'))
        self.heartbeat_script = client.register_script(asset('risk/heartbeat.lua'))

    def acquire(self, source, token):
        try:
            return bool(self.client.set(PREFIX + 'lease:' + key_segment(source, max_bytes=80), token, nx=True, px=30000))
        except RedisError:
            raise StorageError('REDIS_UNAVAILABLE') from None

    def lease(self, operation, source, token):
        try:
            result = self.lease_script(keys=[PREFIX + 'lease:' + key_segment(source, max_bytes=80)], args=[operation, source, token, '30000'])
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
        if self.ownership is None:
            raise StorageError('COLLECTOR_LEASE_LOST')
        keys, args = self.ownership.keys_args()
        try:
            result = self.heartbeat_script(keys=[PREFIX + 'heartbeat'] + keys, args=[now, last_event or ''] + args)
        except RedisError:
            raise StorageError('REDIS_UNAVAILABLE') from None
        if result != 'OK':
            if result == 'COLLECTOR_LEASE_LOST':
                self.ownership.valid = False
            raise StorageError(result)

    def publish(self, publication):
        import json
        validate_envelope(json.loads(publication.envelope), publication.envelope)
        keys = [PREFIX + 'days', PREFIX + 'pending:' + publication.day,
                PREFIX + 'batch:' + publication.day + ':' + publication.batch_id,
                PREFIX + 'checkpoints',
                PREFIX + 'lease:' + key_segment(publication.source, max_bytes=80), PREFIX + 'heartbeat']
        args = [publication.batch_id, publication.day, publication.source, publication.token,
                publication.expected_checkpoint, publication.new_checkpoint, publication.envelope,
                publication.now, publication.last_event]
        if self.ownership is None:
            raise StorageError('COLLECTOR_LEASE_LOST')
        owner_keys, owner_args = self.ownership.keys_args()
        keys += owner_keys
        args += owner_args
        try:
            result = self.publish_script(keys=keys, args=args)
        except RedisError:
            # Keep the same immutable Publication; next attempt can confirm ALREADY_COMMITTED.
            raise StorageError('REDIS_UNAVAILABLE') from None
        if result not in {'OK', 'ALREADY_COMMITTED'}:
            if result == 'COLLECTOR_LEASE_LOST':
                self.ownership.valid = False
            raise StorageError(result)
        return result
