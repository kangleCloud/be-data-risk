"""Bounded, best-effort HTTP statistics delivery."""
from redis.exceptions import RedisError

PREFIX = 'risk:'
HTTP_QUEUE = PREFIX + 'http:pending'
QUEUE_LIMIT = 20000


class StorageError(RuntimeError):
    def __init__(self, code):
        self.code = code
        super().__init__(code)


class RedisStore:
    def __init__(self, client):
        self.client = client

    def checkpoint(self, source):
        try:
            return self.client.hget(PREFIX + 'checkpoints', source)
        except RedisError:
            raise StorageError('REDIS_UNAVAILABLE') from None

    def heartbeat(self, now, last_event=''):
        fields = {'collectorHeartbeatTime': now}
        if last_event:
            fields['lastEventTime'] = last_event
        try:
            self.client.hset(PREFIX + 'heartbeat', mapping=fields)
        except RedisError:
            raise StorageError('REDIS_UNAVAILABLE') from None

    def publish(self, source, checkpoint, records):
        try:
            # Advance the durable cursor first. An uncertain enqueue must never be retried.
            self.client.hset(PREFIX + 'checkpoints', source, checkpoint)
        except RedisError:
            raise StorageError('REDIS_UNAVAILABLE') from None
        if records:
            try:
                with self.client.pipeline(transaction=False) as pipe:
                    for record in records:
                        pipe.rpush(HTTP_QUEUE, record)
                    pipe.ltrim(HTTP_QUEUE, -QUEUE_LIMIT, -1)
                    pipe.execute()
            except RedisError:
                # The commands may have completed in part. Drop local delivery state.
                return False
        return True
