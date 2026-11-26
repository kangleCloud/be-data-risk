"""Live QPS checkpoints and bounded, best-effort historical delivery."""
from redis.exceptions import RedisError, WatchError

PREFIX = 'risk:'
HTTP_QUEUE = PREFIX + 'http:pending'
QPS_PREFIX = PREFIX + 'http:qps:'
CHECKPOINTS = PREFIX + 'checkpoints'
QUEUE_LIMIT = 20000
QPS_TTL_SECONDS = 600
MAX_COUNTER = (1 << 63) - 1


def qps_expiry(minute):
    return (minute + 1) * 60 + QPS_TTL_SECONDS


class StorageError(RuntimeError):
    def __init__(self, code):
        self.code = code
        super().__init__(code)


class RedisStore:
    def __init__(self, client):
        self.client = client

    def checkpoint(self, source):
        try:
            return self.client.hget(CHECKPOINTS, source)
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

    def _commit(self, source, expected_checkpoint, checkpoint, qps_counts):
        keys = [(QPS_PREFIX + str(minute), delta, qps_expiry(minute)) for minute, delta in qps_counts.items()]
        with self.client.pipeline() as pipe:
            pipe.watch(CHECKPOINTS, *(key for key, _, _ in keys))
            current = pipe.hget(CHECKPOINTS, source)
            if current == checkpoint:
                # A previous EXEC may have succeeded before its response was lost.
                return 'UNCHANGED'
            if current is None and expected_checkpoint is not None:
                # A partial Redis restore may retain counts without the cursor. Restore
                # the cursor without replaying this batch and drop its coverage claim.
                for key, _, _ in keys:
                    pipe.hget(key, 'ready')
                pipe.multi()
                for key, _, _ in keys:
                    pipe.hdel(key, 'ready')
                pipe.hset(CHECKPOINTS, source, checkpoint)
                pipe.execute()
                return 'RECOVERED'
            if current != expected_checkpoint:
                raise StorageError('CHECKPOINT_CONFLICT')
            for key, delta, _ in keys:
                count = pipe.hget(key, 'requestCount')
                if count is not None and (not count.isascii() or not count.isdecimal() or len(count) > 19
                                          or (len(count) > 1 and count.startswith('0')) or int(count) > MAX_COUNTER - delta):
                    raise StorageError('QPS_COUNTER_INVALID')
            pipe.multi()
            for key, delta, expiry in keys:
                pipe.hincrby(key, 'requestCount', delta)
                pipe.expireat(key, expiry)
            pipe.hset(CHECKPOINTS, source, checkpoint)
            pipe.execute()
            return 'COMMITTED'

    def ready_minute(self, minute, checkpoints):
        key = QPS_PREFIX + str(minute)
        try:
            with self.client.pipeline() as pipe:
                pipe.watch(CHECKPOINTS, key)
                missing = {}
                for source, checkpoint in checkpoints.items():
                    current = pipe.hget(CHECKPOINTS, source)
                    if current is None and checkpoint is not None:
                        missing[source] = checkpoint
                    elif current != checkpoint:
                        raise StorageError('CHECKPOINT_CONFLICT')
                pipe.hget(key, 'ready')
                pipe.multi()
                if missing:
                    # An idle reader can detect a restore even without a pending batch.
                    pipe.hset(CHECKPOINTS, mapping=missing)
                    pipe.hdel(key, 'ready')
                else:
                    pipe.hset(key, 'ready', '1')
                    pipe.expireat(key, qps_expiry(minute))
                pipe.execute()
                return not missing
        except RedisError:
            raise StorageError('REDIS_UNAVAILABLE') from None

    def publish(self, source, expected_checkpoint, checkpoint, records, qps_counts):
        try:
            # Commit live counting before the independent, best-effort historical queue.
            outcome = self._commit(source, expected_checkpoint, checkpoint, qps_counts)
            if outcome != 'COMMITTED':
                return True, outcome == 'RECOVERED'
        except WatchError:
            # A concurrent writer may only have changed an unrelated source. Recheck on retry.
            raise StorageError('REDIS_UNAVAILABLE') from None
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
                return False, False
        return True, False
