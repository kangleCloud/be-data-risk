"""Explicit offline day-key-id migration; original checkpoints are never written."""
import argparse
import json
import re
import sys
from datetime import date
from redis.exceptions import RedisError
from .algorithms import canonical
from .config import load_config
from .parsing import strict_json
from .protocol import asset
from .storage import StorageError


def checkpoint_value(encoded):
    try:
        value = strict_json(encoded.encode())
        if set(value) != {'generation', 'offset'} or not isinstance(value['generation'], str) or not re.fullmatch(r'[A-Za-z0-9_.:-]{1,128}', value['generation']) or not isinstance(value['offset'], str) or not re.fullmatch(r'0|[1-9][0-9]{0,19}', value['offset']):
            raise ValueError()
        if canonical(value).decode() != encoded:
            raise ValueError()
        return value
    except (ValueError, TypeError, AttributeError):
        raise StorageError('INVALID_CHECKPOINT') from None


def legacy_plan(client, require_stopped=True):
    try:
        if client.hlen('risk:v1:directory'):
            raise StorageError('MIGRATION_REQUIRED')
        # Old hashes have UUID:meta/records suffixes, distinct from date:UUID immutable Strings.
        for pattern in ['risk:v1:batch:*:meta', 'risk:v1:batch:*:records']:
            if next(client.scan_iter(match=pattern, count=100), None) is not None:
                raise StorageError('MIGRATION_REQUIRED')
        for lease in client.scan_iter(match='risk:v1:lease:*', count=100):
            token = client.get(lease)
            if token and (require_stopped or not token.startswith('immutable-')):
                raise StorageError('MIGRATION_REQUIRED')
        checkpoints = client.hgetall('risk:v1:checkpoints')
        for source, value in checkpoints.items():
            if not re.fullmatch(r'[A-Za-z0-9_-]{1,80}', source):
                raise StorageError('INVALID_CHECKPOINT')
            checkpoint_value(value)
        ids = {}
        for field, key_id in client.hgetall('risk:v1:active').items():
            if not re.fullmatch(r'\d{4}-\d{2}-\d{2}:keyId', field) or not re.fullmatch(r'[A-Za-z0-9_-]{1,80}', key_id):
                raise StorageError('MIGRATION_REQUIRED')
            date.fromisoformat(field[:10])
            ids[field[:10]] = key_id
        return {'checkpoints': checkpoints, 'dayKeyIds': ids}
    except RedisError:
        raise StorageError('REDIS_UNAVAILABLE') from None
    except ValueError:
        raise StorageError('INVALID_MIGRATION_INPUT') from None


def guard_startup(client):
    """Only a cutover gate; no old publication/fallback logic, no checkpoint writes."""
    plan = legacy_plan(client, require_stopped=False)
    try:
        for day, key_id in plan['dayKeyIds'].items():
            if client.hget('risk:v1:day-key-ids', day) != key_id:
                raise StorageError('MIGRATION_REQUIRED')
    except RedisError:
        raise StorageError('REDIS_UNAVAILABLE') from None


def migrate(client, execute=False):
    plan = legacy_plan(client)
    try:
        for day, value in plan['dayKeyIds'].items():
            target = client.hget('risk:v1:day-key-ids', day)
            if target is not None and target != value:
                raise StorageError('MIGRATION_CONFLICT')
        if execute:
            result = client.register_script(asset('risk-v1/migrate.lua'))(
                keys=['risk:v1:checkpoints', 'risk:v1:active', 'risk:v1:directory', 'risk:v1:day-key-ids'],
                args=[canonical(plan).decode()])
            if result != 'OK':
                raise StorageError(result)
            guard_startup(client)
        return {'mode': 'EXECUTED' if execute else 'DRY_RUN',
                'checkpointCount': str(len(plan['checkpoints'])), 'dayKeyIdCount': str(len(plan['dayKeyIds']))}
    except RedisError:
        raise StorageError('REDIS_UNAVAILABLE') from None


def main():
    parser = argparse.ArgumentParser(description='Risk V1 offline day-key-id migration; dry-run by default')
    parser.add_argument('--config', required=True)
    parser.add_argument('--execute', action='store_true')
    args = parser.parse_args()
    client = None
    try:
        import redis
        config = load_config(args.config)
        if not config.redis_url:
            raise StorageError('SERVICE_CONFIG_REQUIRED')
        client = redis.Redis.from_url(config.redis_url, decode_responses=True, socket_timeout=3, socket_connect_timeout=3)
        print(json.dumps(migrate(client, args.execute), sort_keys=True))
        return 0
    except StorageError as exc:
        print(json.dumps({'code': exc.code}), file=sys.stderr)
        return 1
    except Exception:
        print('{"code":"MIGRATION_FAILED"}', file=sys.stderr)
        return 1
    finally:
        if client is not None:
            client.close()


if __name__ == '__main__':
    sys.exit(main())
