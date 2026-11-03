"""Preview/reset only risk namespaces on an explicitly confirmed configured target."""
import argparse
import json
from pathlib import Path
import sys
from urllib.parse import urlsplit, parse_qs

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from risk.config import load_config

PREFIXES = ('risk:v1:', 'geoip:v1:')


class RebuildError(ValueError):
    pass


def target_identity(url, *, public_target=False):
    """Credential-free target comparison, including TLS and selected Redis DB."""
    from redis.connection import parse_url
    try:
        parsed = urlsplit(url)
        if public_target and (parsed.username is not None or parsed.password is not None or parsed.fragment
                              or set(parse_qs(parsed.query)) - {'db'}):
            raise ValueError()
        if public_target:
            query = parse_qs(parsed.query)
            if 'db' in query and len(query['db']) != 1:
                raise ValueError()
            explicit_db = 'db' in query
            if not explicit_db and (parsed.scheme == 'unix' or not parsed.path.strip('/').isdigit()):
                raise ValueError()
        options = parse_url(url)
        db = int(options.get('db', 0))
        if db < 0:
            raise ValueError()
        if parsed.scheme == 'unix':
            return ('unix', options['path'], db)
        if parsed.scheme not in {'redis', 'rediss'} or not options.get('host'):
            raise ValueError()
        port = parsed.port if parsed.port is not None else 6379
        if not 1 <= port <= 65535:
            raise ValueError()
        return (parsed.scheme, options['host'].lower(), port, db)
    except (ValueError, TypeError, KeyError):
        raise RebuildError('INVALID_REBUILD_TARGET') from None


def rebuild(client, *, execute=False, writers_stopped=False, batch_size=100, max_scan_calls=10000):
    if execute and not writers_stopped:
        raise RebuildError('WRITERS_STOP_CONFIRMATION_REQUIRED')
    if not 1 <= batch_size <= 1000 or not 1 <= max_scan_calls <= 100000:
        raise RebuildError('INVALID_REBUILD_LIMIT')
    result = {'mode': 'EXECUTED' if execute else 'DRY_RUN', 'namespaces': {}}
    calls = 0
    for prefix in PREFIXES:
        cursor = 0
        entries = deleted = pass_entries = 0
        while True:
            if calls >= max_scan_calls:
                raise RebuildError('REBUILD_SCAN_LIMIT')
            cursor, keys = client.scan(cursor=cursor, match=prefix + '*', count=batch_size)
            calls += 1
            # Do not trust a malformed SCAN response to expand the deletion scope.
            if any(not isinstance(key, str) or not key.startswith(prefix) for key in keys):
                raise RebuildError('INVALID_REBUILD_SCAN')
            entries += len(keys)
            pass_entries += len(keys)
            if execute:
                for start in range(0, len(keys), batch_size):
                    deleted += client.unlink(*keys[start:start + batch_size])
            if int(cursor) == 0:
                if execute and pass_entries:
                    pass_entries = 0 # bounded follow-up sweep verifies no keys remain
                    continue
                break
        result['namespaces'][prefix] = {'scanEntries': entries, 'deletedKeys': deleted}
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--config', required=True, help='Existing private .env or JSON config; never a credential argument')
    parser.add_argument('--target', required=True, help='Credential-free redis[s]://HOST:PORT/DB or unix socket URI; must match config')
    parser.add_argument('--execute', action='store_true', help='Explicitly authorize deletion; default is preview')
    parser.add_argument('--writers-stopped', action='store_true', help='Confirm risk collector and archive writers are stopped')
    parser.add_argument('--batch-size', type=int, default=100)
    parser.add_argument('--max-scan-calls', type=int, default=10000)
    args = parser.parse_args(argv)
    client = None
    try:
        # All confirmations and target checks precede even constructing a connection.
        if args.execute and not args.writers_stopped:
            raise RebuildError('WRITERS_STOP_CONFIRMATION_REQUIRED')
        if not 1 <= args.batch_size <= 1000 or not 1 <= args.max_scan_calls <= 100000:
            raise RebuildError('INVALID_REBUILD_LIMIT')
        config = load_config(args.config)
        if not config.redis_url or target_identity(config.redis_url) != target_identity(args.target, public_target=True):
            raise RebuildError('REBUILD_TARGET_MISMATCH')
        import redis
        client = redis.Redis.from_url(config.redis_url, decode_responses=True, socket_timeout=3, socket_connect_timeout=3)
        print(json.dumps(rebuild(client, execute=args.execute, writers_stopped=args.writers_stopped,
                                 batch_size=args.batch_size, max_scan_calls=args.max_scan_calls), sort_keys=True))
        return 0
    except RebuildError as error:
        print(json.dumps({'code': str(error)}), file=sys.stderr)
        return 1
    except Exception:
        # Redis/configuration exceptions can carry passwords and private URLs.
        print('{"code":"REBUILD_FAILED"}', file=sys.stderr)
        return 1
    finally:
        if client is not None:
            client.close()


if __name__ == '__main__':
    sys.exit(main())
