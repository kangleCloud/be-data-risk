"""Preview/reset only statistic keys, preserving checkpoints and all Geo data."""
import argparse
import json
import re
from datetime import date
from pathlib import Path
import sys
from urllib.parse import urlsplit, parse_qs

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from risk.config import load_config

# Historical keys are only inspected here; protected configuration/checkpoints are never deleted.
PATTERNS = ('risk:v1:days', 'risk:v1:day-key-ids', 'risk:v1:pending:*', 'risk:v1:batch:*',
            'risk:v1:query:*', 'risk:v2:days', 'risk:v2:pending:*', 'risk:v2:batch:*',
            'risk:monitor:v1:resource:pending:*', 'risk:monitor:v1:resource:sample:*')


def candidate_key(key, pattern):
    if pattern in {'risk:v1:days', 'risk:v1:day-key-ids', 'risk:v2:days'}:
        return key == pattern
    if pattern == 'risk:v1:query:*':
        return key.startswith('risk:v1:query:') and len(key) > len('risk:v1:query:')
    match = re.fullmatch(r'risk:v[12]:(pending|batch):(\d{4}-\d{2}-\d{2})(?::([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}))?', key)
    if match:
        try:
            date.fromisoformat(match[2])
        except ValueError:
            return False
        return (match[1] == 'pending' and match[3] is None) or (match[1] == 'batch' and match[3] is not None)
    ident = r'[A-Za-z0-9_-]{1,80}'
    uid = r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}'
    return bool(re.fullmatch(r'risk:monitor:v1:resource:pending:' + ident, key)
                or re.fullmatch(r'risk:monitor:v1:resource:sample:' + ident + ':' + uid, key))


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


def preview(client, *, batch_size=100, max_scan_calls=10000):
    if not 1 <= batch_size <= 1000 or not 1 <= max_scan_calls <= 100000:
        raise RebuildError('INVALID_REBUILD_LIMIT')
    result = {'mode': 'DRY_RUN', 'candidates': {}, 'checkpoints': {}}
    calls = 0
    for pattern in PATTERNS:
        cursor = 0
        count = 0
        while True:
            if calls >= max_scan_calls:
                raise RebuildError('REBUILD_SCAN_LIMIT')
            cursor, keys = client.scan(cursor=cursor, match=pattern, count=batch_size)
            calls += 1
            if any(not isinstance(key, str) or not key.startswith(pattern.rstrip('*')) for key in keys):
                raise RebuildError('INVALID_REBUILD_SCAN')
            count += sum(candidate_key(key, pattern) for key in keys)
            if int(cursor) == 0:
                break
        result['candidates'][pattern] = count
    old = client.hgetall('risk:v1:checkpoints')
    new = client.hgetall('risk:checkpoints')
    result['checkpoints'] = {'oldCount': len(old), 'newCount': len(new),
                             'conflicts': sum(key in new and new[key] != value for key, value in old.items())}
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--config', required=True, help='Existing private .env or JSON config; never a credential argument')
    parser.add_argument('--target', required=True, help='Credential-free redis[s]://HOST:PORT/DB or unix socket URI; must match config')
    parser.add_argument('--batch-size', type=int, default=100)
    parser.add_argument('--max-scan-calls', type=int, default=10000)
    args = parser.parse_args(argv)
    client = None
    try:
        # All confirmations and target checks precede even constructing a connection.
        if not 1 <= args.batch_size <= 1000 or not 1 <= args.max_scan_calls <= 100000:
            raise RebuildError('INVALID_REBUILD_LIMIT')
        config = load_config(args.config)
        if not config.redis_url or target_identity(config.redis_url) != target_identity(args.target, public_target=True):
            raise RebuildError('REBUILD_TARGET_MISMATCH')
        import redis
        client = redis.Redis.from_url(config.redis_url, decode_responses=True, socket_timeout=3, socket_connect_timeout=3)
        print(json.dumps(preview(client, batch_size=args.batch_size, max_scan_calls=args.max_scan_calls), sort_keys=True))
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
