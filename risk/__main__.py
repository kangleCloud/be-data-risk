"""Service and privacy-safe offline validation entry point."""
import argparse
import json
import sys
from .config import load_config
from .parsing import PrivacyPolicy, Rejected, parse_event
from .tailer import FileTailer, SourceError


SAFE_ERROR_CODES = frozenset({
    'INVALID_ENV_CONFIG', 'UNKNOWN_CONFIG_FIELD', 'INVALID_SOURCE_CONFIG',
    'INVALID_SOURCE_ALIAS', 'PATH_MUST_BE_ABSOLUTE', 'SOURCE_PATH_MUST_BE_ABSOLUTE',
    'DUPLICATE_SOURCE', 'INVALID_CONFIG_VALUE', 'INVALID_PATH_RULE',
    'INVALID_TRUSTED_PROXY_CONFIG', 'INVALID_REDIS_CONFIG', 'INVALID_COLLECTOR_ID',
    'INVALID_SM4_KEY', 'INVALID_GEO_SERVICE_CONFIG', 'PROTOCOL_ASSET_MISMATCH',
})


def check_file(path):
    reader = FileTailer(path)
    counts = {'accepted': 0, 'quality': {}}
    try:
        while (candidate := reader.prepare()) is not None:
            reasons = []
            try:
                if candidate.reason:
                    reason = {'SOURCE_ROTATED': None, 'ROTATED_PARTIAL_LINE': 'INVALID_JSON',
                              'LINE_TOO_LONG': 'INVALID_JSON'}.get(candidate.reason, candidate.reason)
                    reasons = [reason] if reason else []
                else:
                    event = parse_event(candidate.raw, PrivacyPolicy())
                    counts['accepted'] += 1
                    reasons = event['quality']
            except Rejected as exc:
                reasons = [exc.reason]
            for reason in reasons:
                counts['quality'][reason] = counts['quality'].get(reason, 0) + 1
            reader.acknowledge(candidate)
    finally:
        reader.close()
    print(json.dumps(counts, sort_keys=True))


def main():
    parser = argparse.ArgumentParser(description='Risk read-only Nginx and resource collector')
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('--check-file', help='Validate a local sample; no persistent checkpoint')
    group.add_argument('--config', help='Explicit local configuration file; no implicit server defaults')
    group.add_argument('--check-config', help='Validate a local configuration without connecting to Redis')
    parser.add_argument('--once', action='store_true', help='Drain currently complete lines then exit')
    args = parser.parse_args()
    stage = 'check_file' if args.check_file else 'config'
    try:
        if args.check_file:
            check_file(args.check_file)
        else:
            config = load_config(args.config or args.check_config)
            stage = 'runtime_import'
            from .monitor import MonitorRuntimeError, run_monitor
            from .ssh import SshBindingError
            from .storage import StorageError
            if args.check_config:
                if not config.redis_url or not config.collector_id:
                    print(json.dumps({'code': 'MONITOR_CONFIG_REQUIRED', 'stage': 'config'}), file=sys.stderr)
                    return 1
                print(json.dumps({'code': 'CONFIG_OK'}))
                return 0
            stage = 'collector'
            try:
                run_monitor(config, args.once)
            except (StorageError, MonitorRuntimeError, SshBindingError) as exc:
                print(json.dumps({'code': exc.code, 'stage': stage}), file=sys.stderr)
                return 1
    except SourceError as exc:
        print(json.dumps({'code': exc.code, 'stage': stage}), file=sys.stderr)
        return 1
    except Exception as exc:
        # Only allow known messages. Other exceptions can contain credentials or raw input.
        code = str(exc) if isinstance(exc, ValueError) else ''
        if code not in SAFE_ERROR_CODES:
            if stage == 'config' and isinstance(exc, OSError):
                code = 'CONFIG_READ_FAILED'
            elif isinstance(exc, ImportError):
                code = 'DEPENDENCY_UNAVAILABLE'
            else:
                code = 'COLLECTOR_STOPPED'
        print(json.dumps({'code': code, 'stage': stage, 'errorType': type(exc).__name__}), file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    sys.exit(main())
