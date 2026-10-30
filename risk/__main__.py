"""Service and privacy-safe offline validation entry point."""
import argparse
import json
import sys
from .config import load_config
from .parsing import PrivacyPolicy, Rejected, parse_event
from .tailer import FileTailer


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
    parser = argparse.ArgumentParser(description='Risk V1 read-only Nginx collector')
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('--check-file', help='Validate a local sample; no persistent checkpoint')
    group.add_argument('--config', help='Explicit local configuration file; no implicit server defaults')
    parser.add_argument('--once', action='store_true', help='Drain currently complete lines then exit')
    args = parser.parse_args()
    try:
        if args.check_file:
            check_file(args.check_file)
        else:
            from .service import run
            run(load_config(args.config), args.once)
    except Exception as exc:
        from .storage import StorageError
        if isinstance(exc, StorageError):
            print(json.dumps({'code': exc.code}), file=sys.stderr)
            return 1
        # Configuration, OS and dependency exceptions can contain credentials/paths/raw input.
        print('{"code":"COLLECTOR_STOPPED"}', file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    sys.exit(main())
