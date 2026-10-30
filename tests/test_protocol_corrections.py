"""Offline regression against shared assets; does not enable Redis integration."""
import hashlib
import json
from pathlib import Path
import unittest

from risk.algorithms import canonical, checksum, micros, bucket
from risk.parsing import PrivacyPolicy, PathRule, Rejected, REASONS, parse_event


class CorrectionsTest(unittest.TestCase):
    def event(self, **updates):
        value = {'@timestamp': '2026-10-27T12:00:00+08:00', 'uri': '/events',
                 'status': 200, 'request_time': '600.1234569'}
        value.update(updates)
        return json.dumps(value).encode()

    def test_timestamp_alias(self):
        result = parse_event(self.event(), PrivacyPolicy())
        self.assertEqual(result['event_at'], '2026-10-27T12:00:00.000+08:00')

    def test_equivalent_timestamp_aliases(self):
        result = parse_event(self.event(time_iso8601='2026-10-27T04:00:00Z'), PrivacyPolicy())
        self.assertEqual(result['business_date'], '2026-10-27')

    def test_conflicting_timestamps_rejected(self):
        for alternate in ['2026-10-27T04:01:00Z', None, 'invalid', '2026-10-27T12:00:00']:
            with self.subTest(alternate=alternate), self.assertRaises(Rejected) as caught:
                parse_event(self.event(time_iso8601=alternate), PrivacyPolicy())
            self.assertEqual(caught.exception.reason, 'INVALID_TIME')

    def test_sse_duration_preserved(self):
        policy = PrivacyPolicy([PathRule('/events', '/events', 'SSE')])
        event = parse_event(self.event(), policy)
        self.assertEqual(event['request_type'], 'SSE')
        self.assertEqual(event['duration_micros'], 600123457)

    def test_ascii_and_schema(self):
        self.assertEqual(canonical({'schemaVersion': 1, 'value': '中😀'}),
                         b'{"schemaVersion":1,"value":"\\u4e2d\\ud83d\\ude00"}')
        for value in [{'schemaVersion': True}, {'schemaVersion': '1'}, {'schemaVersion': 2}, {'count': 1}]:
            with self.assertRaises(ValueError):
                canonical(value)

    def test_shared_fixture(self):
        fixture = json.loads((Path(__file__).resolve().parents[1] / 'risk/assets/risk-v1-fixtures.json').read_text())
        line = fixture['canonicalRecordLine']
        record = json.loads(line)
        self.assertEqual(canonical(record) + b'\n', line.encode())
        self.assertEqual(checksum([record]), fixture['checksum'])
        self.assertEqual(checksum([]), fixture['emptyChecksum'])
        self.assertEqual(checksum([record]), hashlib.sha256(line.encode()).hexdigest())
        self.assertEqual(canonical(record['dimensions']).decode(), fixture['canonicalDimensions'])
        for case in fixture['durationCases']:
            value = micros(case['seconds'])
            self.assertEqual(None if value is None else str(value), case['micros'])
            self.assertEqual(bucket(value), case['bucketIndex'])

    def test_only_contract_reasons(self):
        self.assertEqual(REASONS, {'INVALID_JSON', 'INVALID_TIME', 'INVALID_NUMBER', 'UNMATCHED_PATH',
                         'UNTRUSTED_IP', 'GEO_UNAVAILABLE', 'HTTP_5XX', 'HTTP_4XX', 'CLIENT_ABORT',
                         'UPSTREAM_FAILURE', 'SOURCE_TRUNCATED', 'KEY_UNAVAILABLE'})
        for raw in [b'\xff', b'[]', b'{"uri":"\\x"}']:
            with self.assertRaises(Rejected) as caught:
                parse_event(raw, PrivacyPolicy())
            self.assertEqual(caught.exception.reason, 'INVALID_JSON')
