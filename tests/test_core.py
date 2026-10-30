import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from risk.algorithms import BOUNDS, HLL, bucket, canonical, checksum, micros, number, p95, record_id
from risk.parsing import PathRule, PrivacyPolicy, Rejected, parse_event, strict_json
from risk.tailer import FileTailer


class AlgorithmsTest(unittest.TestCase):
    def test_decimal_exact(self):
        self.assertEqual(micros('0.0000015'), 2)
        self.assertEqual(micros('43200'), 43200000000)
        self.assertIsNone(micros('-'))
        self.assertIsNone(number(None))

    def test_invalid_numbers(self):
        for value in [True, -1, '-1', 'NaN', 'Infinity', ' 1', '1e1000000', 1.0]:
            with self.subTest(value=value), self.assertRaises(ValueError):
                number(value)

    def test_bucket_boundaries(self):
        for index, bound in enumerate(BOUNDS):
            self.assertEqual(bucket(bound), index)
        self.assertEqual(bucket(BOUNDS[-1] + 1), len(BOUNDS))

    def test_percentile(self):
        counts = [0] * 24
        self.assertEqual(p95(counts), (None, False))
        counts[2] = 95
        counts[-1] = 5
        self.assertEqual(p95(counts), (2000, False))
        counts[-1] = 6
        self.assertEqual(p95(counts), (None, True))

    def test_hll_normalization(self):
        left, right = HLL(), HLL()
        left.add(b'test', '2026-10-27', '2001:0DB8:0:0::1')
        right.add(b'test', '2026-10-27', '2001:db8::1')
        self.assertEqual(left.encode(), right.encode())
        self.assertEqual(left.estimate(), 1)
        self.assertEqual(HLL().estimate(), 0)
        self.assertEqual(HLL.decode(left.encode()).encode(), left.encode())

    def test_hll_merge(self):
        left, right = HLL(), HLL()
        left.add(b'test', '2026-10-27', '1.1.1.1')
        right.add(b'test', '2026-10-27', '8.8.8.8')
        left.merge(right)
        left.merge(right)
        self.assertEqual(left.estimate(), 2)

    def test_hll_invalid(self):
        for value in ['???', 'AA==', HLL().encode().rstrip('=')]:
            with self.assertRaises(ValueError):
                HLL.decode(value)
        with self.assertRaises(ValueError):
            HLL(bytes([54]) * 4096)

    def test_canonical_checksum(self):
        self.assertEqual(canonical({'z': '1', 'a': None}), b'{"a":null,"z":"1"}')
        self.assertEqual(checksum([]), hashlib.sha256(b'').hexdigest())
        row = {'kind': 'COUNTER', 'recordId': record_id({'a': '1'})}
        self.assertEqual(checksum([row]), hashlib.sha256(canonical(row) + b'\n').hexdigest())
        for value in [1, 1.0, {'x': 1}]:
            with self.assertRaises(ValueError):
                canonical(value)


class ParsingTest(unittest.TestCase):
    def event(self, **updates):
        data = {'time_iso8601': '2026-10-27T16:01:02Z', 'uri': '/api/user/123?token=secret',
                'request_method': 'GET', 'status': '200', 'body_bytes_sent': '10', 'request_time': '0.001',
                'remote_addr': '8.8.8.8', 'http_user_agent': 'secret desktop', 'authorization': 'secret'}
        data.update(updates)
        return json.dumps(data).encode()

    def test_strict_json(self):
        for raw in [b'{"a":1,"a":2}', b'{"a":NaN}', b'{"a":"\\x"}', b'\xff', b'[]', b'\xef\xbb\xbf{}']:
            with self.subTest(raw=raw), self.assertRaises(Rejected):
                strict_json(raw)

    def test_privacy_default(self):
        event = parse_event(self.event(), PrivacyPolicy())
        self.assertEqual(event['region_code'], 'UNKNOWN')
        self.assertEqual(event['path_template'], 'UNMATCHED')
        self.assertEqual(event['business_date'], '2026-10-28')
        self.assertNotIn('secret', str(event))
        self.assertNotIn('8.8.8.8', str(event))
        self.assertNotIn('/api/user/123', str(event))

    def test_templates_priority(self):
        policy = PrivacyPolicy([PathRule('/api/.*', '/api/{other}', 'API'), PathRule('/api/risk/.*', '/api/risk/{other}', 'RISK_INTERNAL')])
        self.assertEqual(policy.path('/api/risk/test?a=secret')[1], 'RISK_INTERNAL')
        self.assertEqual(policy.path('/unmatched/secret'), ('UNMATCHED', 'OTHER'))

    def test_fake_forwarded(self):
        policy = PrivacyPolicy(trusted_proxies=['10.0.0.0/8'])
        self.assertIsNone(policy.source('8.8.8.8', '1.1.1.1'))
        self.assertEqual(policy.source('10.0.0.1', '1.1.1.1, 10.0.0.2'), '1.1.1.1')
        self.assertIsNone(policy.source('10.0.0.1', 'invalid'))

    def test_geo_offline(self):
        policy = PrivacyPolicy(direct_peer_trusted=True)
        self.assertEqual(policy.region('10.0.0.1'), 'INTERNAL')
        self.assertEqual(policy.region('8.8.8.8'), 'UNKNOWN')
        self.assertEqual(PrivacyPolicy(geo=lambda _: 'CN-31').region('8.8.8.8'), 'CN-31')

    def test_status_separation(self):
        event = parse_event(self.event(status=304, upstream_status='502, 504, 200'), PrivacyPolicy())
        self.assertEqual(event['status'], 304)
        self.assertEqual(event['upstream_failure_count'], 2)

    def test_missing_unknown(self):
        event = parse_event(self.event(status='-', request_time='-', body_bytes_sent='-'), PrivacyPolicy())
        self.assertIsNone(event['status'])
        self.assertIsNone(event['duration_micros'])
        self.assertIsNone(event['bytes_sent'])

    def test_rejection_safe(self):
        with self.assertRaises(Rejected) as caught:
            parse_event(self.event(time_iso8601='secret'), PrivacyPolicy())
        self.assertNotIn('secret', str(caught.exception))
        for update in [{'status': 'secret'}, {'request_time': -1}]:
            event = parse_event(self.event(**update), PrivacyPolicy())
            self.assertIn('INVALID_NUMBER', event['quality'])
            self.assertNotIn('secret', str(event))

    def test_invalid_time_does_not_mutate_hll(self):
        hll = HLL()
        with self.assertRaises(Rejected):
            parse_event(self.event(time_iso8601='secret'), PrivacyPolicy(direct_peer_trusted=True), hll, b'key')
        self.assertEqual(hll.estimate(), 0)


class TailerTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = Path(self.tmp.name) / 'sample.log'

    def reader(self, **kwargs):
        reader = FileTailer(self.path, **kwargs)
        self.addCleanup(reader.close)
        return reader

    def test_partial_restart(self):
        self.path.write_bytes(b'one\ntw')
        reader = self.reader()
        first = reader.prepare()
        reader.acknowledge(first)
        checkpoint = reader.checkpoint
        self.assertIsNone(reader.prepare())
        reader.close()
        with self.path.open('ab') as stream:
            stream.write(b'o\n')
        resumed = self.reader(checkpoint=checkpoint)
        self.assertEqual(resumed.prepare().raw, b'two\n')

    def test_failure_replay_and_stale_ack(self):
        self.path.write_bytes(b'one\n')
        reader = self.reader()
        candidate = reader.prepare()
        self.assertIs(reader.prepare(), candidate)
        self.assertEqual(reader.checkpoint.offset, 0)
        reader.acknowledge(candidate)
        with self.assertRaises(RuntimeError):
            reader.acknowledge(candidate)

    def test_rename_rotation(self):
        self.path.write_bytes(b'old\n')
        reader = self.reader()
        first = reader.prepare()
        self.path.rename(self.path.with_suffix('.1'))
        self.path.write_bytes(b'new\n')
        reader.acknowledge(first)
        rotation = reader.prepare()
        self.assertEqual(rotation.reason, 'SOURCE_ROTATED')
        reader.acknowledge(rotation)
        self.assertEqual(reader.prepare().raw, b'new\n')

    def test_restart_renamed_inode(self):
        self.path.write_bytes(b'old\nmore\n')
        reader = self.reader()
        reader.acknowledge(reader.prepare())
        checkpoint = reader.checkpoint
        reader.close()
        self.path.rename(self.path.with_suffix('.1'))
        self.path.write_bytes(b'new\n')
        self.assertEqual(self.reader(checkpoint=checkpoint).prepare().raw, b'more\n')

    def test_truncation(self):
        self.path.write_bytes(b'long line\n')
        reader = self.reader()
        reader.acknowledge(reader.prepare())
        self.path.write_bytes(b'x\n')
        change = reader.prepare()
        self.assertEqual(change.reason, 'SOURCE_TRUNCATED')
        reader.acknowledge(change)
        self.assertEqual(reader.prepare().raw, b'x\n')

    def test_oversized_and_half_line(self):
        self.path.write_bytes(b'123456789')
        reader = self.reader(max_line_bytes=4)
        self.assertIsNone(reader.prepare())
        with self.path.open('ab') as stream:
            stream.write(b'\nOK\n')
        candidate = reader.prepare()
        self.assertEqual(candidate.reason, 'LINE_TOO_LONG')
        self.assertIsNone(candidate.raw)
        reader.acknowledge(candidate)
        self.assertEqual(reader.prepare().raw, b'OK\n')

    def test_lost_checkpoint_file_fails_closed(self):
        self.path.write_bytes(b'one\n')
        reader = self.reader()
        reader.acknowledge(reader.prepare())
        checkpoint = reader.checkpoint
        reader.close()
        self.path.unlink()
        self.path.write_bytes(b'new\n')
        # inode reuse is possible; use a definitely absent identity.
        from dataclasses import replace
        with self.assertRaises(RuntimeError):
            self.reader(checkpoint=replace(checkpoint, inode=-1)).prepare()


if __name__ == '__main__':
    unittest.main()

class ConfigTest(unittest.TestCase):
    def test_safe_defaults(self):
        from risk.config import load_config
        config = load_config('examples/config.example.json')
        self.assertEqual(config.sources, ())
        self.assertIsNone(config.privacy.source('8.8.8.8'))

    def test_invalid_config(self):
        from risk.config import load_config
        cases = [{'sources': [{'alias': 'secret/path', 'path': '/tmp/sample'}]},
                 {'sources': [{'alias': 'sample', 'path': 'relative'}]},
                 {'directPeerTrusted': 'true'}, {'maxLineBytes': True}, {'password': 'secret'}]
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'config.json'
            for value in cases:
                path.write_text(json.dumps(value))
                with self.assertRaises(ValueError):
                    load_config(path)
