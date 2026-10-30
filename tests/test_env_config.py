import json
from pathlib import Path
import tempfile
import unittest
from risk.config import load_config


class EnvConfigTest(unittest.TestCase):
    def test_example_has_no_sources_and_matches_reading_defaults(self):
        env = load_config('.env.example')
        old = load_config('examples/config.example.json')
        self.assertEqual(env.sources, old.sources)
        self.assertEqual(env.redis_url, 'redis://localhost:6379/2')
        self.assertIsNone(env.hmac_key_file)
        self.assertEqual(env.max_line_bytes, old.max_line_bytes)
        self.assertEqual(env.poll_millis, old.poll_millis)
        self.assertFalse(env.privacy.direct_peer_trusted)

    def test_quoted_structured_fields_and_secret_url(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / '.env'
            source = str(Path(directory) / 'synthetic.log')
            path.write_text("RISK_SOURCES='" + json.dumps([{'alias':'synthetic','path':source}]) + "'\n"
                            "RISK_REDIS_URL='redis://user:synthetic%23secret@fake.invalid:1/0'\n"
                            "RISK_TRUSTED_PROXIES='[\"10.0.0.0/8\"]'\n"
                            "RISK_DIRECT_PEER_TRUSTED=true # explicit\n"
                            "RISK_POLL_MILLIS=300\n")
            config = load_config(path)
            self.assertEqual(config.sources[0].path, Path(source))
            self.assertTrue(config.privacy.direct_peer_trusted)
            self.assertEqual(config.poll_millis, 300)
            self.assertNotIn('synthetic%23secret', repr(config))

    def test_invalid_or_duplicate_values_expose_only_safe_error(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / '.env'
            for text in ["PASSWORD=synthetic-secret", "RISK_REDIS_URL='synthetic-secret", 'RISK_SOURCES=not-json-secret',
                         "RISK_REDIS_URL='a'\nRISK_REDIS_URL='b'", 'RISK_POLL_MILLIS=false', 'RISK_DIRECT_PEER_TRUSTED=1']:
                path.write_text(text)
                with self.subTest(text=text), self.assertRaises(ValueError) as caught:
                    load_config(path)
                self.assertNotIn('synthetic-secret', str(caught.exception))

    def test_values_are_not_executed_or_interpolated(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / '.env'
            path.write_text("RISK_REDIS_URL='redis://${HOST}:1/0'\n")
            self.assertEqual(load_config(path).redis_url, 'redis://${HOST}:1/0')
            path.write_text("RISK_REDIS_URL='redis://$(touch sentinel):1/0'\n")
            self.assertEqual(load_config(path).redis_url, 'redis://$(touch sentinel):1/0')
            self.assertFalse((Path(directory) / 'sentinel').exists())

    def test_flat_reference_style_and_automatic_password_encoding(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / '.env.dev'
            source = str(Path(directory) / 'synthetic.log')
            path.write_text("REDIS_URL=localhost\nREDIS_PASSWORD='synthetic@pass# /'\nREDIS_PORT=6380\nREDIS_DB=2\n"
                            "SOURCE_ID=nginx_access\nSOURCE_LOG_PATH='" + source + "'\n"
                            "TRUSTED_PROXIES=10.0.0.0/8,192.168.0.0/16\nDIRECT_PEER_TRUSTED=false\n")
            config = load_config(path)
            self.assertEqual(config.redis_url, 'redis://:synthetic%40pass%23%20%2F@localhost:6380/2')
            self.assertEqual(config.sources[0].alias, 'nginx_access')
            self.assertEqual(config.sources[0].path, Path(source))
            self.assertEqual(len(config.privacy.networks), 2)
            self.assertNotIn('synthetic%40pass%23%20%2F', repr(config))
            self.assertNotIn('synthetic@pass# /', repr(config))

    def test_conflicting_formats_and_bad_connection_are_rejected(self):
        values = ["REDIS_URL=localhost\nRISK_REDIS_URL='redis://fake.invalid:1/0'",
                  "REDIS_URL=localhost\nREDIS_PORT=0", "REDIS_URL=localhost\nREDIS_DB=-1",
                  "REDIS_URL='redis://localhost:6379/2'", "REDIS_PASSWORD=secret",
                  "SOURCE_LOG_PATH=/tmp/synthetic.log\nRISK_SOURCES='[]'",
                  "POLL_MILLIS=200\nRISK_POLL_MILLIS=300"]
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / '.env.prod'
            for text in values:
                path.write_text(text)
                with self.subTest(text=text), self.assertRaises(ValueError):
                    load_config(path)

    def test_flat_ipv6_acl_and_legacy_json_still_work(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / '.env.prod'
            path.write_text("REDIS_URL=::1\nREDIS_USERNAME=synthetic-user\nREDIS_PASSWORD=synthetic-pass\n")
            config = load_config(path)
            self.assertEqual(config.redis_url, 'redis://synthetic-user:synthetic-pass@[::1]:6379/2')
            self.assertNotIn('synthetic-pass', repr(config))
            path = Path(directory) / 'config.json'
            path.write_text('{"redisUrl":"rediss://fake.invalid:1/3","sources":[]}')
            self.assertEqual(load_config(path).redis_url, 'rediss://fake.invalid:1/3')
