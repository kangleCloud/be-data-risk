import json
from pathlib import Path
import tempfile
import unittest
from risk.config import load_config


class EnvConfigTest(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        self.path=Path(self.tmp.name)/'.env'

    def test_current_example_reading_defaults(self):
        cfg=load_config('.env.example')
        self.assertEqual(cfg.sources,())
        self.assertEqual(cfg.redis_url,'redis://localhost:6379/2')
        self.assertIsNone(cfg.hmac_key)
        self.assertTrue(cfg.privacy.direct_peer_trusted)

    def test_multiple_sources_and_current_grouping_fields(self):
        sources=[{'alias':'first','path':str(Path(self.tmp.name)/'first.log')},
                 {'alias':'second','path':str(Path(self.tmp.name)/'second.log')}]
        self.path.write_text("SOURCES='"+json.dumps(sources)+"'\nPATH_RULES='[{\"pattern\":\"/api/.*\",\"template\":\"/api/{id}\"}]'\nDIRECT_PEER_TRUSTED=true\nPOLL_MILLIS=300\n")
        cfg=load_config(self.path)
        self.assertEqual([s.alias for s in cfg.sources],['first','second'])
        self.assertEqual(cfg.poll_millis,300)
        self.assertEqual(cfg.privacy.path('/api/123')[0],'/api/{id}')

    def test_invalid_unknown_duplicate_and_conflicting_values_safe(self):
        cases=['UNKNOWN_FIELD=synthetic-secret','POLL_MILLIS=false','DIRECT_PEER_TRUSTED=1',
               'POLL_MILLIS=200\nPOLL_MILLIS=300',"SOURCES='[]'\nSOURCE_LOG_PATH=/tmp/sample.log",
               'REDIS_URL=localhost\nREDIS_PORT=0','REDIS_URL=localhost\nREDIS_DB=-1',
               "REDIS_URL='redis://localhost:6379/2'",'REDIS_PASSWORD=synthetic-secret']
        for value in cases:
            self.path.write_text(value)
            with self.subTest(case=value),self.assertRaises(ValueError) as caught:load_config(self.path)
            self.assertNotIn('synthetic-secret',str(caught.exception))

    def test_values_not_executed_or_interpolated(self):
        value='synthetic-key-${HOST}-$(touch sentinel)-32-bytes'
        self.path.write_text("HMAC_KEY='"+value+"'\n")
        self.assertEqual(load_config(self.path).hmac_key,value)
        self.assertFalse((Path(self.tmp.name)/'sentinel').exists())

    def test_flat_password_encoding_and_trusted_proxies(self):
        self.path.write_text("REDIS_URL=localhost\nREDIS_PASSWORD='synthetic@pass# /'\nREDIS_PORT=6380\nREDIS_DB=2\nTRUSTED_PROXIES=10.0.0.0/8,192.168.0.0/16\n")
        cfg=load_config(self.path)
        self.assertEqual(cfg.redis_url,'redis://:synthetic%40pass%23%20%2F@localhost:6380/2')
        self.assertEqual(len(cfg.privacy.networks),2)
        self.assertNotIn('synthetic',repr(cfg))

    def test_ipv6_acl_and_json_connection_capabilities(self):
        self.path.write_text('REDIS_URL=::1\nREDIS_USERNAME=synthetic-user\nREDIS_PASSWORD=synthetic-pass\n')
        cfg=load_config(self.path)
        self.assertEqual(cfg.redis_url,'redis://synthetic-user:synthetic-pass@[::1]:6379/2')
        self.assertNotIn('synthetic-pass',repr(cfg))
        path=Path(self.tmp.name)/'config.json'
        for uri in ['rediss://fake.invalid:1/3','unix:///tmp/fake.sock?db=3']:
            path.write_text(json.dumps({'redisUrl':uri,'sources':[]}))
            self.assertEqual(load_config(path).redis_url,uri)

    def test_inline_key_preserves_bytes_without_repr(self):
        secret='synthetic-direct-hmac-key-with-#-and-spaces 123'
        self.path.write_text("HMAC_KEY='"+secret+"'\n")
        cfg=load_config(self.path)
        self.assertEqual(cfg.hmac_key,secret);self.assertNotIn(secret,repr(cfg))

    def test_invalid_key_type_or_length_safe(self):
        path=Path(self.tmp.name)/'config.json'
        for value in ['synthetic-short',123,True]:
            path.write_text(json.dumps({'hmacKey':value}))
            with self.assertRaisesRegex(ValueError,'INVALID_HMAC_KEY'):load_config(path)
