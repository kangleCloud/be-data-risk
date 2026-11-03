"""Fixed configured destinations only. All tokens synthetic; zero network I/O."""
import json
from pathlib import Path
import tempfile
import time
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch
from risk.config import load_config
from risk.geo import InternalBatchHttp

PATH='/scheduler/api/internal/risk/geo/resolve-batch'
TOKEN='synthetic-v121-token-never-a-real-credential'

class ConfiguredDestinationTest(unittest.TestCase):
    def test_fixed_ip_address_categories_accepted_without_network(self):
        for host in ['127.0.0.1','10.0.0.1','192.168.1.1','8.8.8.8','198.51.100.10','[2001:4860:4860::8888]']:
            for scheme in ['http','https']:
                with self.subTest(host=host,scheme=scheme):
                    transport=InternalBatchHttp(scheme+'://'+host+':19004'+PATH,TOKEN)
                    self.assertEqual(transport.url,scheme+'://'+host+':19004'+PATH)

    def test_fixed_destination_and_synthetic_header_even_response_contains_url(self):
        for host in ['127.0.0.1','8.8.8.8','[2001:4860:4860::8888]']:
            with self.subTest(host=host):
                url='https://'+host+':19004'+PATH
                transport=InternalBatchHttp(url,TOKEN)
                response=Mock();response.status=200
                response.__enter__=Mock(return_value=response);response.__exit__=Mock(return_value=False)
                response.fp=SimpleNamespace(raw=SimpleNamespace(_sock=Mock()))
                response.read1.side_effect=[b'{"url":"http://203.0.113.50/other"}',b'']
                transport.opener=Mock();transport.opener.open.return_value=response
                transport(['1.1.1.1'],time.monotonic()+.1)
                transport.opener.open.assert_called_once()
                request=transport.opener.open.call_args.args[0]
                self.assertEqual(request.full_url,url)
                self.assertEqual(request.get_header('X-risk-geo-token'),TOKEN)
                self.assertEqual(json.loads(request.data),{'items':[{'ip':'1.1.1.1','trusted':True}]})

    def test_token_required_for_private_and_public_targets(self):
        for host in ['127.0.0.1','8.8.8.8']:
            for token in [None,'','   ',123,'bad\rheader','bad\nheader']:
                with self.subTest(host=host,token=repr(token)),self.assertRaises(ValueError):
                    InternalBatchHttp('https://'+host+PATH,token)

    def test_unsupported_urls_rejected_without_network(self):
        for url in ['ftp://8.8.8.8'+PATH,'https://example.invalid'+PATH,'https://user:secret@8.8.8.8'+PATH,'https://8.8.8.8'+PATH+'?url=x','https://8.8.8.8'+PATH+'#x','https://8.8.8.8/wrong','https://8.8.8.8:bad'+PATH,'https://0.0.0.0'+PATH,'https://224.0.0.1'+PATH,'https://[::]'+PATH,'https://[::1]'+PATH]:
            with self.subTest(url=url),self.assertRaises(ValueError):InternalBatchHttp(url,TOKEN)

    def test_public_target_from_explicit_config_only(self):
        with tempfile.TemporaryDirectory() as folder:
            path=Path(folder)/'.env'
            path.write_text('GEO_SERVICE_URL=https://8.8.8.8:19004'+PATH+'\nGEO_SERVICE_TOKEN='+TOKEN+'\n')
            cfg=load_config(path)
            self.assertEqual(cfg.geo_service_url,'https://8.8.8.8:19004'+PATH)
            self.assertNotIn(TOKEN,repr(cfg))

    def test_redirect_and_environment_proxies_disabled(self):
        with patch.dict('os.environ',{'HTTPS_PROXY':'http://203.0.113.50:9000','HTTP_PROXY':'http://203.0.113.50:9000'}):
            transport=InternalBatchHttp('https://8.8.8.8'+PATH,TOKEN)
            from risk.geo import _NoRedirect
            self.assertTrue(any(isinstance(handler,_NoRedirect) for handler in transport.opener.handlers))
            self.assertFalse(any(getattr(handler,'proxies',{}) for handler in transport.opener.handlers))
            self.assertIsNone(_NoRedirect().redirect_request(None,None,302,'',{},'http://203.0.113.50'))
