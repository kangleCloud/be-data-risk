"""Offline actual Collector -> Lua publication fixture; only synthetic local data."""
from pathlib import Path
import json
import sys
import tempfile
from unittest.mock import patch
import uuid
import fakeredis

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from risk.config import Config, SourceConfig
from risk.parsing import PrivacyPolicy
from risk.service import Collector
from risk.storage import RedisStore
from risk.ownership import CollectorOwnership
from risk.geo import fallback_outcome
from risk.protocol import validate_envelope

NOW='2026-11-03T12:00:00.000+08:00'


def export():
    calls=[]
    class SyntheticGeo:
        def resolve_many(self, addresses, budget):
            calls.append(list(addresses))
            return {address: fallback_outcome(address) for address in addresses}
    geo=SyntheticGeo()
    def log(at='2026-11-03T11:00:59.999+08:00',uri='/api/行情/查询?token=synthetic-secret',address='114.247.50.2',status='200'):
        return {'@timestamp':at,'uri':uri,'remote_addr':address,'http_x_forwarded_for':'9.9.9.9',
                'status':status,'request_method':'GET'}
    inputs=[log(at='2026-11-02T23:59:59.999+08:00',status='499'),log(),log(),
            log(status='302'),log(status='499'),log(status='503'),log(status='101'),
            log(address='invalid-peer',status='-'),log(address='::FFFF:C000:0201'),
            log(address='2001:4860:4860::8888'),log(address='1.1.1.1'),
            log(uri='/market/dashboard/stream'),log(uri='/'),log(uri='/assets/app.js'),
            log(uri='/scheduler/api/internal/risk/geo/resolve-batch'),log(uri='/admin/api/risk/dashboard'),
            log(at='2026-11-04T00:00:00.000+08:00',uri='/api/token/synthetic-secret-value',status='204')]
    client=fakeredis.FakeRedis(decode_responses=True)
    owner=CollectorOwnership(client, 'fixture-collector')
    owner.acquire()
    with tempfile.TemporaryDirectory() as folder:
        path=Path(folder)/'synthetic.log'
        path.write_bytes(b''.join(json.dumps(row,ensure_ascii=False).encode()+b'\n' for row in inputs))
        config=Config((SourceConfig('fixture',path),),PrivacyPolicy(direct_peer_trusted=True),65536)
        ids=iter(uuid.UUID(int=i) for i in range(1,50))
        with patch('risk.service.uuid.uuid4',side_effect=lambda:next(ids)):
            collector=Collector(RedisStore(client, owner),config,clock=lambda:NOW,geo=geo)
            try:
                while collector.tick():pass
                collector.close()
            finally:collector.close(flush=False)
        batches=[]
        for key in sorted(client.scan_iter('risk:batch:*')):
            value=json.loads(client.get(key));validate_envelope(value);batches.append(value)
        checkpoint=json.loads(client.hget('risk:checkpoints','fixture'))
        assert int(checkpoint['offset'])==path.stat().st_size
    client.close()
    result={'synthetic':True,'batches':batches,'inputLines':len(inputs),'acceptedRequests':17,
            'geoLookupCalls':calls,'expected':{'requestCount':'17','successCount':'12','failureCount':'3','otherCount':'2',
             'sourceCount':'4','interfaceCount':'7','filteredLines':'0'},
            'canonicalEnvelopes':[json.dumps(v,sort_keys=True,ensure_ascii=False,separators=(',',':')) for v in batches]}
    assert sum(int(row['requestCount']) for batch in batches for row in batch['records'] )==17
    return result


if __name__=='__main__':
    destination=Path(sys.argv[1] if len(sys.argv)>1 else '/tmp/risk-minute-python-envelope.json')
    destination.write_text(json.dumps(export(),ensure_ascii=False,indent=2)+'\n')
    print(str(destination))
