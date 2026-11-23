from unittest import TestCase
from unittest.mock import patch

from fakeredis import FakeRedis
from redis.exceptions import TimeoutError

from risk.storage import HTTP_QUEUE, RedisStore
from tools.rebuild_redis import reset


class HttpQueueTest(TestCase):
    def test_evicts_oldest_records_and_preview_preserves_other_namespaces(self):
        client = FakeRedis(decode_responses=True)
        store = RedisStore(client)
        with patch('risk.storage.QUEUE_LIMIT', 2):
            self.assertTrue(store.publish('source', 'position', ['one', 'two', 'three']))
        self.assertEqual(client.lrange(HTTP_QUEUE, 0, -1), ['two', 'three'])
        client.set('geoip:result:example', 'cache')
        client.set('market:cache', 'other')
        self.assertEqual(reset(client, batch_size=1)['counts'], {'risk:*': 2, 'geoip:*': 1})
        self.assertEqual(client.llen(HTTP_QUEUE), 2)
        self.assertEqual(reset(client, execute=True, batch_size=1)['counts'], {'risk:*': 2, 'geoip:*': 1})
        self.assertEqual(client.keys('*'), ['market:cache'])

    def test_uncertain_enqueue_is_not_retried_and_checkpoint_is_durable(self):
        client = FakeRedis(decode_responses=True)
        store = RedisStore(client)
        with patch.object(client, 'pipeline', side_effect=TimeoutError) as pipeline:
            self.assertFalse(store.publish('source', 'position', ['record']))
            pipeline.assert_called_once_with(transaction=False)
        self.assertEqual(store.checkpoint('source'), 'position')
