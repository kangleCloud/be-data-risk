import unittest
from risk.algorithms import HLL
from risk.ip_address import canonical_ip
from risk.parsing import PrivacyPolicy


class CanonicalIpTest(unittest.TestCase):
    def test_ipv4_mapped_variants_have_one_identity(self):
        for value in ['192.0.2.1', '::ffff:192.0.2.1', '::FFFF:C000:0201']:
            self.assertEqual(canonical_ip(value), '192.0.2.1')

    def test_ipv6_is_compressed_lowercase(self):
        self.assertEqual(canonical_ip('2001:0DB8:0000:0000:0000:0000:0000:0001'), '2001:db8::1')

    def test_invalid_values_have_safe_error(self):
        for value in ['private.example.invalid', '192.168.001.1', 'fe80::1%eth0', '[::1]', '', None]:
            with self.subTest(value=value), self.assertRaises(ValueError) as caught:
                canonical_ip(value)
            self.assertEqual(str(caught.exception), 'INVALID_IP')

    def test_trusted_source_returns_normalized_ip_only_after_trust_check(self):
        self.assertIsNone(PrivacyPolicy().source('::ffff:192.0.2.1'))
        self.assertEqual(PrivacyPolicy(direct_peer_trusted=True).source('::ffff:192.0.2.1'), '192.0.2.1')
        # Existing proxy membership decisions are preserved; normalization does not broaden trust.
        policy = PrivacyPolicy(trusted_proxies=['10.0.0.0/8'])
        self.assertIsNone(policy.source('192.0.2.1', '198.51.100.1'))
        self.assertEqual(policy.source('10.0.0.1', '::ffff:192.0.2.1'), '192.0.2.1')

    def test_existing_hll_algorithm_receives_equivalent_normalized_inputs(self):
        results=[]
        for value in ['192.0.2.1','::ffff:192.0.2.1']:
            hll=HLL();hll.add(b'synthetic-test-only-key','2026-10-30',canonical_ip(value));results.append(hll.encode())
        self.assertEqual(results[0], results[1])
