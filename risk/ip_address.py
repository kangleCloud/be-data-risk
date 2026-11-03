"""Canonical IP text for trusted-source transport; no lookup or policy decisions."""
import ipaddress


def canonical_ip(value):
    if not isinstance(value, str) or '%' in value:
        raise ValueError('INVALID_IP')
    try:
        parsed = ipaddress.ip_address(value)
    except ValueError:
        raise ValueError('INVALID_IP') from None
    if isinstance(parsed, ipaddress.IPv6Address) and parsed.ipv4_mapped is not None:
        parsed = parsed.ipv4_mapped
    return parsed.compressed.lower()


def public_ip(value):
    """Transport eligibility only; no country/provider/Geo result inference."""
    parsed = ipaddress.ip_address(canonical_ip(value))
    return bool(parsed.is_global and not parsed.is_multicast and not parsed.is_reserved
                and not parsed.is_unspecified and not parsed.is_loopback and not parsed.is_link_local
                and not getattr(parsed, 'is_site_local', False))
