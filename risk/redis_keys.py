"""Canonical Redis key segments; identities remain unchanged in payloads and hash fields."""


def key_segment(value, *, max_bytes=256):
    if not isinstance(value, str):
        raise ValueError('INVALID_KEY_SEGMENT')
    try:
        raw = value.encode('utf-8', errors='strict')
    except UnicodeError:
        raise ValueError('INVALID_KEY_SEGMENT') from None
    if not raw or len(raw) > max_bytes:
        raise ValueError('INVALID_KEY_SEGMENT')
    return raw.hex().upper()
