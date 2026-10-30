"""Deterministic algorithms shared by the risk v1 contract."""
import base64
import hashlib
import hmac
import ipaddress
import json
from decimal import Decimal, InvalidOperation, ROUND_HALF_UP, localcontext
import math
import re

BOUNDS = (0, 1000, 2000, 5000, 10000, 20000, 50000, 100000, 200000,
          500000, 1000000, 2000000, 5000000, 10000000, 30000000, 60000000,
          120000000, 300000000, 600000000, 1800000000, 3600000000,
          10800000000, 43200000000)


def number(value):
    """Finite nonnegative decimal; missing values stay unknown."""
    if value is None or value == '-':
        return None
    if isinstance(value, bool) or not isinstance(value, (str, int, Decimal)):
        raise ValueError('INVALID_NUMBER')
    if isinstance(value, str) and not re.fullmatch(r'(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?', value):
        raise ValueError('INVALID_NUMBER')
    try:
        result = Decimal(value)
    except (InvalidOperation, ValueError):
        raise ValueError('INVALID_NUMBER') from None
    if not result.is_finite() or result < 0 or result.adjusted() > 30:
        raise ValueError('INVALID_NUMBER')
    return result


def micros(value):
    parsed = number(value)
    if parsed is None:
        return None
    with localcontext() as context:
        context.prec = 60
        return int((parsed * 1000000).quantize(Decimal(1), rounding=ROUND_HALF_UP))


def bucket(value):
    if value is None:
        return None
    for index, upper in enumerate(BOUNDS):
        if value <= upper:
            return index
    return len(BOUNDS)


def p95(histogram):
    if len(histogram) != len(BOUNDS) + 1 or any(type(v) is not int or v < 0 for v in histogram):
        raise ValueError('INVALID_HISTOGRAM')
    total = sum(histogram)
    if not total:
        return None, False
    threshold = (total * 95 + 99) // 100
    cumulative = 0
    for index, count in enumerate(histogram):
        cumulative += count
        if cumulative >= threshold:
            return (BOUNDS[index], False) if index < len(BOUNDS) else (None, True)


def canonical(value):
    def validate(item):
        if item is None or isinstance(item, (str, bool)):
            return
        if isinstance(item, list):
            for entry in item:
                validate(entry)
            return
        if isinstance(item, dict) and all(isinstance(key, str) and key.isascii() for key in item):
            for key, entry in item.items():
                if key == 'schemaVersion':
                    if type(entry) is not int or entry != 1:
                        raise ValueError('NON_CANONICAL_SCHEMA_VERSION')
                else:
                    validate(entry)
            return
        raise ValueError('NON_CANONICAL_VALUE')
    validate(value)
    return json.dumps(value, sort_keys=True, ensure_ascii=True, separators=(',', ':'), allow_nan=False).encode('utf-8')


def record_id(dimensions):
    return hashlib.sha256(canonical(dimensions)).hexdigest()


def checksum(records):
    ordered = sorted(records, key=lambda row: (row['kind'], row['recordId']))
    return hashlib.sha256(b''.join(canonical(row) + b'\n' for row in ordered)).hexdigest()


class HLL:
    def __init__(self, registers=None):
        self.registers = bytearray(4096) if registers is None else bytearray(registers)
        if len(self.registers) != 4096 or any(value > 53 for value in self.registers):
            raise ValueError('INVALID_HLL')

    def add(self, key, business_date, address):
        canonical_ip = ipaddress.ip_address(address).compressed.lower()
        digest = hmac.new(key, (business_date + '\n' + canonical_ip).encode(), hashlib.sha256).digest()
        hashed = int.from_bytes(digest[:8], 'big')
        index, remaining = hashed >> 52, hashed & ((1 << 52) - 1)
        rank = 53 - remaining.bit_length() if remaining else 53
        self.registers[index] = max(self.registers[index], rank)

    def merge(self, other):
        self.registers[:] = bytes(map(max, self.registers, other.registers))

    def encode(self):
        return base64.b64encode(self.registers).decode('ascii')

    @classmethod
    def decode(cls, value):
        try:
            raw = base64.b64decode(value, validate=True)
            if base64.b64encode(raw).decode() != value:
                raise ValueError('INVALID_HLL')
            return cls(raw)
        except (ValueError, TypeError):
            raise ValueError('INVALID_HLL') from None

    def estimate(self):
        count = 4096
        raw = (0.7213 / (1 + 1.079 / count)) * count * count / sum(2.0 ** -v for v in self.registers)
        zeros = self.registers.count(0)
        estimate = count * math.log(count / zeros) if raw <= 2.5 * count and zeros else raw
        return int(Decimal(str(estimate)).quantize(Decimal(1), rounding=ROUND_HALF_UP))
