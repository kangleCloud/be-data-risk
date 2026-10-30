"""Packaged, frozen protocol assets and strict record validation."""
from datetime import datetime
import hashlib
import json
from pathlib import Path

from jsonschema import Draft202012Validator, FormatChecker
from .algorithms import HLL, canonical, record_id
from .paths import valid_stored_path

ASSETS = Path(__file__).with_name('assets')
PROTOCOL_VERSION = 'risk-v1-20261028-immutable-r1'


def asset(name):
    return (ASSETS / name).read_text(encoding='utf-8')


def verify_assets():
    manifest = json.loads(asset('risk-v1/sha256.json'))
    for name, digest in manifest.items():
        payload = (ASSETS / 'risk-v1' / name).read_bytes()
        if hashlib.sha256(payload).hexdigest() != digest:
            raise ValueError('PROTOCOL_ASSET_MISMATCH')


_SCHEMA = Draft202012Validator(json.loads(asset('risk-v1/record.schema.json')), format_checker=FormatChecker())


def validate_record(record, encoded=None):
    # Never propagate JSON-schema errors: they embed original offending values.
    if not _SCHEMA.is_valid(record):
        raise ValueError('INVALID_RECORD')
    if type(record['schemaVersion']) is not int or record['schemaVersion'] != 1:
        raise ValueError('INVALID_RECORD')
    dimensions = record['dimensions']
    if any(not isinstance(value, str) or len(value) > 512 or not value.isascii() for key, value in dimensions.items() if key != 'pathTemplate'):
        raise ValueError('INVALID_RECORD')
    if 'pathTemplate' in dimensions and not valid_stored_path(dimensions['pathTemplate']):
        raise ValueError('INVALID_RECORD')
    if dimensions['kind'] != record['kind'] or record_id(dimensions) != record['recordId']:
        raise ValueError('INVALID_RECORD')
    if encoded is not None and canonical(record).decode() != encoded:
        raise ValueError('NON_CANONICAL_RECORD')
    if record['kind'] == 'COUNTER':
        count, valid = int(record['requestCount']), int(record['durationValidCount'])
        if sum(map(int, record['histogram'])) != valid or valid > count or int(record['bytesValidCount']) > count:
            raise ValueError('INVALID_RECORD')
        if valid == 0 and int(record['durationSumMicros']) != 0:
            raise ValueError('INVALID_RECORD')
        if int(record['bytesValidCount']) == 0 and int(record['bytesSum']) != 0:
            raise ValueError('INVALID_RECORD')
    if record['kind'] == 'SOURCE':
        HLL.decode(record['registersBase64'])
    for field in ('minuteAt', 'firstAt', 'lastAt'):
        value = dimensions.get(field, record.get(field))
        if value is not None:
            try:
                instant = datetime.fromisoformat(value)
                if instant.date().isoformat() != dimensions['businessDate']:
                    raise ValueError()
                if field == 'minuteAt' and (instant.second or instant.microsecond):
                    raise ValueError()
            except (TypeError, ValueError):
                raise ValueError('INVALID_RECORD') from None
    if record['kind'] == 'EXCEPTION' and record['firstAt'] > record['lastAt']:
        raise ValueError('INVALID_RECORD')


verify_assets()

# Resolve the local record schema in memory; never fetch schema references over network.
_ENVELOPE_SCHEMA = json.loads(asset('risk-v1/envelope.schema.json'))
_ENVELOPE_SCHEMA['properties']['records']['items'] = _SCHEMA.schema
_ENVELOPE = Draft202012Validator(_ENVELOPE_SCHEMA, format_checker=FormatChecker())
MAX_RECORDS = 500
MAX_BYTES = 1048576


def validate_envelope(envelope, encoded=None):
    from .algorithms import checksum
    if not _ENVELOPE.is_valid(envelope) or type(envelope['schemaVersion']) is not int:
        raise ValueError('INVALID_ENVELOPE')
    rows = envelope['records']
    if envelope['recordCount'] != str(len(rows)) or len(rows) > MAX_RECORDS:
        raise ValueError('INVALID_ENVELOPE')
    order = [(row['kind'], row['recordId']) for row in rows]
    if order != sorted(order) or len({row['recordId'] for row in rows}) != len(rows):
        raise ValueError('INVALID_ENVELOPE')
    for row in rows:
        validate_record(row)
        if row['dimensions']['businessDate'] != envelope['businessDate'] or (row['kind'] == 'SOURCE' and row['keyId'] != envelope['keyId']):
            raise ValueError('INVALID_ENVELOPE')
    if checksum(rows) != envelope['checksum']:
        raise ValueError('INVALID_ENVELOPE')
    try:
        datetime.fromisoformat(envelope['createdAt'])
    except ValueError:
        raise ValueError('INVALID_ENVELOPE') from None
    actual = canonical(envelope)
    if len(actual) > MAX_BYTES:
        raise ValueError('RECORD_TOO_LARGE')
    if encoded is not None and actual.decode() != encoded:
        raise ValueError('NON_CANONICAL_ENVELOPE')
    return actual.decode()


def make_envelope(batch_id, day, key_id, now, rows):
    from .algorithms import checksum
    rows = sorted(rows, key=lambda row: (row['kind'], row['recordId']))
    envelope = {'schemaVersion': 1, 'batchId': batch_id, 'businessDate': day, 'keyId': key_id,
                'createdAt': now, 'recordCount': str(len(rows)), 'checksum': checksum(rows), 'records': rows}
    validate_envelope(envelope)
    return envelope
