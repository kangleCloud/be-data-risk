"""Packaged current schemas and complete pre-publication validation."""
from datetime import datetime
import hashlib
import json
from pathlib import Path
from jsonschema import Draft202012Validator, FormatChecker
from .algorithms import canonical
from .paths import valid_stored_path
from .ip_address import canonical_ip, public_ip
from .geo_dimensions import valid_geo_dimensions

ASSETS = Path(__file__).with_name('assets')
MAX_RECORDS = 500
MAX_BYTES = 1048576
MAX_COUNT = 9223372036854775807
REQUEST_TYPES = frozenset({'API', 'PAGE', 'STATIC', 'OTHER'})


def asset(name):
    return (ASSETS / name).read_text(encoding='utf-8')


def verify_assets():
    for directory in ('risk', 'monitor', 'geoip-v1'):
        manifest = json.loads(asset(directory + '/sha256.json'))
        for name, digest in manifest['runtime'].items():
            if hashlib.sha256((ASSETS / directory / name).read_bytes()).hexdigest() != digest:
                raise ValueError('PROTOCOL_ASSET_MISMATCH')


verify_assets()


def _validator(directory, name):
    schema = json.loads(asset(directory + '/' + name))
    if name == 'envelope.schema.json':
        schema['properties']['records']['items'] = json.loads(asset(directory + '/record.schema.json'))
    return Draft202012Validator(schema, format_checker=FormatChecker())


_SCHEMA = _validator('risk', 'record.schema.json')
_ENVELOPE = _validator('risk', 'envelope.schema.json')


def _common_record(row, encoded=None):
    if not valid_stored_path(row['pathTemplate']):
        raise ValueError()
    instant = datetime.fromisoformat(row['minuteAt'])
    if instant.second or instant.microsecond:
        raise ValueError()
    address = row['sourceIp']
    if address is not None and canonical_ip(address) != address:
        raise ValueError()
    dimensions = {field: row[field] or '' for field in ('countryCode','provinceCode','provinceName','cityCode','cityName')}
    dimensions['locationLevel'] = 'CITY' if row['cityCode'] else 'UNKNOWN'
    if any(value == '' for key,value in row.items() if key in dimensions and key != 'locationLevel') or not valid_geo_dimensions(dimensions):
        raise ValueError()
    region, country, province = row['regionCode'], row['countryCode'], row['provinceCode']
    if country is None and any(row[field] is not None for field in ('provinceCode','provinceName','cityCode','cityName')):
        raise ValueError()
    if address is None:
        if region != 'UNKNOWN' or country is not None:
            raise ValueError()
    elif not public_ip(address):
        if region != 'INTERNAL' or country is not None:
            raise ValueError()
    elif region == 'INTERNAL':
        raise ValueError()
    if country is None and region not in {'UNKNOWN','INTERNAL'}:
        raise ValueError()
    if country is not None and region != (province if country == 'CN' and province else country):
        raise ValueError()
    if encoded is not None and canonical(row).decode() != encoded:
        raise ValueError()


def validate_record(row, encoded=None):
    try:
        if not _SCHEMA.is_valid(row) or type(row['httpStatus']) is not int or int(row['requestCount']) > MAX_COUNT:
            raise ValueError()
        if row['requestType'] not in REQUEST_TYPES:
            raise ValueError()
        _common_record(row, encoded)
    except (ValueError, TypeError, KeyError, OverflowError):
        raise ValueError('INVALID_RECORD') from None


def _validate_envelope(envelope, validator, record_validator, encoded=None):
    from .aggregation import identity
    if not validator.is_valid(envelope) or type(envelope['schemaVersion']) is not int:
        raise ValueError('INVALID_ENVELOPE')
    seen = set()
    for row in envelope['records']:
        record_validator(row)
        key = identity(row)
        if row['minuteAt'][:10] != envelope['businessDate'] or key in seen:
            raise ValueError('INVALID_ENVELOPE')
        seen.add(key)
    actual = canonical(envelope)
    if len(actual) > MAX_BYTES:
        raise ValueError('RECORD_TOO_LARGE')
    if encoded is not None and encoded != actual.decode():
        raise ValueError('NON_CANONICAL_ENVELOPE')
    return actual.decode()


def validate_envelope(envelope, encoded=None):
    return _validate_envelope(envelope, _ENVELOPE, validate_record, encoded)


def make_envelope(batch_id, day, now, rows, source_id):
    envelope = {'schemaVersion': 2, 'batchId': batch_id, 'businessDate': day,
                'createdAt': now, 'sourceId': source_id, 'records': rows}
    validate_envelope(envelope)
    return envelope
