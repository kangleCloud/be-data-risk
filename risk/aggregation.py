"""Single API minute row, with exact signed-64-bit count merging."""
from datetime import datetime
from .protocol import validate_record

IDENTITY = ('minuteAt', 'method', 'pathTemplate', 'sourceIp', 'httpStatus')
GEO_FIELDS = ('regionCode', 'countryCode', 'provinceCode', 'provinceName', 'cityCode', 'cityName')


def identity(row):
    return tuple(row[field] for field in IDENTITY)


def event_records(event):
    if event['request_type'] != 'API':
        return []
    geo = event.get('geo', {})
    row = {'minuteAt': datetime.fromisoformat(event['event_at']).replace(second=0, microsecond=0).isoformat(timespec='milliseconds'),
           'method': event['method'], 'pathTemplate': event['path_template'], 'sourceIp': event['source_ip'],
           'httpStatus': event['status'], 'requestCount': '1', 'regionCode': event['region_code']}
    row.update({field: geo.get(field) or None for field in GEO_FIELDS[1:]})
    validate_record(row)
    return [row]


def merge(old, delta):
    validate_record(delta)
    if old is None:
        return dict(delta)
    validate_record(old)
    if identity(old) != identity(delta):
        raise ValueError('RECORD_CONFLICT')
    result = dict(old, requestCount=str(int(old['requestCount']) + int(delta['requestCount'])))
    # A failed lookup never clears the last valid complete snapshot for this natural row.
    if delta['countryCode'] is not None or (old['countryCode'] is None and delta['regionCode'] == 'INTERNAL'):
        result.update({field: delta[field] for field in GEO_FIELDS})
    validate_record(result)
    return result
