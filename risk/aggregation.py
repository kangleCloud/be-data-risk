"""Build only frozen V1 records, then merge exact integers and HLLs in memory."""
import copy
from datetime import datetime
from .algorithms import HLL, bucket, canonical, record_id
from .protocol import validate_record
from .parsing import REASONS


def record(kind, dimensions, **fields):
    dimensions = dict(dimensions, kind=kind)
    result = {'schemaVersion': 1, 'kind': kind, 'recordId': record_id(dimensions),
              'dimensions': dimensions, **fields}
    validate_record(result)
    return result


def quality_record(day, source_id, reason):
    if reason not in REASONS:
        raise ValueError('INVALID_QUALITY_REASON')
    return record('QUALITY', {'businessDate': day, 'regionCode': 'UNKNOWN', 'requestType': 'OTHER',
                             'reasonCode': reason, 'sourceId': source_id}, count='1')


def event_records(event, source_id, hll, key_id):
    base = {'businessDate': event['business_date'], 'regionCode': event['region_code'],
            'requestType': event['request_type']}
    instant = datetime.fromisoformat(event['event_at'])
    minute = instant.replace(second=0, microsecond=0).isoformat(timespec='milliseconds')
    status = 'UNKNOWN' if event['status'] is None else str(event['status'])
    dimensions = dict(base, minuteAt=minute, method=event['method'], pathTemplate=event['path_template'], status=status)
    duration, size = event['duration_micros'], event['bytes_sent']
    histogram = ['0'] * 24
    if duration is not None:
        histogram[bucket(duration)] = '1'
    rows = [record('COUNTER', dimensions, requestCount='1', bytesSum=str(size or 0),
                   bytesValidCount=str(int(size is not None)), durationValidCount=str(int(duration is not None)),
                   durationSumMicros=str(duration or 0), histogram=histogram,
                   upstreamFailureCount=str(event['upstream_failure_count']))]
    if any(hll.registers):
        rows.append(record('SOURCE', base, registersBase64=hll.encode(), keyId=key_id))
    reasons = []
    if event['status'] == 499:
        reasons.append('CLIENT_ABORT')
    elif event['status'] is not None and event['status'] >= 500:
        reasons.append('HTTP_5XX')
    elif event['status'] is not None and event['status'] >= 400:
        reasons.append('HTTP_4XX')
    if event['upstream_failure_count']:
        reasons.append('UPSTREAM_FAILURE')
    for reason in reasons:
        dimensions = dict(base, minuteAt=minute, pathTemplate=event['path_template'], status=status, reasonCode=reason)
        rows.append(record('EXCEPTION', dimensions, count='1', firstAt=event['event_at'], lastAt=event['event_at']))
    rows += [quality_record(base['businessDate'], source_id, reason) for reason in event['quality']]
    return rows


def merge(old, delta):
    validate_record(delta)
    if old is None:
        return copy.deepcopy(delta)
    validate_record(old)
    if old['recordId'] != delta['recordId'] or old['dimensions'] != delta['dimensions'] or old['kind'] != delta['kind']:
        raise ValueError('RECORD_CONFLICT')
    result = copy.deepcopy(old)
    kind = result['kind']
    if kind == 'SOURCE':
        if old['keyId'] != delta['keyId']:
            raise ValueError('KEY_ID_CONFLICT')
        registers = HLL.decode(old['registersBase64'])
        registers.merge(HLL.decode(delta['registersBase64']))
        result['registersBase64'] = registers.encode()
    else:
        fields = ['count'] if kind in {'EXCEPTION', 'QUALITY'} else ['requestCount', 'bytesSum', 'bytesValidCount', 'durationValidCount', 'durationSumMicros', 'upstreamFailureCount']
        for field in fields:
            result[field] = str(int(old[field]) + int(delta[field]))
        if kind == 'COUNTER':
            result['histogram'] = [str(int(left) + int(right)) for left, right in zip(old['histogram'], delta['histogram'])]
        if kind == 'EXCEPTION':
            result['firstAt'] = min(old['firstAt'], delta['firstAt'])
            result['lastAt'] = max(old['lastAt'], delta['lastAt'])
    validate_record(result)
    if len(canonical(result)) > 65536:
        raise ValueError('RECORD_TOO_LARGE')
    return result
