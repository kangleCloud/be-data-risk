"""Executable risk-path-v1 contract; raw paths never escape this module."""
from dataclasses import dataclass
import hashlib
import hmac
import ipaddress
import re
import unicodedata
from urllib.parse import unquote_to_bytes

MAX_INPUT_BYTES = 16384
MAX_PATH_POINTS = 512
SENSITIVE = frozenset({'password', 'passwd', 'pwd', 'token', 'access_token', 'refresh_token',
                       'secret', 'authorization', 'cookie', '密码', '令牌'})
SSE_BASES = ('/market/dashboard/stream', '/stock-monitor/v1/stream', '/etf-monitor/v1/stream')
SSE_PATHS = frozenset(prefix + base for prefix in ('', '/openapi/api', '/stock/openapi/api') for base in SSE_BASES)
STATIC_SUFFIXES = frozenset('css js mjs map png jpg jpeg gif svg ico webp avif woff woff2 ttf eot txt xml pdf mp4 webm'.split())
PLACEHOLDER = re.compile(r'\{[A-Za-z_][A-Za-z0-9_]*\}')
MARKER = re.compile(r'\{(?:redacted(?::[a-f0-9]{64})?|path:(?:[a-f0-9]{64}|redacted)|[A-Za-z_][A-Za-z0-9_]*)\}')
PHONE = re.compile(r'(?<![0-9])(?:\+?86)?1[3-9][0-9]{9}(?![0-9])')
UUID = re.compile(r'[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}')
JWT = re.compile(r'(?<![A-Za-z0-9_-])[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}')
RANDOM_RUN = re.compile(r'[A-Za-z0-9_-]{24,}')


@dataclass(frozen=True)
class PathResult:
    template: str
    request_type: str
    quality: tuple[str, ...] = ()


def _controls(value):
    return any(unicodedata.category(char) in {'Cc', 'Cf', 'Cs', 'Zl', 'Zp'} for char in value)


def _strip(value):
    return re.split(r'[?#]', value, maxsplit=1)[0]


def normalize(value, trusted_template=False):
    try:
        if not isinstance(value, str) or not value.startswith('/') or len(value.encode('utf-8')) > MAX_INPUT_BYTES or _controls(value):
            raise ValueError()
        path = _strip(value)
        for _ in range(2):
            if '%' not in path:
                break
            if re.search(r'%(?![0-9a-fA-F]{2})', path):
                raise ValueError()
            raw = unquote_to_bytes(path)
            if len(raw) > MAX_INPUT_BYTES:
                raise ValueError()
            path = raw.decode('utf-8', errors='strict')
            if _controls(path):
                raise ValueError()
        if '%' in path:
            raise ValueError()
        path = re.sub(r'/+', '/', _strip(unicodedata.normalize('NFC', path)))
        if not path.startswith('/') or any(char in path for char in '\\<>"`'):
            raise ValueError()
        for segment in path.split('/'):
            if ('{' in segment or '}' in segment) and not (trusted_template and PLACEHOLDER.fullmatch(segment)):
                raise ValueError()
        return path
    except (ValueError, UnicodeError):
        raise ValueError('INVALID_PATH') from None


def valid_stored_path(value):
    if value == 'UNMATCHED':
        return True  # historical compatibility only
    if not isinstance(value, str) or not value.startswith('/') or len(value) > MAX_PATH_POINTS or unicodedata.normalize('NFC', value) != value or _controls(value):
        return False
    if any(char in value for char in '\\<>"`?#%'):
        return False
    for match in MARKER.finditer(value):
        marker = match.group()
        if marker.startswith('{path:'):
            if match.end() != len(value) or value[match.start()-1:match.start()] != '/':
                return False
        elif marker != '{redacted}' and not re.fullmatch(r'\{redacted:[a-f0-9]{64}\}', marker):
            if value[match.start()-1:match.start()] != '/' or (match.end() < len(value) and value[match.end()] != '/'):
                return False
    rest = MARKER.sub('', value)
    return '{' not in rest and '}' not in rest


def validate_template(value):
    if value == 'UNMATCHED':
        return
    if not isinstance(value, str) or '?' in value or '#' in value or '%' in value or len(value) > MAX_PATH_POINTS:
        raise ValueError('INVALID_TEMPLATE')
    try:
        normalized = normalize(value, trusted_template=True)
        # Only compute expansion width here; no extra runtime key/configuration is introduced.
        # Fixed digest widths make a non-secret sizing key equivalent to any actual daily key.
        sized, _, _ = redact(normalized, '1970-01-01', bytes(32))
        if '/{path:' in sized:
            raise ValueError()
    except ValueError:
        raise ValueError('INVALID_TEMPLATE') from None


def digest(key, day, purpose, value):
    return hmac.new(key, ('risk-path-v1\n' + day + '\n' + purpose + '\n' + value).encode('utf-8'), hashlib.sha256).hexdigest()


def _random(value):
    for match in RANDOM_RUN.finditer(value):
        run = match.group()
        if re.fullmatch(r'[0-9A-Fa-f]{24,}', run) or (re.search('[A-Za-z]', run) and re.search('[0-9]', run)):
            return True
    return False


def _email(value):
    # Linear equivalent of the contract's email search; avoid quadratic scans on long text.
    for token in re.split(r'[/\s]', value):
        parts = token.split('@')
        for index, local in enumerate(parts[:-1]):
            domain = parts[index + 1]
            if local and domain.find('.', 1, len(domain) - 1) >= 0:
                return True
    return False


def _ip(value):
    candidate = value.split('=', 1)[-1]
    if candidate.startswith('[') and candidate.endswith(']'):
        candidate = candidate[1:-1]
    try:
        ipaddress.ip_address(candidate)
        return True
    except ValueError:
        return False


def redact(path, day, key):
    output, force, changed, unavailable = [], False, False, False
    def mask(value):
        nonlocal changed, unavailable
        changed = True
        if not key:
            unavailable = True
            return '{redacted}'
        return '{redacted:' + digest(key, day, 'segment', value) + '}'
    for segment in path.split('/'):
        if force and segment:
            output.append(mask(segment))
            force = False
        elif segment.lower() in SENSITIVE:
            output.append(segment)
            force = True
        else:
            pair = re.split(r'[=:]', segment, maxsplit=1)
            if len(pair) == 2 and pair[0].lower() in SENSITIVE:
                output.append(pair[0] + segment[len(pair[0])] + mask(pair[1]))
            elif _email(segment) or PHONE.search(segment) or UUID.search(segment) or JWT.search(segment) or _ip(segment) or _random(segment):
                output.append(mask(segment))
            else:
                output.append(segment)
    result = '/'.join(output)
    if len(result) > MAX_PATH_POINTS:
        changed = True
        if key:
            suffix = '/{path:' + digest(key, day, 'path', result) + '}'
        else:
            suffix = '/{path:redacted}'
            unavailable = True
        cut = MAX_PATH_POINTS - len(suffix)
        # Never emit half of a redaction marker/trusted placeholder.
        opening = result.rfind('{', 0, cut)
        closing = result.rfind('}', 0, cut)
        if opening > closing:
            cut = opening
        result = result[:cut] + suffix
    return result, changed, unavailable


def _under(path, prefix):
    return path == prefix or path.startswith(prefix + '/')


def classify(path):
    if any(_under(path, prefix) for prefix in ('/admin/api/risk', '/stock/admin/api/risk')):
        return 'RISK_INTERNAL'
    if path in SSE_PATHS:
        return 'SSE'
    final = path.rsplit('/', 1)[-1]
    suffix = final.rsplit('.', 1)[-1].lower() if '.' in final else ''
    if any(_under(path, prefix) for prefix in ('/assets', '/static')) or suffix in STATIC_SUFFIXES:
        return 'STATIC'
    prefixes = ('/api', '/admin/api', '/app/api', '/openapi/api', '/scheduler/api', '/stock/api', '/stock/admin/api', '/stock/app/api', '/stock/openapi/api', '/stock/scheduler/api', '/internal', '/market', '/stock-monitor', '/etf-monitor')
    if any(_under(path, prefix) for prefix in prefixes):
        return 'API'
    if path == '/' or path.endswith('/') or '.' not in final or suffix in {'html', 'htm'}:
        return 'PAGE'
    return 'OTHER'


def protect_path(value, day, key, rules=()):
    try:
        normalized = normalize(value)
    except ValueError:
        return PathResult('/__invalid_path__', 'OTHER', ('UNMATCHED_PATH',))
    kind = classify(normalized)
    result, changed, unavailable = redact(normalized, day, key)
    if not changed and kind not in {'RISK_INTERNAL', 'SSE'}:
        for pattern, template, _legacy_kind in rules:
            if template != 'UNMATCHED' and pattern.fullmatch(normalized):
                result, _, missing = redact(normalize(template, trusted_template=True), day, key)
                unavailable = unavailable or missing
                break
    if not valid_stored_path(result):
        raise ValueError('INVALID_SANITIZED_PATH')
    return PathResult(result, kind, ('KEY_UNAVAILABLE',) if unavailable else ())
