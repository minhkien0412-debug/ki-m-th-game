"""Shared, dependency-free helpers for passive (SAFE) validators.

Every helper here operates only on evidence that was *already* collected — an
HTTP exchange the tool observed earlier. Nothing in this module opens a socket,
sends a request, or mutates a target, so validators built on it keep the safe,
passive contract.

An exchange record is a plain dict with these (all optional except ``url``):
    url                str
    method             str
    status             int
    request_headers    dict[str, str]
    response_headers   dict[str, str]   (a Set-Cookie value may be a list)
    body               str
"""

from typing import Any, Dict, List, Optional
from urllib.parse import urlparse


# Paths that usually require authorization; a 2xx here with no auth on the
# request is worth flagging for manual review. Kept deliberately conservative.
SENSITIVE_PATH_HINTS = (
    '/admin', '/administrator', '/internal', '/debug', '/config',
    '/account', '/accounts', '/user', '/users', '/profile', '/settings',
    '/billing', '/payment', '/invoice', '/order', '/orders', '/wallet',
    '/dashboard', '/manage', '/console', '/private', '/secret', '/token',
)

AUTH_REQUEST_HEADERS = ('authorization', 'cookie', 'x-api-key', 'x-auth-token')


def header_lookup(headers: Optional[Dict[str, Any]], name: str) -> Optional[str]:
    """Case-insensitive header read; returns the first value as a string."""
    if not headers:
        return None
    target = name.lower()
    for key, value in headers.items():
        if str(key).lower() == target:
            if isinstance(value, (list, tuple)):
                return str(value[0]) if value else None
            return str(value)
    return None


def iter_set_cookie(headers: Optional[Dict[str, Any]]) -> List[str]:
    """Return every Set-Cookie value, whether stored as a string or a list."""
    if not headers:
        return []
    values: List[str] = []
    for key, value in headers.items():
        if str(key).lower() == 'set-cookie':
            if isinstance(value, (list, tuple)):
                values.extend(str(item) for item in value)
            elif value:
                values.append(str(value))
    return values


def path_of(url: str) -> str:
    try:
        return urlparse(url).path or '/'
    except Exception:
        return '/'


def is_sensitive_path(url: str) -> bool:
    path = path_of(url).lower().rstrip('/')
    return any(hint in path for hint in SENSITIVE_PATH_HINTS)


def request_has_auth(record: Dict[str, Any]) -> bool:
    """True when the recorded request carried any authorization material."""
    headers = record.get('request_headers') or {}
    for name in AUTH_REQUEST_HEADERS:
        if header_lookup(headers, name):
            return True
    return False


def is_success(status: Any) -> bool:
    try:
        return 200 <= int(status) < 300
    except (TypeError, ValueError):
        return False


def looks_like_session_cookie(cookie_value: str) -> bool:
    name = cookie_value.split('=', 1)[0].strip().lower()
    return any(hint in name for hint in ('session', 'sess', 'sid', 'auth', 'token', 'jwt'))


def snippet(body: str, marker: str, radius: int = 40) -> str:
    """Return a short context window around the first occurrence of ``marker``."""
    index = body.find(marker)
    if index < 0:
        return ''
    start = max(0, index - radius)
    end = min(len(body), index + len(marker) + radius)
    prefix = '…' if start > 0 else ''
    suffix = '…' if end < len(body) else ''
    return f"{prefix}{body[start:end]}{suffix}"


def make_finding(finding_type: str, title: str, severity: str, url: str,
                 description: str, evidence: Dict[str, Any],
                 signature: str, confidence: str = 'medium') -> Dict[str, Any]:
    """Build a structured finding dict shared by all passive validators."""
    return {
        'type': finding_type,
        'title': title,
        'severity': severity,
        'url': url,
        'description': description,
        'evidence': evidence,
        'signature': signature,
        'confidence': confidence,
    }
