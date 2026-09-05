"""Security-header and cookie hygiene validator (SAFE, passive).

Inspects response headers that were already collected and flags missing or weak
browser-security headers and insecure cookies. It sends nothing. Findings are
de-duplicated per origin+check so one weak header is reported once, not once per
URL.
"""

from typing import Any, Dict, List
from urllib.parse import urlparse

from .base import BaseValidator
from .analysis_helpers import (
    header_lookup,
    iter_set_cookie,
    looks_like_session_cookie,
    make_finding,
)


class SecurityHeadersValidator(BaseValidator):
    """Report missing/weak security headers and insecure cookies."""

    name = "security_headers"
    description = "Flags missing security headers and insecure cookies (passive)"

    def is_safe(self) -> bool:
        return True

    @staticmethod
    def _origin(url: str) -> str:
        parsed = urlparse(url)
        host = (parsed.hostname or '').lower()
        scheme = (parsed.scheme or 'https').lower()
        port = f":{parsed.port}" if parsed.port else ''
        return f"{scheme}://{host}{port}"

    def validate(self, context: Any) -> Dict[str, Any]:
        findings: List[Dict[str, Any]] = []
        seen = set()
        responses = getattr(context, 'responses', []) or []
        analyzed = 0

        for record in responses:
            status = record.get('status')
            try:
                status_int = int(status) if status is not None else 200
            except (TypeError, ValueError):
                status_int = 200
            # Header hardening is relevant to responses a browser renders.
            if status_int >= 400 or 300 <= status_int < 400:
                continue
            headers = record.get('response_headers') or {}
            if not headers:
                continue

            url = record['url']
            origin = self._origin(url)
            is_https = url.lower().startswith('https://')
            analyzed += 1

            for finding in self._check_headers(url, origin, is_https, headers):
                if finding['signature'] not in seen:
                    seen.add(finding['signature'])
                    findings.append(finding)
            for finding in self._check_cookies(url, origin, is_https, headers):
                if finding['signature'] not in seen:
                    seen.add(finding['signature'])
                    findings.append(finding)

        return {
            'findings': findings,
            'metadata': {
                'responses_analyzed': analyzed,
                'origins': len({self._origin(r['url']) for r in responses if r.get('url')}),
            },
        }

    def _check_headers(self, url, origin, is_https, headers):
        out = []

        def missing(header, title, severity, why):
            if header_lookup(headers, header) is None:
                out.append(make_finding(
                    'missing_security_header', title, severity, url,
                    why, {'origin': origin, 'header': header, 'present': False,
                          'sampled_url': url},
                    signature=f'header|{origin}|{header.lower()}',
                    confidence='high',
                ))

        if is_https:
            missing('Strict-Transport-Security',
                    'Missing HSTS header', 'medium',
                    'HTTPS responses should send Strict-Transport-Security to '
                    'prevent protocol downgrade.')
        missing('Content-Security-Policy',
                'Missing Content-Security-Policy', 'medium',
                'No Content-Security-Policy header; the page has no first line of '
                'defense against injected content.')
        missing('Referrer-Policy',
                'Missing Referrer-Policy', 'low',
                'No Referrer-Policy header; full URLs may leak to third parties.')

        xcto = header_lookup(headers, 'X-Content-Type-Options')
        if xcto is None or xcto.strip().lower() != 'nosniff':
            out.append(make_finding(
                'weak_security_header', 'X-Content-Type-Options not nosniff', 'low',
                url, 'X-Content-Type-Options should be "nosniff" to stop MIME '
                'sniffing.',
                {'origin': origin, 'header': 'X-Content-Type-Options',
                 'value': xcto, 'sampled_url': url},
                signature=f'header|{origin}|x-content-type-options',
                confidence='high',
            ))

        xfo = header_lookup(headers, 'X-Frame-Options')
        csp = header_lookup(headers, 'Content-Security-Policy') or ''
        if xfo is None and 'frame-ancestors' not in csp.lower():
            out.append(make_finding(
                'missing_security_header', 'No clickjacking protection', 'low',
                url, 'Neither X-Frame-Options nor CSP frame-ancestors is set; the '
                'page can be framed.',
                {'origin': origin, 'header': 'X-Frame-Options', 'present': False,
                 'sampled_url': url},
                signature=f'header|{origin}|x-frame-options',
                confidence='medium',
            ))
        return out

    def _check_cookies(self, url, origin, is_https, headers):
        out = []
        for cookie in iter_set_cookie(headers):
            if not looks_like_session_cookie(cookie):
                continue
            name = cookie.split('=', 1)[0].strip()
            attrs = {part.strip().lower() for part in cookie.split(';')[1:]}
            redacted = f'{name}=[REDACTED]; ' + '; '.join(sorted(attrs))
            if is_https and 'secure' not in attrs:
                out.append(make_finding(
                    'insecure_cookie', f'Session cookie "{name}" missing Secure',
                    'high', url,
                    'A session cookie without Secure can be sent over plaintext '
                    'and captured.',
                    {'origin': origin, 'cookie': redacted, 'attribute': 'Secure',
                     'sampled_url': url},
                    signature=f'cookie|{origin}|{name.lower()}|secure',
                    confidence='high',
                ))
            if 'httponly' not in attrs:
                out.append(make_finding(
                    'insecure_cookie', f'Session cookie "{name}" missing HttpOnly',
                    'medium', url,
                    'A session cookie without HttpOnly is reachable from JavaScript '
                    'and exposed to XSS theft.',
                    {'origin': origin, 'cookie': redacted, 'attribute': 'HttpOnly',
                     'sampled_url': url},
                    signature=f'cookie|{origin}|{name.lower()}|httponly',
                    confidence='high',
                ))
            if not any(part.startswith('samesite') for part in attrs):
                out.append(make_finding(
                    'insecure_cookie', f'Session cookie "{name}" missing SameSite',
                    'low', url,
                    'A session cookie without SameSite offers no built-in CSRF '
                    'protection.',
                    {'origin': origin, 'cookie': redacted, 'attribute': 'SameSite',
                     'sampled_url': url},
                    signature=f'cookie|{origin}|{name.lower()}|samesite',
                    confidence='medium',
                ))
        return out
