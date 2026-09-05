"""Authorization boundary validator (SAFE, passive).

Reviews collected exchanges for two conservative signals that warrant a manual
authorization review: a sensitive-looking endpoint that returned success while
the request carried no authorization material, and inconsistent auth
requirements for the same endpoint across requests. It sends nothing.
"""

from typing import Any, Dict, List

from .base import BaseValidator
from .analysis_helpers import (
    is_sensitive_path,
    is_success,
    make_finding,
    path_of,
    request_has_auth,
)


class AuthorizationBoundaryValidator(BaseValidator):
    """Detect potential missing/inconsistent authorization from collected data."""

    name = "authorization_boundary"
    description = "Flags sensitive endpoints reachable without auth (passive)"

    def is_safe(self) -> bool:
        return True

    def validate(self, context: Any) -> Dict[str, Any]:
        findings: List[Dict[str, Any]] = []
        seen = set()
        responses = getattr(context, 'responses', []) or []

        # Track, per endpoint, whether auth was ever required (a 401/403 seen).
        auth_required = {}
        analyzed = 0

        for record in responses:
            url = record['url']
            path = path_of(url)
            status = record.get('status')
            try:
                status_int = int(status) if status is not None else 0
            except (TypeError, ValueError):
                status_int = 0
            if status_int in (401, 403):
                auth_required[path] = True
            analyzed += 1

            if is_sensitive_path(url) and is_success(status) and not request_has_auth(record):
                signature = f'authz-open|{path}'
                if signature not in seen:
                    seen.add(signature)
                    findings.append(make_finding(
                        'missing_authorization',
                        f'Sensitive endpoint reachable without auth: {path}',
                        'high', url,
                        'A sensitive-looking endpoint returned success while the '
                        'request carried no Authorization, Cookie, or API-key '
                        'header. Verify whether it should require authentication '
                        '(possible broken access control / IDOR).',
                        {'path': path, 'status': status_int,
                         'request_had_auth': False},
                        signature=signature,
                        confidence='low',
                    ))

        # Inconsistent auth: an endpoint that was 401/403 sometimes but 2xx
        # without auth other times.
        for record in responses:
            path = path_of(record['url'])
            if auth_required.get(path) and is_success(record.get('status')) \
                    and not request_has_auth(record):
                signature = f'authz-inconsistent|{path}'
                if signature not in seen:
                    seen.add(signature)
                    findings.append(make_finding(
                        'inconsistent_authorization',
                        f'Inconsistent auth enforcement: {path}',
                        'medium', record['url'],
                        'The same endpoint rejected some requests with 401/403 but '
                        'served others successfully without authorization. Confirm '
                        'the access-control rule is applied consistently.',
                        {'path': path},
                        signature=signature,
                        confidence='low',
                    ))

        return {
            'findings': findings,
            'metadata': {'exchanges_analyzed': analyzed,
                         'endpoints_requiring_auth': len(auth_required)},
        }
