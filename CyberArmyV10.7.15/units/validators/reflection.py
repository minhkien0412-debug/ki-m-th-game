"""Reflection validator - detects reflected input in collected responses (SAFE).

Passive only: it never injects anything. It checks whether markers the tool
already sent (or its own default test tokens) appear verbatim in response bodies
that were previously collected. A raw, unencoded reflection is reported as a
potential injection sink for manual XSS review.
"""

from typing import Any, Dict, List

from .base import BaseValidator
from .analysis_helpers import header_lookup, make_finding, snippet


class ReflectionValidator(BaseValidator):
    """Check whether previously sent test markers are reflected in responses."""

    name = "reflection"
    description = "Detects reflected test markers in collected responses (passive)"

    def __init__(self, config: Dict[str, Any]):
        super().__init__(config)
        self.default_markers = ["CyberArmyTest123", "CyberArmyXSS456"]

    def is_safe(self) -> bool:
        return True

    def validate(self, context: Any) -> Dict[str, Any]:
        findings: List[Dict[str, Any]] = []
        seen = set()
        responses = getattr(context, 'responses', []) or []
        markers = list(getattr(context, 'sent_markers', []) or []) or list(self.default_markers)

        checked = 0
        for record in responses:
            body = record.get('body')
            if not isinstance(body, str) or not body:
                continue
            checked += 1
            content_type = (header_lookup(record.get('response_headers'), 'Content-Type') or '')
            html_context = 'html' in content_type.lower() or content_type == ''
            for marker in markers:
                if marker and marker in body:
                    url = record['url']
                    # An HTML-context reflection is the interesting XSS signal;
                    # a reflection in JSON/text is lower severity.
                    severity = 'medium' if html_context else 'low'
                    signature = f'reflection|{url}|{marker}'
                    if signature in seen:
                        continue
                    seen.add(signature)
                    findings.append(make_finding(
                        'reflected_input',
                        f'Reflected marker "{marker}"',
                        severity, url,
                        'A test marker was reflected unencoded in the response body, '
                        'indicating a possible injection sink. Confirm manually '
                        'whether it breaks out of its context (XSS).',
                        {'marker': marker, 'content_type': content_type or 'unknown',
                         'context': snippet(body, marker)},
                        signature=signature,
                        confidence='medium' if html_context else 'low',
                    ))

        return {
            'findings': findings,
            'metadata': {'responses_checked': checked, 'markers': len(markers)},
        }
