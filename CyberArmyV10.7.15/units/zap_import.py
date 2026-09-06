"""Import OWASP ZAP alerts into CyberArmy findings (triage only).

Reads a ZAP alert export (several JSON shapes are supported) and normalizes it
into the shared finding structure, optionally filtered to the HackerOne scope.

Important: ZAP alerts are *scanner output*. Many bug-bounty programs (PlayStation
included) treat raw scanner output as out of scope, so this import is for your
own triage/record — verify each item manually before treating it as a finding,
and never submit raw scanner alerts where a program excludes them.
"""

import json
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional
from urllib.parse import urlparse

_RISK = {
    '3': 'high', '2': 'medium', '1': 'low', '0': 'info',
    'high': 'high', 'medium': 'medium', 'low': 'low',
    'informational': 'info', 'info': 'info',
}


def _iter_raw_alerts(data: Any):
    """Yield raw alert dicts from the common ZAP export shapes."""
    if isinstance(data, list):
        yield from (a for a in data if isinstance(a, dict))
    elif isinstance(data, dict):
        if isinstance(data.get('alerts'), list):
            yield from (a for a in data['alerts'] if isinstance(a, dict))
        for site in data.get('site', []) or []:
            if isinstance(site, dict):
                yield from (a for a in site.get('alerts', []) or [] if isinstance(a, dict))


def _severity(alert: Dict[str, Any]) -> str:
    code = str(alert.get('riskcode', '')).strip()
    if code:
        return _RISK.get(code, 'info')
    risk = str(alert.get('risk', '')).strip().lower().split(' ')[0]
    return _RISK.get(risk, 'info')


def _confidence(alert: Dict[str, Any]) -> str:
    value = str(alert.get('confidence', '')).strip().lower()
    if value in {'3', 'high'}:
        return 'high'
    if value in {'1', 'low'}:
        return 'low'
    return 'medium'


def normalize_alerts(data: Any,
                     in_scope: Optional[Callable[[str], bool]] = None) -> List[Dict[str, Any]]:
    """Convert a parsed ZAP export into finding dicts, deduped by signature."""
    findings: Dict[str, Dict[str, Any]] = {}
    def _add(alert, url, param, evidence):
        name = str(alert.get('alert') or alert.get('name') or 'ZAP alert').strip()
        url = str(url or '').strip()
        host = (urlparse(url).hostname or '') if url else ''
        if in_scope is not None and host and not in_scope(host):
            return
        param = str(param or '')
        signature = f'zap|{name}|{host}|{param}'
        if signature in findings:
            findings[signature]['evidence']['occurrences'] += 1
            return
        description = str(alert.get('description') or alert.get('desc') or '').strip()
        solution = str(alert.get('solution') or '').strip()
        findings[signature] = {
            'type': 'zap_alert',
            'title': name,
            'severity': _severity(alert),
            'url': url,
            'description': (description + (f'\n\nSolution: {solution}' if solution else '')).strip(),
            'evidence': {
                'param': param,
                'evidence': str(evidence or ''),
                'cweid': alert.get('cweid'),
                'wascid': alert.get('wascid'),
                'zap_risk': alert.get('risk') or alert.get('riskdesc'),
                'occurrences': 1,
            },
            'signature': signature,
            'confidence': _confidence(alert),
        }

    for alert in _iter_raw_alerts(data):
        # The traditional JSON report groups occurrences under "instances";
        # expand those so each URL is captured and scope-filtered. Otherwise
        # fall back to the flat top-level url/param (core/view/alerts shape).
        instances = alert.get('instances')
        if isinstance(instances, list) and instances:
            for inst in instances:
                if isinstance(inst, dict):
                    _add(alert, inst.get('uri') or inst.get('url'),
                         inst.get('param'), inst.get('evidence'))
        else:
            _add(alert, alert.get('url') or alert.get('uri'),
                 alert.get('param'), alert.get('evidence'))
    return list(findings.values())


class ZapFindingImporter:
    """Load a ZAP export file and normalize it to scope-filtered findings."""

    def __init__(self, config: Dict[str, Any]):
        self.config = config

    def _scope_predicate(self) -> Optional[Callable[[str], bool]]:
        h1 = self.config.get('hackerone', {})
        if h1.get('enabled'):
            from .hackerone_engagement import HackerOneEngagement
            engagement = HackerOneEngagement(self.config)
            return lambda host: engagement.find_scope_asset(host) is not None
        return None

    def import_file(self, path: str) -> List[Dict[str, Any]]:
        source = Path(path)
        if not source.is_file():
            raise FileNotFoundError(f'ZAP export not found: {path}')
        try:
            data = json.loads(source.read_text(encoding='utf-8'))
        except json.JSONDecodeError as exc:
            raise ValueError(f'ZAP export is not valid JSON: {exc}') from exc
        return normalize_alerts(data, self._scope_predicate())
