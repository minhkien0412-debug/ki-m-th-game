"""Low-impact HackerOne observations with no exploit automation."""

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List
from urllib.parse import urlparse

from .hackerone_engagement import EngagementError, HackerOneEngagement
from .recon_engine import ReconEngine
from .secret_redactor import SecretRedactor
from .target_request_gate import TargetRequestGate


class HackerOneRunner:
    """Run only passive recon or a single metadata-only HEAD observation."""

    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.engagement = HackerOneEngagement(config)
        self.redactor = SecretRedactor()
        output_dir = config.get('hackerone', {}).get(
            'observation_output_dir', 'state/hackerone_observations'
        )
        self.output_dir = Path(output_dir)

    def passive_recon(self, target: str) -> Dict[str, Any]:
        """Query passive certificate transparency sources and filter to scope."""
        self.engagement.authorize('passive_recon', target, recon_root=True)
        parsed = urlparse(target if '://' in target else f'https://{target}')
        hostname = parsed.hostname or ''

        recon = ReconEngine(self.config)
        try:
            raw = recon.run_passive_recon(hostname)
        finally:
            recon.close()

        max_results = min(
            100,
            max(1, int(self.config.get('hackerone', {}).get('max_passive_results', 50))),
        )
        in_scope = [
            host for host in raw.get('subdomains', [])
            if self.engagement.find_scope_asset(host) is not None
        ][:max_results]
        return {
            'target': hostname,
            'source': 'crt.sh',
            'in_scope_subdomains': sorted(set(in_scope)),
            'observed_at': datetime.now(timezone.utc).isoformat(),
            'note': 'Passive discovery only; no discovered host was contacted.',
        }

    def recon_scope(self) -> Dict[str, Any]:
        """Sweep every eligible scope asset into one deduplicated host list.

        Enumeration is rooted at each eligible wildcard's base domain (via the
        public crt.sh service only); the eligible exact domains are added
        directly. Every discovered host is still filtered with the strict
        ``find_scope_asset``. No target is contacted.
        """
        valid, errors, _ = self.engagement.validate_profile()
        if not valid:
            raise EngagementError('; '.join(errors))

        roots: List[str] = []
        known: List[str] = []
        for asset in self.engagement.assets:
            if asset.get('eligible_for_submission', True) is False:
                continue
            if asset.get('type') != 'domain':
                continue
            identifier = str(asset.get('identifier', '')).strip().lower().rstrip('.')
            if identifier.startswith('*.'):
                roots.append(identifier[2:])
            elif identifier:
                known.append(identifier)

        discovered = set()
        per_root: Dict[str, int] = {}
        errors_by_root: Dict[str, str] = {}
        recon = ReconEngine(self.config)
        try:
            for root in sorted(set(roots)):
                raw = recon.run_passive_recon(root)
                hosts = {
                    host for host in raw.get('subdomains', [])
                    if self.engagement.find_scope_asset(host) is not None
                }
                per_root[root] = len(hosts)
                if not hosts:
                    errors_by_root[root] = 'no in-scope hosts returned (see crt.sh log above)'
                discovered.update(hosts)
        finally:
            recon.close()

        max_hosts = min(5000, max(1, int(
            self.config.get('hackerone', {}).get('max_recon_hosts', 1000)
        )))
        consolidated = sorted(set(known) | discovered)[:max_hosts]

        self.output_dir.mkdir(parents=True, exist_ok=True)
        filename = datetime.now(timezone.utc).strftime('scope_recon_%Y%m%d_%H%M%S.json')
        output_path = self.output_dir / filename
        result = {
            'roots_queried': sorted(set(roots)),
            'per_root_in_scope': per_root,
            'root_notes': errors_by_root,
            'known_domains': sorted(set(known)),
            'in_scope_hosts': consolidated,
            'host_count': len(consolidated),
            'source': 'crt.sh + scope assets',
            'observed_at': datetime.now(timezone.utc).isoformat(),
            'note': 'Passive discovery only; no discovered host was contacted.',
        }
        output_path.write_text(json.dumps(result, indent=2), encoding='utf-8')
        result['saved_to'] = str(output_path)
        return result

    def observe_head(self, target: str) -> Dict[str, Any]:
        """Perform one HEAD request and store only redacted response metadata."""
        self.engagement.authorize('http_head', target)
        parsed = urlparse(target)
        if parsed.scheme not in {'http', 'https'} or not parsed.hostname:
            raise ValueError('HEAD observation requires an absolute HTTP(S) URL')
        hostname = (parsed.hostname or '').lower().rstrip('.')

        gate_config = {
            'target': {
                'allowed_hosts': [hostname],
                'allowed_paths': [],
                'blocked_paths': [],
            },
            'rate_limit': {
                'requests_per_second': 1,
                'requests_per_minute': 30,
                'concurrent_connections': 1,
            },
        }
        gate = TargetRequestGate(gate_config)
        try:
            response = gate.head(target, timeout=10, allow_redirects=False)
            if response is None:
                raise RuntimeError('The safe request gate blocked or failed the HEAD request')

            headers = {}
            for key, value in response.headers.items():
                if key.lower() == 'location':
                    headers[key] = self.redactor.redact_url(value)
                else:
                    headers[key] = self.redactor.redact(str(value))
            headers = self.redactor.redact_headers(headers)

            observation = {
                'target': self.redactor.redact_url(target),
                'method': 'HEAD',
                'status_code': response.status_code,
                'headers': headers,
                'observed_at': datetime.now(timezone.utc).isoformat(),
                'redirect_followed': False,
                'body_collected': False,
                'note': 'Metadata observation only; this is not a vulnerability finding.',
            }
        finally:
            gate.close()

        self.output_dir.mkdir(parents=True, exist_ok=True)
        filename = datetime.now(timezone.utc).strftime('observation_%Y%m%d_%H%M%S_%f.json')
        output_path = self.output_dir / filename
        output_path.write_text(json.dumps(observation, indent=2), encoding='utf-8')
        observation['saved_to'] = str(output_path)
        return observation
