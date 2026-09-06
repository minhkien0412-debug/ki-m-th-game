"""Drive OWASP ZAP from the terminal, under fail-closed authorization.

Automated scanning (spider + active scan) sends traffic to the target, so this
orchestrator authorizes it ONLY for:
  - self-hosted loopback targets (your own lab), or
  - hosts you explicitly attest are permitted, via zap.automated_testing_allowed
    + zap.authorization_reference + zap.allowed_hosts.

It REFUSES to automatically scan a HackerOne in-scope target: PlayStation (and
most programs) list scanner output as out of scope and forbid disruption. For
those, use ZAP as a passive proxy with manual testing instead — this tool will
not do it for you.

Requires a running ZAP and the `zaproxy` Python client (pip install zaproxy).
"""

import os
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse

from .zap_import import normalize_alerts

LOOPBACK_HOSTS = {'127.0.0.1', '::1', 'localhost'}


class ZapError(RuntimeError):
    """Raised when a ZAP scan is unauthorized or the ZAP API is unavailable."""


class ZapOrchestrator:
    """Authorize and run ZAP spider/active scans against permitted targets."""

    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.zap_cfg = config.get('zap', {})

    # ------------------------------------------------------------- authorize
    def _h1_in_scope(self, host: str) -> bool:
        h1 = self.config.get('hackerone', {})
        if not h1.get('enabled'):
            return False
        from .hackerone_engagement import HackerOneEngagement
        return HackerOneEngagement(self.config).find_scope_asset(host) is not None

    def authorize(self, url: str) -> Tuple[bool, Optional[str]]:
        """Decide whether automated scanning of ``url`` is permitted."""
        parsed = urlparse(url or '')
        if parsed.scheme.lower() not in ('http', 'https'):
            return False, f'Target must be an http(s) URL, got: {url!r}'
        try:
            parsed.port  # raises ValueError on a non-numeric port (e.g. ":PORT")
        except ValueError:
            return False, (f'Invalid port in target URL: {url!r} '
                           '(use a real port number, e.g. http://127.0.0.1:8080/)')
        host = (parsed.hostname or '').lower().rstrip('.')
        if not host:
            return False, 'Invalid URL: missing host'

        if host in LOOPBACK_HOSTS:
            return True, None

        # Never auto-scan a bug-bounty target through this orchestrator.
        if self._h1_in_scope(host):
            return False, (
                'Refusing to automatically scan a HackerOne in-scope target. '
                'PlayStation and most programs list scanner output as out of scope '
                'and forbid disruption. Use ZAP as a passive proxy with manual '
                'testing instead.'
            )

        allowed_hosts = {h.lower().rstrip('.') for h in self.zap_cfg.get('allowed_hosts', [])}
        if (self.zap_cfg.get('automated_testing_allowed')
                and str(self.zap_cfg.get('authorization_reference', '')).strip()
                and host in allowed_hosts):
            return True, None

        return False, (
            f'Target "{host}" is not authorized for automated scanning. Use a '
            'self-hosted (loopback) target, or add it to zap.allowed_hosts with '
            'zap.automated_testing_allowed: true and an authorization_reference — '
            'only for a program whose policy explicitly permits automated scanning.'
        )

    # ------------------------------------------------------------------- ZAP
    def _connect(self):
        try:
            from zapv2 import ZAPv2
        except ImportError as exc:
            raise ZapError('ZAP client not installed. Run: pip install zaproxy') from exc
        api_url = self.zap_cfg.get('api_url', 'http://127.0.0.1:8080')
        api_key = self.zap_cfg.get('api_key') or os.environ.get('ZAP_API_KEY', '')
        return ZAPv2(apikey=api_key, proxies={'http': api_url, 'https': api_url})

    def scan(self, url: str, active: bool = False, zap=None) -> Dict[str, Any]:
        """Spider (and optionally active-scan) an AUTHORIZED target via ZAP.

        ``zap`` may be injected for testing; otherwise a live client is created.
        """
        ok, reason = self.authorize(url)
        if not ok:
            raise ZapError(reason)

        if zap is None:
            zap = self._connect()

        poll = int(self.zap_cfg.get('scan_poll_seconds', 5))
        max_spider = int(self.zap_cfg.get('spider_max_duration_min', 5))
        api_url = self.zap_cfg.get('api_url', 'http://127.0.0.1:8080')

        # Any failure talking to ZAP (not running, wrong api_url, bad target URL)
        # becomes a clean ZapError instead of an unhandled traceback.
        try:
            zap.urlopen(url)
            spider_id = zap.spider.scan(url, maxchildren=None)
            self._await(lambda: int(zap.spider.status(spider_id)), poll,
                        max_spider * 60 // max(poll, 1))
            # Let the passive scanner drain.
            self._await(lambda: 100 if int(zap.pscan.records_to_scan) == 0 else 0, poll, 60)

            active_ran = False
            if active:
                ascan_id = zap.ascan.scan(url)
                self._await(lambda: int(zap.ascan.status(ascan_id)), poll,
                            3600 // max(poll, 1))
                active_ran = True

            raw_alerts = zap.core.alerts(baseurl=url)
        except ZapError:
            raise
        except Exception as exc:  # noqa: BLE001 - normalize any ZAP/HTTP failure
            raise ZapError(
                f'Could not complete the ZAP scan of {url!r}. Check that ZAP is '
                f'running and reachable at {api_url} (start it with '
                f'"zaproxy -daemon -host 127.0.0.1 -port 8090 -config api.key=...") '
                f'and that the target URL is valid. Underlying error: {exc}'
            ) from exc

        findings = normalize_alerts({'alerts': raw_alerts})
        by_sev: Dict[str, int] = {}
        for f in findings:
            by_sev[f['severity']] = by_sev.get(f['severity'], 0) + 1

        return {
            'mode': 'active-scan' if active_ran else 'spider+passive',
            'target': url,
            'active_scan': active_ran,
            'alert_count': len(findings),
            'by_severity': by_sev,
            'findings': findings,
            'note': 'Automated scan of an authorized/self-hosted target. Scanner '
                    'output is triage material; verify before reporting.',
        }

    @staticmethod
    def _await(progress, poll_seconds: int, max_polls: int) -> None:
        """Poll ``progress`` (a 0-100 callable) until complete or capped."""
        import time
        for _ in range(max(1, max_polls)):
            try:
                if progress() >= 100:
                    return
            except Exception:
                return
            time.sleep(poll_seconds)
