"""Tests for ZAP import and the fail-closed ZAP orchestrator."""

import unittest

from units.zap_import import normalize_alerts, ZapFindingImporter
from units.zap_orchestrator import ZapOrchestrator, ZapError


def h1_config(extra_zap=None):
    cfg = {
        'hackerone': {
            'enabled': True,
            'scope_assets': [
                {'type': 'domain', 'identifier': '*.playstation.net',
                 'eligible_for_submission': True, 'allowed_actions': ['passive_recon']},
            ],
        }
    }
    if extra_zap is not None:
        cfg['zap'] = extra_zap
    return cfg


class TestZapImport(unittest.TestCase):
    def test_flat_list_and_risk_mapping(self):
        data = [
            {'alert': 'SQL Injection', 'riskcode': '3', 'url': 'https://x.example/a', 'param': 'id'},
            {'name': 'Reflected XSS', 'risk': 'Medium', 'url': 'https://x.example/b'},
            {'alert': 'Info leak', 'riskcode': '0', 'url': 'https://x.example/c'},
        ]
        findings = normalize_alerts(data)
        sev = {f['title']: f['severity'] for f in findings}
        self.assertEqual(sev['SQL Injection'], 'high')
        self.assertEqual(sev['Reflected XSS'], 'medium')
        self.assertEqual(sev['Info leak'], 'info')

    def test_traditional_site_report_shape(self):
        data = {'site': [{'@name': 'https://x.example',
                          'alerts': [{'alert': 'CSP missing', 'riskcode': '1',
                                      'url': 'https://x.example/'}]}]}
        findings = normalize_alerts(data)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]['severity'], 'low')

    def test_dedup_by_signature_counts_occurrences(self):
        data = [
            {'alert': 'X', 'riskcode': '2', 'url': 'https://x.example/1', 'param': 'q'},
            {'alert': 'X', 'riskcode': '2', 'url': 'https://x.example/1', 'param': 'q'},
        ]
        findings = normalize_alerts(data)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]['evidence']['occurrences'], 2)

    def test_scope_filter_drops_out_of_scope_hosts(self):
        data = [
            {'alert': 'A', 'riskcode': '2', 'url': 'https://a.playstation.net/x'},
            {'alert': 'B', 'riskcode': '2', 'url': 'https://evil.example/y'},
        ]
        importer = ZapFindingImporter(h1_config())
        predicate = importer._scope_predicate()
        findings = normalize_alerts(data, predicate)
        urls = [f['url'] for f in findings]
        self.assertIn('https://a.playstation.net/x', urls)
        self.assertNotIn('https://evil.example/y', urls)


class TestZapAuthorize(unittest.TestCase):
    def test_loopback_is_allowed(self):
        ok, _ = ZapOrchestrator({}).authorize('http://127.0.0.1:8080/')
        self.assertTrue(ok)

    def test_hackerone_target_is_refused(self):
        ok, reason = ZapOrchestrator(h1_config()).authorize('https://a.playstation.net/')
        self.assertFalse(ok)
        self.assertIn('Refusing to automatically scan', reason)

    def test_attested_allowlisted_host_is_allowed(self):
        cfg = {'zap': {'automated_testing_allowed': True,
                       'authorization_reference': 'ENG-1',
                       'allowed_hosts': ['staging.example']}}
        ok, _ = ZapOrchestrator(cfg).authorize('https://staging.example/app')
        self.assertTrue(ok)

    def test_attestation_missing_reference_is_refused(self):
        cfg = {'zap': {'automated_testing_allowed': True, 'allowed_hosts': ['staging.example']}}
        ok, reason = ZapOrchestrator(cfg).authorize('https://staging.example/app')
        self.assertFalse(ok)
        self.assertIn('not authorized', reason)

    def test_unknown_host_is_refused(self):
        ok, _ = ZapOrchestrator({}).authorize('https://random.example/')
        self.assertFalse(ok)

    def test_placeholder_port_is_refused_cleanly(self):
        ok, reason = ZapOrchestrator({}).authorize('http://127.0.0.1:PORT/')
        self.assertFalse(ok)
        self.assertIn('port', reason.lower())

    def test_non_http_scheme_is_refused(self):
        ok, reason = ZapOrchestrator({}).authorize('ftp://127.0.0.1/')
        self.assertFalse(ok)
        self.assertIn('http', reason.lower())


class FakeZap:
    class _Spider:
        def scan(self, url, maxchildren=None): return '0'
        def status(self, sid): return '100'

    class _Pscan:
        records_to_scan = '0'

    class _Ascan:
        def __init__(self): self.called = False
        def scan(self, url): self.called = True; return '0'
        def status(self, sid): return '100'

    class _Core:
        def alerts(self, baseurl=None):
            return [{'alert': 'Test', 'riskcode': '2', 'url': 'http://127.0.0.1:8080/x'}]

    def __init__(self):
        self.spider = self._Spider()
        self.pscan = self._Pscan()
        self.ascan = self._Ascan()
        self.core = self._Core()

    def urlopen(self, url): pass


class TestZapScanFlow(unittest.TestCase):
    def test_authorized_active_scan_runs_and_returns_alerts(self):
        fake = FakeZap()
        result = ZapOrchestrator({}).scan('http://127.0.0.1:8080/', active=True, zap=fake)
        self.assertEqual(result['mode'], 'active-scan')
        self.assertTrue(fake.ascan.called)
        self.assertEqual(result['alert_count'], 1)

    def test_unauthorized_scan_raises_before_touching_zap(self):
        fake = FakeZap()
        with self.assertRaises(ZapError):
            ZapOrchestrator(h1_config()).scan('https://a.playstation.net/', zap=fake)
        self.assertFalse(fake.ascan.called)

    def test_zap_connection_failure_becomes_clean_error(self):
        class RaisingZap(FakeZap):
            def urlopen(self, url):
                raise ConnectionError('connection refused')

        with self.assertRaises(ZapError) as ctx:
            ZapOrchestrator({}).scan('http://127.0.0.1:8090/', zap=RaisingZap())
        self.assertIn('ZAP', str(ctx.exception))


if __name__ == '__main__':
    unittest.main()
