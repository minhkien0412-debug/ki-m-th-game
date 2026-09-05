"""Tests for the maturity work: real passive validators, triage, fuzzer
minimization, and offline integrity analysis."""

import tempfile
import unittest
from pathlib import Path

from units.finding_engine import FindingEngine
from units.integrity_analyzer import IntegrityAnalyzer, IntegrityAnalyzerError
from units.local_crash_fuzzer import LocalCrashFuzzer
from units.validation_context import ValidationContext
from units.validators.authorization_boundary import AuthorizationBoundaryValidator
from units.validators.reflection import ReflectionValidator
from units.validators.security_headers import SecurityHeadersValidator


def ctx(responses=None, markers=None):
    c = ValidationContext('MISSION-TEST', {})
    for r in responses or []:
        c.add_response(r)
    for m in markers or []:
        c.mark_sent(m)
    return c


class TestSecurityHeadersValidator(unittest.TestCase):
    def test_flags_missing_headers_and_insecure_cookie(self):
        response = {
            'url': 'https://game.example/app',
            'status': 200,
            'response_headers': {
                'Content-Type': 'text/html',
                'Set-Cookie': 'sessionid=abc123; Path=/',
            },
        }
        result = SecurityHeadersValidator({}).validate(ctx([response]))
        sigs = {f['signature'] for f in result['findings']}
        self.assertIn('header|https://game.example|strict-transport-security', sigs)
        self.assertIn('header|https://game.example|content-security-policy', sigs)
        self.assertIn('cookie|https://game.example|sessionid|secure', sigs)
        self.assertIn('cookie|https://game.example|sessionid|httponly', sigs)

    def test_hardened_response_produces_no_findings(self):
        response = {
            'url': 'https://game.example/app',
            'status': 200,
            'response_headers': {
                'Content-Type': 'text/html',
                'Strict-Transport-Security': 'max-age=63072000',
                'Content-Security-Policy': "default-src 'self'; frame-ancestors 'none'",
                'X-Content-Type-Options': 'nosniff',
                'X-Frame-Options': 'DENY',
                'Referrer-Policy': 'no-referrer',
                'Set-Cookie': 'sessionid=abc; Secure; HttpOnly; SameSite=Lax',
            },
        }
        result = SecurityHeadersValidator({}).validate(ctx([response]))
        self.assertEqual(result['findings'], [])

    def test_same_origin_missing_header_is_reported_once(self):
        responses = [
            {'url': 'https://game.example/a', 'status': 200,
             'response_headers': {'Content-Type': 'text/html'}},
            {'url': 'https://game.example/b', 'status': 200,
             'response_headers': {'Content-Type': 'text/html'}},
        ]
        result = SecurityHeadersValidator({}).validate(ctx(responses))
        csp = [f for f in result['findings']
               if f['signature'].endswith('content-security-policy')]
        self.assertEqual(len(csp), 1)


class TestReflectionValidator(unittest.TestCase):
    def test_detects_reflected_marker(self):
        response = {
            'url': 'https://game.example/search?q=x',
            'status': 200,
            'response_headers': {'Content-Type': 'text/html'},
            'body': '<div>results for CyberArmyXSS456 here</div>',
        }
        result = ReflectionValidator({}).validate(ctx([response], markers=['CyberArmyXSS456']))
        self.assertEqual(len(result['findings']), 1)
        self.assertEqual(result['findings'][0]['type'], 'reflected_input')
        self.assertEqual(result['findings'][0]['severity'], 'medium')

    def test_no_reflection_no_finding(self):
        response = {
            'url': 'https://game.example/search',
            'status': 200,
            'response_headers': {'Content-Type': 'text/html'},
            'body': '<div>nothing here</div>',
        }
        result = ReflectionValidator({}).validate(ctx([response], markers=['CyberArmyXSS456']))
        self.assertEqual(result['findings'], [])


class TestAuthorizationBoundaryValidator(unittest.TestCase):
    def test_sensitive_success_without_auth_is_flagged(self):
        response = {
            'url': 'https://game.example/admin/users',
            'status': 200,
            'request_headers': {},
        }
        result = AuthorizationBoundaryValidator({}).validate(ctx([response]))
        types = {f['type'] for f in result['findings']}
        self.assertIn('missing_authorization', types)

    def test_sensitive_success_with_auth_is_not_flagged(self):
        response = {
            'url': 'https://game.example/admin/users',
            'status': 200,
            'request_headers': {'Authorization': 'Bearer x'},
        }
        result = AuthorizationBoundaryValidator({}).validate(ctx([response]))
        self.assertEqual(result['findings'], [])

    def test_inconsistent_auth_enforcement(self):
        responses = [
            {'url': 'https://game.example/account', 'status': 403,
             'request_headers': {}},
            {'url': 'https://game.example/account', 'status': 200,
             'request_headers': {}},
        ]
        result = AuthorizationBoundaryValidator({}).validate(ctx(responses))
        types = {f['type'] for f in result['findings']}
        self.assertIn('inconsistent_authorization', types)


class TestFindingTriage(unittest.TestCase):
    def test_dedup_by_signature_counts_occurrences(self):
        engine = FindingEngine({})
        f = {'type': 'x', 'title': 'T', 'severity': 'high', 'url': 'u',
             'description': 'd', 'signature': 'sig-1'}
        engine.add_findings([f, dict(f)])
        self.assertEqual(engine.get_summary()['total'], 1)
        only = engine.get_all_findings()[0]
        self.assertEqual(only['occurrences'], 2)
        self.assertTrue(only['id'].startswith('FINDING-'))

    def test_sorted_by_severity(self):
        engine = FindingEngine({})
        engine.add_findings([
            {'type': 'a', 'title': 'low', 'severity': 'low', 'signature': 's-low'},
            {'type': 'a', 'title': 'crit', 'severity': 'critical', 'signature': 's-crit'},
            {'type': 'a', 'title': 'med', 'severity': 'medium', 'signature': 's-med'},
        ])
        order = [f['severity'] for f in engine.get_sorted_findings()]
        self.assertEqual(order, ['critical', 'medium', 'low'])

    def test_id_is_stable_across_engines(self):
        a = FindingEngine({}).create_finding('t', 'Title', 'low', 'u', signature='same')
        b = FindingEngine({}).create_finding('t', 'Title', 'low', 'u', signature='same')
        self.assertEqual(a, b)


class TestFuzzerMinimization(unittest.TestCase):
    def test_minimize_shrinks_while_still_crashing(self):
        original = b'AAAAAAAAAABUGAAAAAAAAAA'
        crashes = lambda d: b'BUG' in d
        minimized = LocalCrashFuzzer.minimize(original, crashes)
        self.assertIn(b'BUG', minimized)
        self.assertLess(len(minimized), len(original))
        self.assertTrue(crashes(minimized))

    def test_minimize_noop_when_not_crashing(self):
        original = b'no-trigger-here'
        minimized = LocalCrashFuzzer.minimize(original, lambda d: b'BUG' in d)
        self.assertEqual(minimized, original)

    def test_crash_signature_groups_and_distinguishes(self):
        s1 = LocalCrashFuzzer.crash_signature(0xC0000005, 'Segmentation fault\nline2')
        s2 = LocalCrashFuzzer.crash_signature(0xC0000005, 'Segmentation fault\nline9')
        s3 = LocalCrashFuzzer.crash_signature(0xC0000094, 'Segmentation fault')
        self.assertEqual(s1, s2)          # same code + first stderr line
        self.assertNotEqual(s1, s3)       # different exit code


class TestIntegrityAnalyzer(unittest.TestCase):
    def _write(self, root, rows, header='frame_time_ms,player_speed'):
        path = Path(root) / 'telemetry.csv'
        path.write_text(header + '\n' + '\n'.join(rows) + '\n', encoding='utf-8')
        return str(path)

    def test_detects_bounds_outliers_and_frametime(self):
        rows = [f'16.6,{s}' for s in [10, 11, 10, 12, 9, 10, 11, 10, 10, 11]]
        rows.append('0.0,10')      # near-zero frame time (time manipulation)
        rows.append('16.6,999')    # speed way out of range + statistical outlier
        with tempfile.TemporaryDirectory() as root:
            csv_path = self._write(root, rows)
            cfg = {'integrity': {'bounds': {'player_speed': {'min': 0, 'max': 50}}}}
            result = IntegrityAnalyzer(cfg).analyze(csv_path)
        types = {f['type'] for f in result['findings']}
        self.assertIn('integrity_bound_violation', types)
        self.assertIn('integrity_time_anomaly', types)
        self.assertIn('integrity_statistical_outlier', types)
        self.assertEqual(result['mode'], 'offline-integrity-analysis')
        self.assertIn('source_sha256', result)

    def test_clean_telemetry_yields_no_findings(self):
        rows = [f'16.6,{s}' for s in [10, 11, 10, 12, 9, 10, 11, 10, 10, 11]]
        with tempfile.TemporaryDirectory() as root:
            csv_path = self._write(root, rows)
            result = IntegrityAnalyzer({}).analyze(csv_path)
        self.assertEqual(result['finding_count'], 0)

    def test_missing_file_errors(self):
        with self.assertRaises(IntegrityAnalyzerError):
            IntegrityAnalyzer({}).analyze('/nonexistent/telemetry.csv')


if __name__ == '__main__':
    unittest.main()
