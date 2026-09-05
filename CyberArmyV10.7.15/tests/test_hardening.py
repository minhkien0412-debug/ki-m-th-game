"""Tests for the safety-hardening fixes (DNS pinning, blocklist, lazy imports)."""

import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock

from urllib3.util import connection as urllib3_connection

import units.pinned_connection as pinned_connection
from units.canonicalizer import Canonicalizer
from units.console_kit_adapter import ConsoleKitAdapter
from units.scope_engine import ScopeEngine
from units.target_request_gate import TargetRequestGate


class TestConnectionPinning(unittest.TestCase):
    def test_pin_host_forces_connection_to_validated_ip(self):
        pinned_connection.install()
        captured = []

        def fake_create_connection(address, *args, **kwargs):
            captured.append(address)
            return 'socket'

        original = pinned_connection._real_create_connection
        pinned_connection._real_create_connection = fake_create_connection
        try:
            # Case-insensitive host key; the socket must dial the pinned IP.
            with pinned_connection.pin_host('Example.COM', '203.0.113.9'):
                urllib3_connection.create_connection(('example.com', 443))
            self.assertEqual(captured[-1], ('203.0.113.9', 443))

            # Outside the pin, resolution passes through untouched.
            urllib3_connection.create_connection(('example.com', 443))
            self.assertEqual(captured[-1], ('example.com', 443))
        finally:
            pinned_connection._real_create_connection = original

    def test_pin_is_restored_after_nested_context(self):
        pinned_connection.install()
        with pinned_connection.pin_host('host.test', '198.51.100.1'):
            with pinned_connection.pin_host('host.test', '198.51.100.2'):
                self.assertEqual(pinned_connection._pins().get('host.test'), '198.51.100.2')
            self.assertEqual(pinned_connection._pins().get('host.test'), '198.51.100.1')
        self.assertNotIn('host.test', pinned_connection._pins())


class TestGatePinSelection(unittest.TestCase):
    def setUp(self):
        self.gate = TargetRequestGate({'target': {'allowed_hosts': ['example.com']}})
        self.addCleanup(self.gate.close)

    def test_ip_literal_host_is_not_pinned(self):
        self.assertIsNone(self.gate._choose_pin_ip('93.184.216.34', ['93.184.216.34']))

    def test_ipv4_is_preferred_over_ipv6(self):
        chosen = self.gate._choose_pin_ip('example.com', ['2606:2800:220:1::1', '93.184.216.34'])
        self.assertEqual(chosen, '93.184.216.34')

    def test_ipv6_only_host_pins_the_ipv6(self):
        chosen = self.gate._choose_pin_ip('example.com', ['2606:2800:220:1::1'])
        self.assertEqual(chosen, '2606:2800:220:1::1')

    def test_validate_before_request_records_the_pin(self):
        self.gate.canonicalizer.validate_url = Mock(return_value=(True, None))
        self.gate.dns_gate.safe_request_check = Mock(
            return_value=(True, None, ['93.184.216.34'])
        )
        ok, err = self.gate.validate_before_request('https://example.com/api')
        self.assertTrue(ok)
        self.assertIsNone(err)
        self.assertEqual(self.gate._take_pin('example.com'), '93.184.216.34')

    def test_blocked_resolution_reports_two_tuple_and_no_pin(self):
        self.gate.canonicalizer.validate_url = Mock(return_value=(True, None))
        self.gate.dns_gate.safe_request_check = Mock(
            return_value=(False, 'private IP: 127.0.0.1', ['127.0.0.1'])
        )
        result = self.gate.validate_before_request('https://example.com/api')
        self.assertEqual(len(result), 2)
        ok, err = result
        self.assertFalse(ok)
        self.assertIn('DNS/IP safety check failed', err)
        self.assertIsNone(self.gate._take_pin('example.com'))


class TestBlockedPathHardening(unittest.TestCase):
    def test_canonicalizer_blocklist_resists_case_and_missing_slash(self):
        canon = Canonicalizer(
            allowed_hosts=['example.com'], allowed_paths=[], blocked_paths=['/admin/*']
        )
        for blocked in ('/admin', '/admin/', '/admin/panel', '/ADMIN/secret'):
            allowed, _ = canon.is_path_allowed(blocked)
            self.assertFalse(allowed, f'{blocked} should be blocked')
        # A sibling that merely shares a prefix must stay allowed.
        allowed, _ = canon.is_path_allowed('/administrator')
        self.assertTrue(allowed)

    def test_scope_engine_blocklist_resists_case_and_missing_slash(self):
        engine = ScopeEngine({'target': {'allowed_hosts': ['example.com'],
                                          'allowed_paths': [],
                                          'blocked_paths': ['/admin/*']}})
        for blocked in ('/admin', '/ADMIN/secret'):
            allowed, _ = engine.is_path_in_scope(blocked)
            self.assertFalse(allowed, f'{blocked} should be blocked')


class TestNormalizerParity(unittest.TestCase):
    def test_scope_engine_delegates_to_canonicalizer(self):
        cfg = {'target': {'allowed_hosts': ['example.com'],
                          'allowed_paths': [], 'blocked_paths': []}}
        url = 'https://EXAMPLE.com//a/./b/../c'
        expected = Canonicalizer(['example.com'], [], []).normalize_url(url)
        self.assertEqual(ScopeEngine(cfg).normalize_url(url), expected)
        # The old copy could not resolve '..'; the shared one does.
        self.assertNotIn('..', ScopeEngine(cfg).normalize_url(url))


class TestLazyUnitImports(unittest.TestCase):
    def test_importing_units_does_not_pull_web_analyzer(self):
        script = (
            'import sys, units\n'
            "assert 'units.web_analyzer' not in sys.modules, 'web_analyzer eagerly imported'\n"
            "assert 'units.api_boundary_lab' not in sys.modules, 'api_boundary_lab eagerly imported'\n"
            'from units.console_lab_policy import ConsoleLabPolicy\n'
            'print(units.canonicalizer.__name__)\n'  # lazy attribute access still works
        )
        result = subprocess.run(
            [sys.executable, '-c', script],
            capture_output=True, text=True, cwd=str(Path(__file__).resolve().parent.parent),
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('units.canonicalizer', result.stdout)


class TestScanProducesNoFabricatedFindings(unittest.TestCase):
    def test_safe_validators_yield_no_findings(self):
        from units.safe_validator import SafeValidator
        from units.validation_context import ValidationContext
        from units.validators.reflection import ReflectionValidator
        from units.validators.authorization_boundary import (
            AuthorizationBoundaryValidator,
        )

        cfg = {'validation': {'safe_validators_only': True}, 'rate_limit': {}}
        registry = SafeValidator(cfg)
        registry.register_validator('reflection', ReflectionValidator(cfg))
        registry.register_validator(
            'authorization_boundary', AuthorizationBoundaryValidator(cfg)
        )
        context = ValidationContext('MISSION-TEST', cfg)
        results = registry.run_all_validators(context)
        total = sum(len(r.get('findings', [])) for r in results)
        self.assertEqual(total, 0)
        self.assertEqual(len(registry.get_all_validators()), 2)


class TestConsoleTimeoutShape(unittest.TestCase):
    def test_timeout_result_includes_output_tails(self):
        with tempfile.TemporaryDirectory() as tmp:
            adapter = ConsoleKitAdapter({'console_lab': {
                'process_timeout_seconds': 1,
                'workspace_root': tmp,
            }})
            result = adapter._execute_command(
                'launch',
                [sys.executable, '-c', 'import time; time.sleep(5)'],
                Path(tmp),
            )
        self.assertTrue(result['timed_out'])
        self.assertFalse(result['successful'])
        self.assertIn('stdout_tail', result)
        self.assertIn('stderr_tail', result)


if __name__ == '__main__':
    unittest.main()
