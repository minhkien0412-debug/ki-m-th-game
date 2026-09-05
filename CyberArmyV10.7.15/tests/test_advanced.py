"""Tests for coverage-guided fuzzing, sanitizer parsing, and anti-cheat rules."""

import tempfile
import unittest
from pathlib import Path

from units.anticheat_rules import AntiCheatRuleEngine
from units.coverage_fuzzer import LocalCoverageFuzzer
from units.integrity_analyzer import IntegrityAnalyzer
from units.local_crash_fuzzer import LocalCrashFuzzer
from units.sanitizer import parse_sanitizer_report, sanitizer_signature

HERE = str(Path(__file__).resolve().parent)

ASAN_REPORT = """=================================================================
==12345==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x602000000094
READ of size 4 at 0x602000000094 thread T0
    #0 0x4a1b2c in parse_packet /src/net/parse.c:88:12
    #1 0x4a2000 in main /src/main.c:20:3
"""

UBSAN_REPORT = "/src/math.c:42:10: runtime error: signed integer overflow: 2147483647 + 1"


def lab_config(root):
    return {'local_lab': {
        'enabled': True,
        'authorized_self_hosted_only': True,
        'human_in_the_loop': True,
        'network_isolated': True,
        'authorization_reference': 'LAB-TEST-001',
        'workspace_root': root,
        'max_fuzz_cases': 50,
        'max_input_bytes': 4096,
    }}


# --- coverage fuzz targets (module-level so co_filename == this test file) ---
def target_branches(data: bytes):
    n = len(data)
    if n == 0:
        return 'empty'
    if data[0] > 200:
        return 'high'
    if n > 5:
        return 'long'
    return 'ok'


_SENTINEL = b'UNREACHABLE-SENTINEL-VALUE'


def target_always_crashes(data: bytes):
    if data != _SENTINEL:
        raise ValueError('boom')
    return 'never'


class TestSanitizerParser(unittest.TestCase):
    def test_parses_asan_report(self):
        report = parse_sanitizer_report(ASAN_REPORT)
        self.assertEqual(report['tool'], 'AddressSanitizer')
        self.assertEqual(report['bug'], 'heap-buffer-overflow')
        self.assertEqual(report['function'], 'parse_packet')
        self.assertIn('parse.c:88', report['location'])

    def test_parses_ubsan_report(self):
        report = parse_sanitizer_report(UBSAN_REPORT)
        self.assertEqual(report['tool'], 'UndefinedBehaviorSanitizer')
        self.assertIn('signed integer overflow', report['bug'])

    def test_none_when_no_report(self):
        self.assertIsNone(parse_sanitizer_report('just normal output'))

    def test_signature_is_stable(self):
        self.assertEqual(sanitizer_signature(ASAN_REPORT), sanitizer_signature(ASAN_REPORT))


class TestCrashSignatureUsesSanitizer(unittest.TestCase):
    def test_asan_report_drives_signature(self):
        sig = LocalCrashFuzzer.crash_signature(-11, ASAN_REPORT)
        self.assertTrue(sig.startswith('san|AddressSanitizer|heap-buffer-overflow'))

    def test_plain_crash_falls_back_to_code(self):
        sig = LocalCrashFuzzer.crash_signature(0xC0000005, 'no sanitizer here')
        self.assertTrue(sig.startswith('0x'))


class TestCoverageFuzzer(unittest.TestCase):
    def test_collects_coverage_without_crashing(self):
        with tempfile.TemporaryDirectory() as root:
            result = LocalCoverageFuzzer(lab_config(root)).fuzz(
                target_branches, [b'AA'], iterations=30, trace_paths=[HERE]
            )
        self.assertEqual(result['mode'], 'coverage-guided-python-harness')
        self.assertGreater(result['edges_discovered'], 0)
        self.assertEqual(result['crashes'], 0)

    def test_finds_and_minimizes_a_crash(self):
        with tempfile.TemporaryDirectory() as root:
            result = LocalCoverageFuzzer(lab_config(root)).fuzz(
                target_always_crashes, [b'AAAAAAAA'], iterations=10, trace_paths=[HERE]
            )
            # Assert while the workspace tempdir still exists.
            self.assertGreater(result['crashes'], 0)
            self.assertEqual(result['unique_crashes'], 1)
            detail = result['unique_crash_details'][0]
            self.assertEqual(detail['exception'], 'ValueError')
            self.assertTrue(Path(detail['saved_input']).exists())
            # Every mutated input crashes, so minimization shrinks the reproducer.
            self.assertIn('minimized_bytes', detail)
            self.assertLessEqual(detail['minimized_bytes'], detail['input_bytes'])

    def test_requires_valid_lab_policy(self):
        with tempfile.TemporaryDirectory() as root:
            cfg = lab_config(root)
            cfg['local_lab']['enabled'] = False
            from units.local_lab_policy import LocalLabError
            with self.assertRaises(LocalLabError):
                LocalCoverageFuzzer(cfg).fuzz(target_branches, [b'A'], 5, trace_paths=[HERE])


class TestAntiCheatRules(unittest.TestCase):
    def _cols(self, **series):
        return {name: [{'row': i + 1, 'value': float(v)} for i, v in enumerate(vals)]
                for name, vals in series.items()}

    def test_max_and_min(self):
        cols = self._cols(speed=[5, 6, 99, 4])
        f = AntiCheatRuleEngine([{'type': 'max', 'column': 'speed', 'value': 50}]).evaluate(cols)
        self.assertEqual(len(f), 1)
        self.assertEqual(f[0]['evidence']['violation_count'], 1)
        self.assertEqual(f[0]['type'], 'anticheat_rule_violation')

    def test_max_delta_catches_teleport(self):
        cols = self._cols(x=[0, 1, 2, 500, 501])
        f = AntiCheatRuleEngine([{'type': 'max_delta', 'column': 'x', 'value': 10}]).evaluate(cols)
        self.assertEqual(f[0]['evidence']['violation_count'], 1)

    def test_monotonic_timestamp(self):
        cols = self._cols(t=[1, 2, 3, 2, 4])
        f = AntiCheatRuleEngine([{'type': 'monotonic', 'column': 't',
                                  'direction': 'nondecreasing'}]).evaluate(cols)
        self.assertEqual(f[0]['severity'], 'medium')
        self.assertEqual(f[0]['evidence']['violation_count'], 1)

    def test_allowed_set(self):
        cols = self._cols(item_id=[1, 2, 2, 7])
        f = AntiCheatRuleEngine([{'type': 'allowed_set', 'column': 'item_id',
                                  'values': [1, 2, 3]}]).evaluate(cols)
        self.assertEqual(f[0]['evidence']['violation_count'], 1)

    def test_max_rate(self):
        cols = self._cols(score=[0, 10, 1000], t=[0, 1, 2])
        f = AntiCheatRuleEngine([{'type': 'max_rate', 'column': 'score',
                                  'per': 't', 'value': 100}]).evaluate(cols)
        self.assertEqual(f[0]['evidence']['violation_count'], 1)

    def test_missing_column_is_skipped(self):
        cols = self._cols(a=[1, 2, 3])
        f = AntiCheatRuleEngine([{'type': 'max', 'column': 'nope', 'value': 1}]).evaluate(cols)
        self.assertEqual(f, [])


class TestIntegrityRulesIntegration(unittest.TestCase):
    def test_rules_run_via_integrity_analyzer(self):
        with tempfile.TemporaryDirectory() as root:
            csv_path = Path(root) / 'tele.csv'
            rows = ['frame_time_ms,player_speed']
            rows += [f'16.6,{s}' for s in [5, 6, 5, 7, 6, 5, 6, 5, 300]]
            csv_path.write_text('\n'.join(rows) + '\n', encoding='utf-8')
            cfg = {'integrity': {'rules': [
                {'id': 'speed-cap', 'type': 'max', 'column': 'player_speed', 'value': 50},
            ]}}
            result = IntegrityAnalyzer(cfg).analyze(str(csv_path))
        types = {f['type'] for f in result['findings']}
        self.assertIn('anticheat_rule_violation', types)
        sigs = {f['signature'] for f in result['findings']}
        self.assertIn('anticheat|speed-cap', sigs)


if __name__ == '__main__':
    unittest.main()
