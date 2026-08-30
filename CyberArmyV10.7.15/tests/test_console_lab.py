"""Tests for the fail-closed PlayStation dev/test-kit integration layer."""

import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from units.console_artifacts import (
    ConsoleArtifactManager,
    ConsoleCorpusIndexer,
    ConsoleTelemetryAnalyzer,
)
from units.console_kit_adapter import ConsoleKitAdapter
from units.console_lab_policy import ConsoleLabPolicy
from units.local_lab_policy import LocalLabError


def console_config(root: str, allow_execution: bool = False):
    tool = Path(root) / 'official-sdk-tool.exe'
    tool.write_bytes(b'owned-test-tool-placeholder')
    return {
        'console_lab': {
            'enabled': True,
            'partner_access_confirmed': True,
            'official_sdk_installed': True,
            'dev_or_test_kit_only': True,
            'human_in_the_loop': True,
            'network_isolated': True,
            'allow_device_execution': allow_execution,
            'authorization_reference': 'UNIT-TEST-CONSOLE-LAB',
            'platform': 'ps5',
            'kit_id': 'OWNED-TEST-KIT-01',
            'workspace_root': root,
            'process_timeout_seconds': 2,
            'max_artifact_bytes': 1048576,
            'max_crash_bytes': 1048576,
            'max_corpus_files': 10,
            'max_telemetry_rows': 100,
            'frame_budget_ms': 16.667,
            'allowed_artifact_extensions': ['.pkg'],
            'allowed_crash_extensions': ['.dmp', '.log'],
            'artifact_output_dir': 'state/console_artifacts',
            'session_output_dir': 'state/console_sessions',
            'sdk_environment_allowlist': [],
            'run_command': [str(tool), '--kit', '{kit_id}', '--run', '{artifact}'],
            'symbolicate_command': [
                str(tool), '--crash', '{crash}', '--symbols', '{symbols}',
                '--output', '{output_dir}',
            ],
            'preflight_command': [str(tool), '--status', '{kit_id}'],
            'deploy_command': [str(tool), '--deploy', '{artifact}'],
            'launch_command': [str(tool), '--launch', '{artifact}'],
            'collect_command': [str(tool), '--collect', '{session_dir}'],
            'stop_command': [str(tool), '--stop', '{kit_id}'],
        }
    }


class TestConsolePolicy(unittest.TestCase):
    def test_policy_is_fail_closed_and_requires_explicit_execution_flag(self):
        with tempfile.TemporaryDirectory() as root:
            config = console_config(root)
            policy = ConsoleLabPolicy(config)

            self.assertTrue(policy.validate()[0])
            self.assertFalse(policy.validate(require_execution=True)[0])
            with self.assertRaisesRegex(LocalLabError, 'allow_device_execution'):
                policy.require_valid(require_execution=True)

    def test_workspace_escape_and_unknown_command_placeholder_are_blocked(self):
        with tempfile.TemporaryDirectory() as root:
            policy = ConsoleLabPolicy(console_config(root))
            with self.assertRaisesRegex(LocalLabError, 'escapes'):
                policy.require_workspace_path('../outside.pkg')
            with self.assertRaisesRegex(LocalLabError, 'unsupported placeholders'):
                policy.validate_command_template(
                    [str(Path(root) / 'official-sdk-tool.exe'), '{unknown}'],
                    'run_command',
                )

    def test_capability_validation_does_not_require_unrelated_tools(self):
        with tempfile.TemporaryDirectory() as root:
            config = console_config(root)
            config['console_lab']['run_command'] = []
            config['console_lab']['symbolicate_command'] = []
            policy = ConsoleLabPolicy(config)

            self.assertTrue(policy.validate_capability('corpus')[0])
            self.assertFalse(policy.validate_capability('run')[0])
            self.assertFalse(policy.validate_capability('symbolicate')[0])


class TestConsoleKitAdapter(unittest.TestCase):
    def test_dry_run_hashes_artifact_and_builds_argv_without_a_shell(self):
        with tempfile.TemporaryDirectory() as root:
            artifact = Path(root) / 'owned-build.pkg'
            artifact.write_bytes(b'owned-console-build')
            result = ConsoleKitAdapter(console_config(root)).plan_artifact(
                'owned-build.pkg'
            )

        self.assertEqual(result['mode'], 'dry-run')
        self.assertFalse(result['shell'])
        self.assertIn('OWNED-TEST-KIT-01', result['argv'])
        self.assertEqual(len(result['artifact_sha256']), 64)

    def test_execution_uses_argv_and_shell_false(self):
        with tempfile.TemporaryDirectory() as root:
            artifact = Path(root) / 'owned-build.pkg'
            artifact.write_bytes(b'owned-console-build')
            completed = subprocess.CompletedProcess(
                args=[], returncode=0, stdout=b'ok', stderr=b''
            )
            with patch(
                'units.console_kit_adapter.subprocess.run', return_value=completed
            ) as run:
                result = ConsoleKitAdapter(
                    console_config(root, allow_execution=True)
                ).run_artifact('owned-build.pkg')

        self.assertTrue(result['successful'])
        self.assertFalse(run.call_args.kwargs['shell'])
        self.assertIsInstance(run.call_args.args[0], list)

    def test_workflow_always_stops_after_a_launch_failure_and_writes_audit(self):
        with tempfile.TemporaryDirectory() as root:
            artifact = Path(root) / 'owned-build.pkg'
            artifact.write_bytes(b'owned-console-build')
            completed = [
                subprocess.CompletedProcess([], 0, b'healthy', b''),
                subprocess.CompletedProcess([], 0, b'deployed', b''),
                subprocess.CompletedProcess([], 1, b'', b'token=abcdefghijklmnopqrstuvwxyz'),
                subprocess.CompletedProcess([], 0, b'stopped', b''),
            ]
            with patch(
                'units.console_kit_adapter.subprocess.run', side_effect=completed
            ) as run:
                result = ConsoleKitAdapter(
                    console_config(root, allow_execution=True)
                ).run_workflow('owned-build.pkg')

            self.assertFalse(result['successful'])
            self.assertEqual([step['step'] for step in result['steps']], [
                'preflight', 'deploy', 'launch', 'stop'
            ])
            self.assertEqual(run.call_count, 4)
            self.assertIn('--stop', run.call_args.args[0])
            self.assertIn('[REDACTED]', result['steps'][2]['stderr_tail'])
            self.assertTrue(Path(result['audit_path']).is_file())


class TestConsoleArtifacts(unittest.TestCase):
    def test_crash_import_is_hashed_and_copied_with_a_manifest(self):
        with tempfile.TemporaryDirectory() as root:
            crash = Path(root) / 'exported-crash.dmp'
            crash.write_bytes(b'owned-crash-dump')
            result = ConsoleArtifactManager(console_config(root)).import_crash(
                'exported-crash.dmp'
            )

            self.assertTrue(Path(result['stored_path']).is_file())
            self.assertTrue(Path(result['manifest_path']).is_file())
            self.assertEqual(len(result['sha256']), 64)
            duplicate = ConsoleArtifactManager(console_config(root)).import_crash(
                'exported-crash.dmp'
            )
            self.assertTrue(duplicate['duplicate'])
            self.assertEqual(duplicate['signature_occurrences'], 2)

    def test_symbolication_hook_is_offline_and_shell_free(self):
        with tempfile.TemporaryDirectory() as root:
            crash = Path(root) / 'exported-crash.dmp'
            symbols = Path(root) / 'owned-symbols.log'
            crash.write_bytes(b'owned-crash-dump')
            symbols.write_bytes(b'owned-symbol-map')
            completed = subprocess.CompletedProcess(
                args=[], returncode=0, stdout=b'symbolicated', stderr=b''
            )
            with patch(
                'units.console_artifacts.subprocess.run', return_value=completed
            ) as run:
                result = ConsoleArtifactManager(console_config(root)).symbolicate(
                    'exported-crash.dmp', 'owned-symbols.log'
                )

            self.assertEqual(result['return_code'], 0)
            self.assertFalse(run.call_args.kwargs['shell'])
            self.assertTrue(Path(result['output_dir'], 'symbolication.json').is_file())

    def test_corpus_manifest_is_deterministic_and_offline(self):
        with tempfile.TemporaryDirectory() as root:
            corpus = Path(root) / 'corpus'
            corpus.mkdir()
            (corpus / 'case-b.bin').write_bytes(b'b')
            (corpus / 'case-a.bin').write_bytes(b'a')
            result = ConsoleCorpusIndexer(console_config(root)).index('corpus')

            self.assertEqual(result['mode'], 'offline-owned-corpus')
            self.assertEqual(result['file_count'], 2)
            self.assertEqual(
                [item['path'] for item in result['files']],
                ['case-a.bin', 'case-b.bin'],
            )
            self.assertTrue(Path(result['manifest_path']).is_file())
            second = ConsoleCorpusIndexer(console_config(root)).index('corpus')
            self.assertEqual(second['files'], result['files'])

    def test_telemetry_analysis_reports_frame_budget_and_percentiles(self):
        with tempfile.TemporaryDirectory() as root:
            telemetry = Path(root) / 'telemetry.csv'
            telemetry.write_text(
                'frame_time_ms,memory_mb,cpu_percent,gpu_percent,network_kbps\n'
                '10,100,20,30,40\n'
                '20,110,25,35,50\n'
                'bad,120,30,40,60\n',
                encoding='utf-8',
            )
            result = ConsoleTelemetryAnalyzer(console_config(root)).analyze(
                'telemetry.csv'
            )

        self.assertEqual(result['mode'], 'offline-telemetry-analysis')
        self.assertEqual(result['valid_rows'], 2)
        self.assertEqual(result['invalid_rows'], 1)
        self.assertEqual(result['frames_over_budget'], 1)
        self.assertEqual(result['metrics']['frame_time_ms']['p95'], 20.0)


if __name__ == '__main__':
    unittest.main()
