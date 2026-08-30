"""Tests for the isolated, self-hosted research lab."""

import asyncio
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from aiohttp import web

from units.api_boundary_lab import BoundaryCaseGenerator, LocalApiInvariantTester
from units.local_crash_fuzzer import LocalCrashFuzzer
from units.local_lab_policy import LocalLabError, LocalLabPolicy
from units.observation_instrumentation import ObservationScriptBuilder
from units.protocol_corpus import ProtocolCorpusAnalyzer


def lab_config(root: str):
    return {
        'local_lab': {
            'enabled': True,
            'authorized_self_hosted_only': True,
            'human_in_the_loop': True,
            'network_isolated': True,
            'authorization_reference': 'UNIT-TEST-OWNED-LAB',
            'workspace_root': root,
            'max_api_cases': 16,
            'max_concurrency': 2,
            'max_fuzz_cases': 10,
            'max_input_bytes': 1048576,
            'max_response_bytes': 262144,
            'process_timeout_seconds': 2,
            'allowed_executable_extensions': ['.exe'],
            'trace_output_dir': 'state/traces',
            'fuzz_output_dir': 'state/fuzz',
        }
    }


class TestLocalLabPolicy(unittest.TestCase):
    def test_remote_and_privileged_targets_are_blocked(self):
        with tempfile.TemporaryDirectory() as root:
            policy = LocalLabPolicy(lab_config(root))

            self.assertEqual(
                policy.require_loopback_url('http://127.0.0.1:8080/test'),
                'http://127.0.0.1:8080/test',
            )
            with self.assertRaises(LocalLabError):
                policy.require_loopback_url('https://example.com:8443/test')
            with self.assertRaises(LocalLabError):
                policy.require_loopback_url('http://127.0.0.1:80/test')

    def test_workspace_escape_is_blocked(self):
        with tempfile.TemporaryDirectory() as root:
            policy = LocalLabPolicy(lab_config(root))
            with self.assertRaisesRegex(LocalLabError, 'escapes'):
                policy.require_workspace_file('../outside.bin', must_exist=False)


class TestBoundaryLab(unittest.TestCase):
    def test_boundary_cases_are_deterministic_and_bounded(self):
        cases = BoundaryCaseGenerator.generate({'quantity': 1}, 'quantity', 'integer')

        self.assertEqual(len(cases), 6)
        self.assertEqual(cases[0]['value'], 0)
        self.assertEqual(cases[1]['value'], -1)
        self.assertEqual(cases[0]['payload']['quantity'], 0)

    def test_boundary_runner_contacts_only_the_local_test_server(self):
        async def scenario(root: str):
            payload_path = Path(root) / 'payload.json'
            payload_path.write_text('{"quantity": 1}', encoding='utf-8')

            async def handler(request):
                payload = await request.json()
                return web.json_response({'accepted_type': type(payload['quantity']).__name__})

            app = web.Application()
            app.router.add_post('/test', handler)
            runner = web.AppRunner(app)
            await runner.setup()
            site = web.TCPSite(runner, '127.0.0.1', 0)
            await site.start()
            port = site._server.sockets[0].getsockname()[1]
            try:
                return await LocalApiInvariantTester(lab_config(root)).run(
                    f'http://127.0.0.1:{port}/test',
                    'payload.json',
                    'quantity',
                    'integer',
                )
            finally:
                await runner.cleanup()

        with tempfile.TemporaryDirectory() as root:
            result = asyncio.run(scenario(root))

        self.assertEqual(result['case_count'], 6)
        self.assertTrue(all('status_code' in item for item in result['results']))
        self.assertTrue(all(not item['redirect_followed'] for item in result['results']))


class TestProtocolAndInstrumentation(unittest.TestCase):
    def test_protocol_analysis_is_offline_and_read_only(self):
        with tempfile.TemporaryDirectory() as root:
            corpus = Path(root) / 'capture.bin'
            corpus.write_bytes(b'GAME\x00PROTO\x01\x02GAME')
            result = ProtocolCorpusAnalyzer(lab_config(root)).analyze('capture.bin')

        self.assertEqual(result['mode'], 'offline-observation-only')
        self.assertFalse(result['modified_or_forwarded'])
        self.assertIn('GAME', result['ascii_strings'])

    def test_trace_script_contains_no_memory_or_return_patching(self):
        with tempfile.TemporaryDirectory() as root:
            output = ObservationScriptBuilder(lab_config(root)).build('OwnedParserFunction')
            script = Path(output).read_text(encoding='utf-8')

        self.assertIn('Interceptor.attach', script)
        self.assertNotIn('retval.replace', script)
        self.assertNotIn('Interceptor.replace', script)
        self.assertNotIn('Memory.write', script)


class TestLocalCrashFuzzer(unittest.TestCase):
    def test_mutations_are_deterministic_and_crash_codes_are_classified(self):
        self.assertEqual(
            LocalCrashFuzzer.mutate(b'abcdef', 3),
            LocalCrashFuzzer.mutate(b'abcdef', 3),
        )
        self.assertTrue(LocalCrashFuzzer.is_crash_return_code(0xC0000005))
        self.assertFalse(LocalCrashFuzzer.is_crash_return_code(0))

    def test_fuzzer_retains_crash_input_without_building_an_exploit(self):
        with tempfile.TemporaryDirectory() as root:
            binary = Path(root) / 'owned_target.exe'
            seed = Path(root) / 'seed.bin'
            binary.write_bytes(b'MZ-owned-test-placeholder')
            seed.write_bytes(b'valid-seed')
            completed = subprocess.CompletedProcess(
                args=[], returncode=0xC0000005, stdout=b'', stderr=b'crash'
            )

            with patch('units.local_crash_fuzzer.subprocess.run', return_value=completed):
                result = LocalCrashFuzzer(lab_config(root)).run(
                    'owned_target.exe', 'seed.bin', 1
                )

            self.assertTrue(Path(result['results'][0]['saved_input']).exists())

        self.assertEqual(result['crashes'], 1)
        self.assertFalse(result['exploit_generated'])
        self.assertIn('no shellcode', result['note'])


if __name__ == '__main__':
    unittest.main()
