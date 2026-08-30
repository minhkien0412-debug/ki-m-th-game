"""Boundary-value and concurrency checks for self-hosted loopback APIs."""

import asyncio
import hashlib
import json
import time
from copy import deepcopy
from typing import Any, Dict, List

import aiohttp

from .local_lab_policy import LocalLabError, LocalLabPolicy


class BoundaryCaseGenerator:
    """Generate deterministic edge values without targeting any real service."""

    CASES = {
        'integer': [0, -1, 1, 2, 2147483647, -2147483648],
        'number': [0, -1, 0.5, -0.5, 1, 1.0000001],
        'string': ['', ' ', '0', '-1', 'null', 'A' * 256],
        'boolean': [False, True, 0, 1, 'false', 'true'],
    }

    @classmethod
    def generate(cls, payload: Dict[str, Any], field: str, value_type: str) -> List[Dict[str, Any]]:
        if value_type not in cls.CASES:
            raise LocalLabError(f'Unsupported boundary type: {value_type}')
        if field not in payload:
            raise LocalLabError(f'Field is missing from baseline payload: {field}')

        cases = []
        for index, value in enumerate(cls.CASES[value_type]):
            mutated = deepcopy(payload)
            mutated[field] = value
            cases.append({
                'case_id': f'{field}-{value_type}-{index:02d}',
                'field': field,
                'value': value,
                'payload': mutated,
            })
        return cases


class LocalApiInvariantTester:
    """Send a small bounded case set only to an authorized loopback service."""

    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.policy = LocalLabPolicy(config)

    async def run(self, url: str, payload_path: str, field: str,
                  value_type: str) -> Dict[str, Any]:
        self.policy.require_loopback_url(url)
        payload_file = self.policy.require_workspace_file(payload_path)
        with open(payload_file, 'r', encoding='utf-8') as handle:
            payload = json.load(handle)
        if not isinstance(payload, dict):
            raise LocalLabError('Baseline payload must be a JSON object')

        cases = BoundaryCaseGenerator.generate(payload, field, value_type)
        max_cases = int(self.policy.config.get('max_api_cases', 16))
        if len(cases) > max_cases:
            raise LocalLabError('Generated case count exceeds max_api_cases')

        concurrency = int(self.policy.config.get('max_concurrency', 2))
        semaphore = asyncio.Semaphore(concurrency)
        timeout = aiohttp.ClientTimeout(
            total=int(self.policy.config.get('process_timeout_seconds', 5))
        )

        async def execute(session: aiohttp.ClientSession, case: Dict[str, Any]):
            async with semaphore:
                started = time.monotonic()
                try:
                    async with session.post(
                        url,
                        json=case['payload'],
                        headers={'X-CyberArmy-Lab': 'boundary-invariant-test'},
                        allow_redirects=False,
                    ) as response:
                        max_response = int(
                            self.policy.config.get('max_response_bytes', 262144)
                        )
                        body = await response.content.read(max_response + 1)
                        truncated = len(body) > max_response
                        body = body[:max_response]
                        return {
                            'case_id': case['case_id'],
                            'field': field,
                            'value': case['value'],
                            'status_code': response.status,
                            'body_length': len(body),
                            'body_sha256': hashlib.sha256(body).hexdigest(),
                            'body_truncated': truncated,
                            'elapsed_ms': round((time.monotonic() - started) * 1000, 2),
                            'redirect_followed': False,
                        }
                except (aiohttp.ClientError, asyncio.TimeoutError) as exc:
                    return {
                        'case_id': case['case_id'],
                        'field': field,
                        'value': case['value'],
                        'error': type(exc).__name__,
                        'elapsed_ms': round((time.monotonic() - started) * 1000, 2),
                    }

        connector = aiohttp.TCPConnector(limit=concurrency, use_dns_cache=False)
        async with aiohttp.ClientSession(
            connector=connector,
            timeout=timeout,
            trust_env=False,
        ) as session:
            results = await asyncio.gather(*(execute(session, case) for case in cases))

        return {
            'target': url,
            'baseline_file': str(payload_file),
            'field': field,
            'value_type': value_type,
            'case_count': len(results),
            'authorization_reference': self.policy.authorization_reference,
            'results': results,
            'note': 'Local invariant observations only; no exploit conclusion is automatic.',
        }
