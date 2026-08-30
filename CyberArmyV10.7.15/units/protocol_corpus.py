"""Offline-only analysis for user-owned protocol capture corpora."""

import hashlib
import math
import re
from collections import Counter
from typing import Any, Dict, List

from .local_lab_policy import LocalLabError, LocalLabPolicy


class ProtocolCorpusAnalyzer:
    """Describe bytes from a local file without sniffing or forwarding traffic."""

    def __init__(self, config: Dict[str, Any]):
        self.policy = LocalLabPolicy(config)

    @staticmethod
    def _entropy(data: bytes) -> float:
        if not data:
            return 0.0
        counts = Counter(data)
        length = len(data)
        return -sum(
            (count / length) * math.log2(count / length)
            for count in counts.values()
        )

    @staticmethod
    def _ascii_strings(data: bytes, minimum: int = 4, limit: int = 50) -> List[str]:
        pattern = rb'[\x20-\x7e]{' + str(minimum).encode('ascii') + rb',}'
        strings = []
        for match in re.finditer(pattern, data):
            strings.append(match.group(0).decode('ascii', errors='replace')[:200])
            if len(strings) >= limit:
                break
        return strings

    def analyze(self, path: str) -> Dict[str, Any]:
        corpus_path = self.policy.require_workspace_file(path)
        max_bytes = int(self.policy.config.get('max_input_bytes', 1048576))
        size = corpus_path.stat().st_size
        if size > max_bytes:
            raise LocalLabError('Protocol corpus exceeds max_input_bytes')

        data = corpus_path.read_bytes()
        frequencies = Counter(data).most_common(16)
        return {
            'file': str(corpus_path),
            'size': len(data),
            'sha256': hashlib.sha256(data).hexdigest(),
            'entropy_bits_per_byte': round(self._entropy(data), 4),
            'most_common_bytes': [
                {'byte': f'0x{value:02x}', 'count': count}
                for value, count in frequencies
            ],
            'ascii_strings': self._ascii_strings(data),
            'first_64_bytes_hex': data[:64].hex(),
            'mode': 'offline-observation-only',
            'modified_or_forwarded': False,
            'authorization_reference': self.policy.authorization_reference,
        }
