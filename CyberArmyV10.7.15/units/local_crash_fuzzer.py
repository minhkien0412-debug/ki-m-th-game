"""Bounded mutation fuzzing for self-hosted user-mode binaries only."""

import hashlib
import os
import random
import shutil
import subprocess
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List

from .local_lab_policy import LocalLabError, LocalLabPolicy
from .sanitizer import sanitizer_signature


class LocalCrashFuzzer:
    """Mutate a local seed and retain crash inputs without exploit construction."""

    WINDOWS_CRASH_CODES = {
        0xC0000005,  # access violation
        0xC000001D,  # illegal instruction
        0xC0000094,  # integer divide by zero
        0xC00000FD,  # stack overflow
        0xC0000409,  # stack buffer overrun / fast fail
    }

    def __init__(self, config: Dict[str, Any]):
        self.policy = LocalLabPolicy(config)
        output_dir = self.policy.config.get('fuzz_output_dir', 'state/lab_fuzz')
        self.output_dir = self.policy.require_workspace_file(output_dir, must_exist=False)

    @staticmethod
    def mutate(data: bytes, case_index: int) -> bytes:
        """Apply one deterministic bounded mutation."""
        rng = random.Random(case_index)
        mutable = bytearray(data or b'\x00')
        strategy = case_index % 4

        if strategy == 0:
            offset = rng.randrange(len(mutable))
            mutable[offset] ^= 1 << rng.randrange(8)
        elif strategy == 1:
            offset = rng.randrange(len(mutable))
            mutable[offset] = rng.randrange(256)
        elif strategy == 2:
            new_length = rng.randrange(len(mutable) + 1)
            del mutable[new_length:]
        else:
            extension = bytes(rng.randrange(256) for _ in range(min(16, len(mutable) + 1)))
            mutable.extend(extension)

        return bytes(mutable)

    @classmethod
    def is_crash_return_code(cls, return_code: int) -> bool:
        unsigned = return_code & 0xFFFFFFFF
        return return_code < 0 or unsigned in cls.WINDOWS_CRASH_CODES

    @staticmethod
    def crash_signature(return_code, stderr_tail: str = '') -> str:
        """A stable fingerprint used to group duplicate crashes.

        When the target is a sanitizer-instrumented build, the ASan/UBSan bug
        class and faulting frame give the most precise grouping. Otherwise fall
        back to the (normalized) exit code plus the first stderr line, so many
        mutated inputs that trip the same bug collapse to one unique crash.
        """
        san = sanitizer_signature(stderr_tail or '')
        if san:
            return f'san|{san}'
        if return_code is None:
            code = 'timeout'
        else:
            code = format(return_code & 0xFFFFFFFF, '#010x')
        line = ''
        for candidate in (stderr_tail or '').splitlines():
            candidate = candidate.strip()
            if candidate:
                line = candidate
                break
        digest = hashlib.sha1(line.encode('utf-8', 'replace')).hexdigest()[:10]
        return f'{code}|{digest}'

    @staticmethod
    def minimize(data: bytes, still_crashes, max_rounds: int = 200) -> bytes:
        """Delta-debug a crashing input to a smaller one that still crashes.

        ``still_crashes`` is a callable ``bytes -> bool``. This only *removes*
        bytes; it never synthesizes new content, builds a payload, or constructs
        an exploit — it just shrinks the reproducer for triage.
        """
        if not data or not still_crashes(data):
            return data
        current = bytes(data)
        chunk = max(1, len(current) // 2)
        rounds = 0
        while chunk >= 1 and rounds < max_rounds:
            index = 0
            removed_any = False
            while index < len(current) and rounds < max_rounds:
                candidate = current[:index] + current[index + chunk:]
                rounds += 1
                if candidate and still_crashes(candidate):
                    current = candidate
                    removed_any = True
                else:
                    index += chunk
            if not removed_any:
                chunk //= 2
        return current

    def run(self, executable: str, seed_path: str, cases: int) -> Dict[str, Any]:
        self.policy.require_valid()
        binary = self.policy.require_workspace_file(executable)
        seed = self.policy.require_workspace_file(seed_path)

        allowed_extensions = set(
            self.policy.config.get('allowed_executable_extensions', ['.exe'])
        )
        if binary.suffix.lower() not in {ext.lower() for ext in allowed_extensions}:
            raise LocalLabError('Executable extension is not allowlisted for the local lab')

        max_cases = int(self.policy.config.get('max_fuzz_cases', 50))
        if cases < 1 or cases > max_cases:
            raise LocalLabError(f'cases must be between 1 and {max_cases}')

        max_bytes = int(self.policy.config.get('max_input_bytes', 1048576))
        if seed.stat().st_size > max_bytes:
            raise LocalLabError('Seed exceeds max_input_bytes')
        seed_data = seed.read_bytes()

        self.output_dir.mkdir(parents=True, exist_ok=True)
        crash_dir = self.output_dir / 'crashes'
        crash_dir.mkdir(parents=True, exist_ok=True)
        timeout = int(self.policy.config.get('process_timeout_seconds', 5))
        results: List[Dict[str, Any]] = []

        safe_env = {
            key: value for key, value in os.environ.items()
            if key.upper() in {'PATH', 'SYSTEMROOT', 'WINDIR', 'TEMP', 'TMP'}
        }

        minimize_enabled = bool(self.policy.config.get('minimize_crashes', True))
        unique_crashes: Dict[str, Dict[str, Any]] = {}

        with tempfile.TemporaryDirectory(dir=self.output_dir) as temp_dir:
            temp_root = Path(temp_dir)

            def still_crashes(candidate: bytes) -> bool:
                probe = temp_root / 'minimize_probe.bin'
                probe.write_bytes(candidate)
                try:
                    completed = subprocess.run(
                        [str(binary), str(probe)],
                        cwd=str(binary.parent),
                        capture_output=True,
                        timeout=timeout,
                        check=False,
                        shell=False,
                        env=safe_env,
                    )
                except subprocess.TimeoutExpired:
                    return False
                return self.is_crash_return_code(completed.returncode)

            for index in range(cases):
                mutated = self.mutate(seed_data, index)
                input_path = temp_root / f'case_{index:05d}.bin'
                input_path.write_bytes(mutated)
                started_at = datetime.now(timezone.utc).isoformat()

                try:
                    completed = subprocess.run(
                        [str(binary), str(input_path)],
                        cwd=str(binary.parent),
                        capture_output=True,
                        timeout=timeout,
                        check=False,
                        shell=False,
                        env=safe_env,
                    )
                    crashed = self.is_crash_return_code(completed.returncode)
                    result = {
                        'case': index,
                        'sha256': hashlib.sha256(mutated).hexdigest(),
                        'return_code': completed.returncode,
                        'crashed': crashed,
                        'timed_out': False,
                        'started_at': started_at,
                        'stdout_tail': completed.stdout[-4096:].decode(errors='replace'),
                        'stderr_tail': completed.stderr[-4096:].decode(errors='replace'),
                    }
                except subprocess.TimeoutExpired:
                    crashed = False
                    result = {
                        'case': index,
                        'sha256': hashlib.sha256(mutated).hexdigest(),
                        'return_code': None,
                        'crashed': False,
                        'timed_out': True,
                        'started_at': started_at,
                    }

                if crashed:
                    saved = crash_dir / f'crash_{index:05d}_{result["sha256"][:12]}.bin'
                    shutil.copy2(input_path, saved)
                    result['saved_input'] = str(saved)

                    signature = self.crash_signature(
                        result['return_code'], result.get('stderr_tail', '')
                    )
                    result['crash_signature'] = signature
                    is_new = signature not in unique_crashes
                    result['duplicate'] = not is_new
                    if is_new:
                        record = {'signature': signature, 'first_case': index,
                                  'saved_input': str(saved), 'occurrences': 1}
                        # Shrink the first reproducer of each distinct crash.
                        if minimize_enabled:
                            minimized = self.minimize(mutated, still_crashes)
                            if len(minimized) < len(mutated):
                                min_path = (crash_dir /
                                            f'crash_{index:05d}_{signature.split("|")[0]}_min.bin')
                                min_path.write_bytes(minimized)
                                result['minimized_input'] = str(min_path)
                                record['minimized_input'] = str(min_path)
                            result['minimized_bytes'] = len(minimized)
                            record['minimized_bytes'] = len(minimized)
                        unique_crashes[signature] = record
                    else:
                        unique_crashes[signature]['occurrences'] += 1
                results.append(result)

        return {
            'executable': str(binary),
            'seed': str(seed),
            'cases': cases,
            'crashes': sum(1 for result in results if result['crashed']),
            'unique_crashes': len(unique_crashes),
            'unique_crash_details': list(unique_crashes.values()),
            'timeouts': sum(1 for result in results if result['timed_out']),
            'results': results,
            'authorization_reference': self.policy.authorization_reference,
            'exploit_generated': False,
            'note': 'Crash triage and minimization only; no shellcode, ROP chain, '
                    'or privilege escalation.',
        }
