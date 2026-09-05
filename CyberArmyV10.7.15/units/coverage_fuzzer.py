"""Coverage-guided (greybox) fuzzing for a Python harness in the isolated lab.

Unlike the black-box native fuzzer (which only sees a process exit code), this
evolves a corpus using real edge-coverage feedback collected with sys.settrace:
an input that reaches a new edge in the code under test is kept and mutated
further, so the fuzzer drives itself deeper instead of guessing blindly. It is
the coverage-guided counterpart for targets you can drive in-process (a Python
harness, or a native library wrapped by one such as via ctypes/cffi).

Scope, honestly stated: this needs a target it can execute in-process to read
coverage. It does not instrument an opaque prebuilt binary — for that, run a
sanitizer/coverage-instrumented build under the native fuzzer, whose crash
triage now understands ASan/UBSan reports. Nothing here builds an exploit; it
retains and shrinks crashing inputs for triage only.
"""

import hashlib
import importlib
import sys
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

from .local_crash_fuzzer import LocalCrashFuzzer
from .local_lab_policy import LocalLabError, LocalLabPolicy


class LocalCoverageFuzzer:
    """Greybox fuzz a Python-callable target with edge-coverage feedback."""

    def __init__(self, config: Dict[str, Any]):
        self.policy = LocalLabPolicy(config)
        output_dir = self.policy.config.get('fuzz_output_dir', 'state/lab_fuzz')
        self.output_dir = self.policy.require_workspace_file(output_dir, must_exist=False)

    # --------------------------------------------------------------- tracing
    @staticmethod
    def _run_traced(target: Callable[[bytes], Any], data: bytes,
                    trace_paths: List[str]):
        """Run ``target(data)`` capturing edge coverage in ``trace_paths``.

        Returns ``(exception_or_None, set_of_edges)``.
        """
        edges = set()
        state = {'prev': None}
        prefixes = tuple(trace_paths)

        def local_tracer(frame, event, arg):
            if event == 'line':
                cur = (frame.f_code.co_filename, frame.f_lineno)
                edges.add((state['prev'], cur))
                state['prev'] = cur
            return local_tracer

        def global_tracer(frame, event, arg):
            filename = frame.f_code.co_filename
            if prefixes and not filename.startswith(prefixes):
                return None
            return local_tracer

        raised = None
        previous = sys.gettrace()
        sys.settrace(global_tracer)
        try:
            target(data)
        except (KeyboardInterrupt, SystemExit):
            sys.settrace(previous)
            raise
        except BaseException as exc:  # noqa: BLE001 - a crash is the signal
            raised = exc
        finally:
            sys.settrace(previous)
        return raised, edges

    @staticmethod
    def _crash_signature(exc: BaseException, trace_paths: List[str]) -> str:
        """Fingerprint a crash by exception type and deepest in-scope frame."""
        prefixes = tuple(trace_paths)
        location = ''
        tb = exc.__traceback__
        while tb is not None:
            filename = tb.tb_frame.f_code.co_filename
            if not prefixes or filename.startswith(prefixes):
                location = f'{Path(filename).name}:{tb.tb_lineno}'
            tb = tb.tb_next
        return f'{type(exc).__name__}|{location}'

    # ------------------------------------------------------------------ fuzz
    def fuzz(self, target: Callable[[bytes], Any], seeds: List[bytes],
             iterations: int, trace_paths: Optional[List[str]] = None) -> Dict[str, Any]:
        self.policy.require_valid()
        if not callable(target):
            raise LocalLabError('Coverage fuzz target must be callable')

        max_cases = int(self.policy.config.get('max_fuzz_cases', 50))
        if iterations < 1 or iterations > max_cases:
            raise LocalLabError(f'iterations must be between 1 and {max_cases}')
        max_bytes = int(self.policy.config.get('max_input_bytes', 1048576))

        if trace_paths is None:
            trace_paths = [str(self.policy.workspace_root)]

        corpus: List[bytes] = [bytes(s)[:max_bytes] for s in seeds if s is not None]
        if not corpus:
            corpus = [b'\x00']

        # Baseline coverage from the seed corpus.
        seen_edges = set()
        for seed in corpus:
            _, edges = self._run_traced(target, seed, trace_paths)
            seen_edges |= edges

        self.output_dir.mkdir(parents=True, exist_ok=True)
        crash_dir = self.output_dir / 'coverage_crashes'
        crash_dir.mkdir(parents=True, exist_ok=True)

        unique_crashes: Dict[str, Dict[str, Any]] = {}
        total_crashes = 0
        new_coverage_hits = 0

        for index in range(iterations):
            base = corpus[index % len(corpus)]
            mutated = LocalCrashFuzzer.mutate(base, index)[:max_bytes]
            raised, edges = self._run_traced(target, mutated, trace_paths)

            if edges - seen_edges:
                seen_edges |= edges
                new_coverage_hits += 1
                if len(corpus) < max_cases * 4:
                    corpus.append(mutated)

            if raised is not None:
                total_crashes += 1
                signature = self._crash_signature(raised, trace_paths)
                if signature not in unique_crashes:
                    def still_crashes(candidate: bytes) -> bool:
                        exc, _ = self._run_traced(target, candidate, trace_paths)
                        return (exc is not None
                                and type(exc).__name__ == type(raised).__name__)

                    minimized = LocalCrashFuzzer.minimize(mutated, still_crashes)
                    digest = hashlib.sha1(mutated).hexdigest()[:12]
                    saved = crash_dir / f'covcrash_{index:05d}_{digest}.bin'
                    saved.write_bytes(mutated)
                    record = {
                        'signature': signature,
                        'exception': type(raised).__name__,
                        'first_case': index,
                        'saved_input': str(saved),
                        'input_bytes': len(mutated),
                        'occurrences': 1,
                    }
                    if len(minimized) < len(mutated):
                        min_path = crash_dir / f'covcrash_{index:05d}_{digest}_min.bin'
                        min_path.write_bytes(minimized)
                        record['minimized_input'] = str(min_path)
                        record['minimized_bytes'] = len(minimized)
                    unique_crashes[signature] = record
                else:
                    unique_crashes[signature]['occurrences'] += 1

        return {
            'mode': 'coverage-guided-python-harness',
            'iterations': iterations,
            'edges_discovered': len(seen_edges),
            'new_coverage_inputs': new_coverage_hits,
            'corpus_size': len(corpus),
            'crashes': total_crashes,
            'unique_crashes': len(unique_crashes),
            'unique_crash_details': list(unique_crashes.values()),
            'authorization_reference': self.policy.authorization_reference,
            'exploit_generated': False,
            'note': 'Coverage-guided triage only; retains and minimizes crashing '
                    'inputs, builds no shellcode/ROP/privilege escalation.',
        }

    # ------------------------------------------------------------------- CLI
    def fuzz_module_target(self, spec: str, seed_path: Optional[str],
                           iterations: int) -> Dict[str, Any]:
        """Load ``module:function`` from the workspace and fuzz it.

        The harness must be a callable taking a single ``bytes`` argument. Only
        modules importable from the configured workspace_root are loaded.
        """
        self.policy.require_valid()
        if ':' not in spec:
            raise LocalLabError('Target must be given as "module:function"')
        module_name, func_name = spec.split(':', 1)

        workspace = str(self.policy.workspace_root)
        seeds: List[bytes] = []
        if seed_path:
            seed_file = self.policy.require_workspace_file(seed_path)
            seeds.append(seed_file.read_bytes())

        added = workspace not in sys.path
        if added:
            sys.path.insert(0, workspace)
        try:
            module = importlib.import_module(module_name)
            target = getattr(module, func_name, None)
        finally:
            if added and workspace in sys.path:
                sys.path.remove(workspace)

        if not callable(target):
            raise LocalLabError(f'{spec} is not a callable harness')

        module_file = getattr(module, '__file__', '') or ''
        trace_paths = [workspace]
        if module_file and not module_file.startswith(workspace):
            trace_paths.append(str(Path(module_file).parent))

        result = self.fuzz(target, seeds, iterations, trace_paths=trace_paths)
        result['target'] = spec
        return result
