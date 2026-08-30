"""Crash/log ingestion, symbolication hooks, and corpus manifests."""

import csv
import hashlib
import json
import re
import shutil
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List

from .console_lab_policy import ConsoleLabPolicy
from .local_lab_policy import LocalLabError


def _hash_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open('rb') as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b''):
            digest.update(chunk)
    return digest.hexdigest()


class ConsoleArtifactManager:
    """Import exported artifacts and invoke a configured offline symbolicator."""

    def __init__(self, config: Dict[str, Any]):
        self.policy = ConsoleLabPolicy(config)
        self.output_dir = self.policy.require_workspace_path(
            self.policy.config.get('artifact_output_dir', 'state/console_artifacts'),
            must_exist=False,
        )

    def import_crash(self, source_path: str) -> Dict[str, Any]:
        self.policy.require_capability('import_crash')
        source = self.policy.require_workspace_path(source_path)
        max_bytes = int(self.policy.config.get('max_crash_bytes', 268435456))
        if source.stat().st_size > max_bytes:
            raise LocalLabError('Crash artifact exceeds max_crash_bytes')
        allowed = {
            str(item).lower() for item in self.policy.config.get(
                'allowed_crash_extensions', ['.dmp', '.core', '.log', '.txt', '.json']
            )
        }
        if source.suffix.lower() not in allowed:
            raise LocalLabError('Crash artifact extension is not allowlisted')

        digest = _hash_file(source)
        signature = self._crash_signature(source, digest)
        imported_at = datetime.now(timezone.utc).isoformat()
        destination_dir = self.output_dir / 'imports' / digest[:16]
        destination_dir.mkdir(parents=True, exist_ok=True)
        destination = destination_dir / source.name
        shutil.copy2(source, destination)
        manifest = {
            'platform': self.policy.platform,
            'kit_id': self.policy.kit_id,
            'source_name': source.name,
            'stored_path': str(destination),
            'bytes': destination.stat().st_size,
            'sha256': digest,
            'crash_signature': signature,
            'imported_at': imported_at,
            'authorization_reference': self.policy.authorization_reference,
        }
        manifest_path = destination_dir / 'manifest.json'
        manifest_path.write_text(json.dumps(manifest, indent=2), encoding='utf-8')
        manifest['manifest_path'] = str(manifest_path)
        manifest.update(self._record_occurrence(manifest))
        manifest_path.write_text(json.dumps(manifest, indent=2), encoding='utf-8')
        return manifest

    @staticmethod
    def _crash_signature(source: Path, fallback_hash: str) -> str:
        """Normalize likely stack lines so repeat crashes group together."""
        sample = source.read_bytes()[:1024 * 1024]
        text = sample.decode('utf-8', errors='ignore')
        candidates = []
        for raw_line in text.splitlines():
            line = raw_line.strip()
            if not line:
                continue
            if re.search(r'(?i)(exception|fatal|crash|stack|frame|\bat\b|^#\d+)', line):
                line = re.sub(r'0x[0-9a-fA-F]+', '0xADDR', line)
                line = re.sub(r'(?<=:)[0-9]+\b', 'LINE', line)
                line = re.sub(r'\s+', ' ', line)
                candidates.append(line[:512])
            if len(candidates) >= 20:
                break
        material = '\n'.join(candidates).encode('utf-8')
        return hashlib.sha256(material).hexdigest() if material else fallback_hash

    def _record_occurrence(self, manifest: Dict[str, Any]) -> Dict[str, Any]:
        self.output_dir.mkdir(parents=True, exist_ok=True)
        index_path = self.output_dir / 'crash-index.json'
        try:
            index = json.loads(index_path.read_text(encoding='utf-8'))
        except (FileNotFoundError, json.JSONDecodeError, OSError):
            index = {'signatures': {}}
        signatures = index.setdefault('signatures', {})
        occurrences = signatures.setdefault(manifest['crash_signature'], [])
        duplicate_of = occurrences[0]['stored_path'] if occurrences else None
        occurrences.append({
            'sha256': manifest['sha256'],
            'stored_path': manifest['stored_path'],
            'imported_at': manifest['imported_at'],
        })
        index_path.write_text(json.dumps(index, indent=2), encoding='utf-8')
        return {
            'duplicate': duplicate_of is not None,
            'duplicate_of': duplicate_of,
            'signature_occurrences': len(occurrences),
            'crash_index_path': str(index_path),
        }

    def symbolicate(self, crash_path: str, symbols_path: str) -> Dict[str, Any]:
        self.policy.require_capability('symbolicate')
        crash = self.policy.require_workspace_path(crash_path)
        symbols = self.policy.require_workspace_path(symbols_path)
        output_dir = self.output_dir / 'symbolicated' / _hash_file(crash)[:16]
        output_dir.mkdir(parents=True, exist_ok=True)
        template = self.policy.validate_command_template(
            self.policy.config.get('symbolicate_command', []), 'symbolicate_command'
        )
        replacements = {
            '{crash}': str(crash),
            '{symbols}': str(symbols),
            '{output_dir}': str(output_dir),
            '{kit_id}': self.policy.kit_id,
        }
        command: List[str] = []
        for item in template:
            for token, value in replacements.items():
                item = item.replace(token, value)
            command.append(item)
        safe_env = self.policy.safe_environment()
        try:
            completed = subprocess.run(
                command,
                cwd=str(output_dir),
                capture_output=True,
                timeout=int(self.policy.config.get('process_timeout_seconds', 30)),
                check=False,
                shell=False,
                env=safe_env,
            )
        except subprocess.TimeoutExpired as exc:
            raise LocalLabError('Symbolication command timed out') from exc
        result = {
            'crash': str(crash),
            'crash_sha256': _hash_file(crash),
            'symbols': str(symbols),
            'symbols_sha256': _hash_file(symbols),
            'output_dir': str(output_dir),
            'return_code': completed.returncode,
            'stdout_tail': completed.stdout[-16384:].decode(errors='replace'),
            'stderr_tail': completed.stderr[-16384:].decode(errors='replace'),
            'shell': False,
            'authorization_reference': self.policy.authorization_reference,
        }
        (output_dir / 'symbolication.json').write_text(
            json.dumps(result, indent=2), encoding='utf-8'
        )
        return result


class ConsoleCorpusIndexer:
    """Build a deterministic manifest for an owned game-input corpus."""

    def __init__(self, config: Dict[str, Any]):
        self.policy = ConsoleLabPolicy(config)

    def index(self, corpus_directory: str) -> Dict[str, Any]:
        self.policy.require_capability('corpus')
        root = self.policy.require_workspace_path(
            corpus_directory, directory=True
        )
        max_files = int(self.policy.config.get('max_corpus_files', 1000))
        output_path = root / 'corpus-manifest.json'
        files = sorted(
            path for path in root.rglob('*')
            if path.is_file() and path != output_path
        )
        if len(files) > max_files:
            raise LocalLabError('Corpus exceeds max_corpus_files')
        entries = [
            {
                'path': path.relative_to(root).as_posix(),
                'bytes': path.stat().st_size,
                'sha256': _hash_file(path),
            }
            for path in files
        ]
        manifest = {
            'mode': 'offline-owned-corpus',
            'root': str(root),
            'file_count': len(entries),
            'total_bytes': sum(item['bytes'] for item in entries),
            'files': entries,
            'authorization_reference': self.policy.authorization_reference,
        }
        output_path.write_text(json.dumps(manifest, indent=2), encoding='utf-8')
        manifest['manifest_path'] = str(output_path)
        return manifest


class ConsoleTelemetryAnalyzer:
    """Summarize an exported CSV without contacting a console or service."""

    METRICS = ('frame_time_ms', 'memory_mb', 'cpu_percent', 'gpu_percent', 'network_kbps')

    def __init__(self, config: Dict[str, Any]):
        self.policy = ConsoleLabPolicy(config)

    @staticmethod
    def _summary(values: List[float]) -> Dict[str, float]:
        ordered = sorted(values)
        p95_index = max(0, min(len(ordered) - 1, int(len(ordered) * 0.95 + 0.999) - 1))
        return {
            'min': round(ordered[0], 4),
            'average': round(sum(ordered) / len(ordered), 4),
            'p95': round(ordered[p95_index], 4),
            'max': round(ordered[-1], 4),
        }

    def analyze(self, csv_path: str) -> Dict[str, Any]:
        self.policy.require_capability('telemetry')
        source = self.policy.require_workspace_path(csv_path)
        if source.suffix.lower() != '.csv':
            raise LocalLabError('Telemetry input must be a CSV file')
        max_rows = int(self.policy.config.get('max_telemetry_rows', 100000))
        collected = {name: [] for name in self.METRICS}
        invalid_rows = 0
        with source.open('r', encoding='utf-8-sig', newline='') as handle:
            reader = csv.DictReader(handle)
            if not reader.fieldnames or 'frame_time_ms' not in reader.fieldnames:
                raise LocalLabError('Telemetry CSV requires frame_time_ms')
            for row_index, row in enumerate(reader, start=1):
                if row_index > max_rows:
                    raise LocalLabError('Telemetry CSV exceeds max_telemetry_rows')
                row_valid = True
                parsed: Dict[str, float] = {}
                for name in self.METRICS:
                    raw = row.get(name, '')
                    if raw in (None, ''):
                        continue
                    try:
                        value = float(raw)
                    except (TypeError, ValueError):
                        row_valid = False
                        break
                    if value < 0 or value != value or value == float('inf'):
                        row_valid = False
                        break
                    parsed[name] = value
                if not row_valid or 'frame_time_ms' not in parsed:
                    invalid_rows += 1
                    continue
                for name, value in parsed.items():
                    collected[name].append(value)

        if not collected['frame_time_ms']:
            raise LocalLabError('Telemetry CSV has no valid frame-time rows')
        frame_budget = float(self.policy.config.get('frame_budget_ms', 16.667))
        frames = collected['frame_time_ms']
        return {
            'mode': 'offline-telemetry-analysis',
            'source': str(source),
            'source_sha256': _hash_file(source),
            'valid_rows': len(frames),
            'invalid_rows': invalid_rows,
            'frame_budget_ms': frame_budget,
            'frames_over_budget': sum(value > frame_budget for value in frames),
            'metrics': {
                name: self._summary(values)
                for name, values in collected.items() if values
            },
            'authorization_reference': self.policy.authorization_reference,
        }
