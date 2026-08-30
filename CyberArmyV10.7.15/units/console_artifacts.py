"""Crash/log ingestion, symbolication hooks, and corpus manifests."""

import hashlib
import json
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
        self.policy.require_valid()
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
            'imported_at': imported_at,
            'authorization_reference': self.policy.authorization_reference,
        }
        manifest_path = destination_dir / 'manifest.json'
        manifest_path.write_text(json.dumps(manifest, indent=2), encoding='utf-8')
        manifest['manifest_path'] = str(manifest_path)
        return manifest

    def symbolicate(self, crash_path: str, symbols_path: str) -> Dict[str, Any]:
        self.policy.require_valid()
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
        self.policy.require_valid()
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
