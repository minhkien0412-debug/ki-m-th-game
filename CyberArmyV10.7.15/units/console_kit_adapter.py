"""Vendor-neutral command adapter for an official PlayStation SDK installation."""

import hashlib
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Mapping

from .console_lab_policy import ConsoleLabPolicy
from .local_lab_policy import LocalLabError


class ConsoleKitAdapter:
    """Plan or execute an explicitly configured official SDK command."""

    def __init__(self, config: Dict[str, Any]):
        self.policy = ConsoleLabPolicy(config)

    @staticmethod
    def _sha256(path: Path) -> str:
        digest = hashlib.sha256()
        with path.open('rb') as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b''):
                digest.update(chunk)
        return digest.hexdigest()

    def _render(self, template_name: str, values: Mapping[str, str]) -> List[str]:
        template = self.policy.validate_command_template(
            self.policy.config.get(template_name, []), template_name
        )
        return [
            item.replace('{artifact}', values.get('artifact', ''))
                .replace('{kit_id}', self.policy.kit_id)
                .replace('{crash}', values.get('crash', ''))
                .replace('{symbols}', values.get('symbols', ''))
                .replace('{output_dir}', values.get('output_dir', ''))
            for item in template
        ]

    def plan_artifact(self, artifact_path: str) -> Dict[str, Any]:
        self.policy.require_valid()
        artifact = self.policy.require_artifact(artifact_path)
        command = self._render('run_command', {'artifact': str(artifact)})
        return {
            'mode': 'dry-run',
            'platform': self.policy.platform,
            'kit_id': self.policy.kit_id,
            'artifact': str(artifact),
            'artifact_bytes': artifact.stat().st_size,
            'artifact_sha256': self._sha256(artifact),
            'argv': command,
            'shell': False,
            'authorization_reference': self.policy.authorization_reference,
        }

    def run_artifact(self, artifact_path: str) -> Dict[str, Any]:
        self.policy.require_valid(require_execution=True)
        plan = self.plan_artifact(artifact_path)
        safe_env = self.policy.safe_environment()
        timeout = int(self.policy.config.get('process_timeout_seconds', 30))
        started_at = datetime.now(timezone.utc).isoformat()
        try:
            completed = subprocess.run(
                plan['argv'],
                cwd=str(Path(plan['artifact']).parent),
                capture_output=True,
                timeout=timeout,
                check=False,
                shell=False,
                env=safe_env,
            )
        except subprocess.TimeoutExpired as exc:
            raise LocalLabError('Official SDK command timed out') from exc
        return {
            **plan,
            'mode': 'executed-on-authorized-dev-test-kit',
            'started_at': started_at,
            'return_code': completed.returncode,
            'stdout_tail': completed.stdout[-8192:].decode(errors='replace'),
            'stderr_tail': completed.stderr[-8192:].decode(errors='replace'),
            'successful': completed.returncode == 0,
        }
