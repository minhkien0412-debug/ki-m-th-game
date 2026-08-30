"""Vendor-neutral command adapter for an official PlayStation SDK installation."""

import hashlib
import json
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Mapping

from .console_lab_policy import ConsoleLabPolicy
from .local_lab_policy import LocalLabError
from .secret_redactor import SecretRedactor


class ConsoleKitAdapter:
    """Plan or execute an explicitly configured official SDK command."""

    def __init__(self, config: Dict[str, Any]):
        self.policy = ConsoleLabPolicy(config)
        self.redactor = SecretRedactor()

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
                .replace('{session_dir}', values.get('session_dir', ''))
            for item in template
        ]

    def _execute_command(
        self, name: str, argv: List[str], cwd: Path
    ) -> Dict[str, Any]:
        started_at = datetime.now(timezone.utc).isoformat()
        try:
            completed = subprocess.run(
                argv,
                cwd=str(cwd),
                capture_output=True,
                timeout=int(self.policy.config.get('process_timeout_seconds', 30)),
                check=False,
                shell=False,
                env=self.policy.safe_environment(),
            )
        except subprocess.TimeoutExpired:
            return {
                'step': name,
                'started_at': started_at,
                'return_code': None,
                'successful': False,
                'timed_out': True,
                'shell': False,
            }
        return {
            'step': name,
            'started_at': started_at,
            'return_code': completed.returncode,
            'successful': completed.returncode == 0,
            'timed_out': False,
            'stdout_tail': self.redactor.redact(
                completed.stdout[-8192:].decode(errors='replace')
            ),
            'stderr_tail': self.redactor.redact(
                completed.stderr[-8192:].decode(errors='replace')
            ),
            'shell': False,
        }

    def plan_artifact(self, artifact_path: str) -> Dict[str, Any]:
        self.policy.require_capability('run')
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
        self.policy.require_capability('run', require_execution=True)
        plan = self.plan_artifact(artifact_path)
        execution = self._execute_command(
            'run', plan['argv'], Path(plan['artifact']).parent
        )
        return {
            **plan,
            'mode': 'executed-on-authorized-dev-test-kit',
            **execution,
        }

    def plan_workflow(self, artifact_path: str) -> Dict[str, Any]:
        self.policy.require_capability('workflow')
        artifact = self.policy.require_artifact(artifact_path)
        session_root = self.policy.require_workspace_path(
            self.policy.config.get('session_output_dir', 'state/console_sessions'),
            must_exist=False,
        )
        values = {
            'artifact': str(artifact),
            'session_dir': str(session_root / 'SESSION-ID-AT-RUNTIME'),
            'output_dir': str(session_root / 'SESSION-ID-AT-RUNTIME'),
        }
        return {
            'mode': 'workflow-dry-run',
            'platform': self.policy.platform,
            'kit_id': self.policy.kit_id,
            'artifact': str(artifact),
            'artifact_sha256': self._sha256(artifact),
            'steps': [
                {
                    'step': name,
                    'argv': self._render(f'{name}_command', values),
                    'shell': False,
                }
                for name in ('preflight', 'deploy', 'launch', 'collect', 'stop')
            ],
            'authorization_reference': self.policy.authorization_reference,
        }

    def run_workflow(self, artifact_path: str) -> Dict[str, Any]:
        """Run a bounded SDK session and always attempt stop after launch."""
        self.policy.require_capability('workflow', require_execution=True)
        artifact = self.policy.require_artifact(artifact_path)
        session_id = datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S%fZ')
        session_root = self.policy.require_workspace_path(
            self.policy.config.get('session_output_dir', 'state/console_sessions'),
            must_exist=False,
        )
        session_dir = session_root / session_id
        session_dir.mkdir(parents=True, exist_ok=False)
        values = {
            'artifact': str(artifact),
            'session_dir': str(session_dir),
            'output_dir': str(session_dir),
        }
        results: List[Dict[str, Any]] = []
        launch_attempted = False
        try:
            for name in ('preflight', 'deploy', 'launch', 'collect'):
                if name == 'launch':
                    launch_attempted = True
                result = self._execute_command(
                    name,
                    self._render(f'{name}_command', values),
                    artifact.parent,
                )
                results.append(result)
                if not result['successful']:
                    break
        finally:
            if launch_attempted:
                results.append(self._execute_command(
                    'stop', self._render('stop_command', values), artifact.parent
                ))

        successful = (
            len(results) == 5 and all(item['successful'] for item in results)
        )
        audit = {
            'mode': 'authorized-dev-test-kit-workflow',
            'session_id': session_id,
            'session_dir': str(session_dir),
            'platform': self.policy.platform,
            'kit_id': self.policy.kit_id,
            'artifact': str(artifact),
            'artifact_sha256': self._sha256(artifact),
            'steps': results,
            'successful': successful,
            'authorization_reference': self.policy.authorization_reference,
        }
        audit_path = session_dir / 'session-audit.json'
        audit_path.write_text(json.dumps(audit, indent=2), encoding='utf-8')
        audit['audit_path'] = str(audit_path)
        return audit
