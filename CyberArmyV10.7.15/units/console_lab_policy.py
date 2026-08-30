"""Fail-closed policy for authorized PlayStation dev/test-kit workflows."""

import os
import re
from pathlib import Path
from typing import Any, Dict, List, Sequence, Tuple

from .local_lab_policy import LocalLabError


class ConsoleLabPolicy:
    """Validate local artifacts and explicit partner/dev-kit attestations."""

    AUTHORIZATION_PATTERN = re.compile(r'^[A-Za-z0-9_.:-]{3,100}$')
    KIT_PATTERN = re.compile(r'^[A-Za-z0-9_.:-]{1,100}$')
    ALLOWED_PLATFORMS = {'ps4', 'ps5'}
    ALLOWED_PLACEHOLDERS = {
        '{artifact}', '{kit_id}', '{crash}', '{symbols}', '{output_dir}'
    }

    def __init__(self, config: Dict[str, Any]):
        self.config = config.get('console_lab', {})
        self.workspace_root = Path(
            self.config.get('workspace_root', '.')
        ).resolve()
        self.authorization_reference = str(
            self.config.get('authorization_reference', '')
        ).strip()
        self.platform = str(self.config.get('platform', '')).lower().strip()
        self.kit_id = str(self.config.get('kit_id', '')).strip()

    def validate(self, require_execution: bool = False) -> Tuple[bool, List[str]]:
        errors: List[str] = []
        required_flags = (
            ('enabled', 'Console lab mode is disabled'),
            ('partner_access_confirmed', 'partner_access_confirmed must be true'),
            ('official_sdk_installed', 'official_sdk_installed must be true'),
            ('dev_or_test_kit_only', 'dev_or_test_kit_only must be true'),
            ('human_in_the_loop', 'human_in_the_loop must be true'),
            ('network_isolated', 'network_isolated must be true'),
        )
        for key, message in required_flags:
            if not self.config.get(key, False):
                errors.append(message)

        if require_execution and not self.config.get('allow_device_execution', False):
            errors.append('allow_device_execution must be true for device execution')
        if not self.AUTHORIZATION_PATTERN.fullmatch(self.authorization_reference):
            errors.append('authorization_reference is missing or invalid')
        if self.platform not in self.ALLOWED_PLATFORMS:
            errors.append('platform must be ps4 or ps5')
        if not self.KIT_PATTERN.fullmatch(self.kit_id):
            errors.append('kit_id is missing or invalid')
        if not self.workspace_root.is_dir():
            errors.append('workspace_root must be an existing directory')

        for command_name in ('run_command', 'symbolicate_command'):
            try:
                self.validate_command_template(
                    self.config.get(command_name, []), command_name
                )
            except LocalLabError as exc:
                errors.append(str(exc))

        environment_names = self.config.get('sdk_environment_allowlist', [])
        if not isinstance(environment_names, list) or any(
            not isinstance(name, str)
            or not re.fullmatch(r'[A-Za-z_][A-Za-z0-9_]{0,127}', name)
            for name in environment_names
        ):
            errors.append('sdk_environment_allowlist must contain valid variable names')

        for key, default, maximum in (
            ('process_timeout_seconds', 30, 600),
            ('max_artifact_bytes', 1073741824, 107374182400),
            ('max_crash_bytes', 268435456, 4294967296),
            ('max_corpus_files', 1000, 10000),
        ):
            try:
                value = int(self.config.get(key, default))
            except (TypeError, ValueError):
                errors.append(f'{key} must be an integer')
                continue
            if value < 1 or value > maximum:
                errors.append(f'{key} must be between 1 and {maximum}')

        return not errors, errors

    def require_valid(self, require_execution: bool = False) -> None:
        valid, errors = self.validate(require_execution=require_execution)
        if not valid:
            raise LocalLabError('; '.join(errors))

    def require_workspace_path(
        self, path: str, *, must_exist: bool = True, directory: bool = False
    ) -> Path:
        self.require_valid()
        candidate = Path(path)
        if not candidate.is_absolute():
            candidate = self.workspace_root / candidate
        candidate = candidate.resolve()
        try:
            candidate.relative_to(self.workspace_root)
        except ValueError as exc:
            raise LocalLabError('Path escapes console_lab.workspace_root') from exc
        if must_exist:
            expected = candidate.is_dir() if directory else candidate.is_file()
            if not expected:
                kind = 'directory' if directory else 'file'
                raise LocalLabError(f'Console lab {kind} does not exist: {candidate}')
        return candidate

    def require_artifact(self, path: str) -> Path:
        artifact = self.require_workspace_path(path)
        allowed = {
            str(item).lower() for item in self.config.get(
                'allowed_artifact_extensions', ['.pkg', '.self', '.elf']
            )
        }
        if artifact.suffix.lower() not in allowed:
            raise LocalLabError('Artifact extension is not allowlisted')
        if artifact.stat().st_size > int(
            self.config.get('max_artifact_bytes', 1073741824)
        ):
            raise LocalLabError('Artifact exceeds max_artifact_bytes')
        return artifact

    def require_tool(self, path: str) -> Path:
        tool = Path(path).expanduser().resolve()
        if not tool.is_file():
            raise LocalLabError(f'Configured SDK tool does not exist: {tool}')
        if tool.suffix.lower() != '.exe':
            raise LocalLabError('Configured SDK tool must be an .exe executable')
        return tool

    def validate_command_template(self, command: Sequence[str], name: str) -> List[str]:
        if not isinstance(command, list) or not command:
            raise LocalLabError(f'{name} must be a non-empty YAML list')
        rendered: List[str] = []
        for item in command:
            if not isinstance(item, str) or not item:
                raise LocalLabError(f'{name} entries must be non-empty strings')
            unknown = {
                token for token in re.findall(r'\{[^{}]+\}', item)
                if token not in self.ALLOWED_PLACEHOLDERS
            }
            if unknown:
                raise LocalLabError(f'{name} contains unsupported placeholders: {sorted(unknown)}')
            rendered.append(item)
        self.require_tool(rendered[0])
        return rendered

    def safe_environment(self) -> Dict[str, str]:
        allowed = {'PATH', 'SYSTEMROOT', 'WINDIR', 'TEMP', 'TMP'}
        allowed.update(
            str(name).upper()
            for name in self.config.get('sdk_environment_allowlist', [])
        )
        return {
            key: value for key, value in os.environ.items()
            if key.upper() in allowed
        }
