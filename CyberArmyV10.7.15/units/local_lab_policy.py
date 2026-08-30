"""Authorization boundary for self-hosted, isolated local security labs."""

import re
from pathlib import Path
from typing import Any, Dict, List, Tuple
from urllib.parse import urlparse


class LocalLabError(ValueError):
    """Raised when a local-lab operation violates the declared sandbox."""


class LocalLabPolicy:
    """Fail closed unless the target is loopback or a file inside the lab root."""

    LOOPBACK_HOSTS = {'127.0.0.1', '::1'}
    AUTHORIZATION_PATTERN = re.compile(r'^[A-Za-z0-9_.:-]{3,100}$')

    def __init__(self, config: Dict[str, Any]):
        self.config = config.get('local_lab', {})
        self.workspace_root = Path(
            self.config.get('workspace_root', '.')
        ).resolve()
        self.authorization_reference = str(
            self.config.get('authorization_reference', '')
        ).strip()

    def validate(self) -> Tuple[bool, List[str]]:
        errors: List[str] = []
        if not self.config.get('enabled', False):
            errors.append('Local lab mode is disabled')
        if not self.config.get('authorized_self_hosted_only', False):
            errors.append('authorized_self_hosted_only must be true')
        if not self.config.get('human_in_the_loop', False):
            errors.append('human_in_the_loop must be true')
        if not self.config.get('network_isolated', False):
            errors.append('network_isolated must be true')
        if not self.AUTHORIZATION_PATTERN.fullmatch(self.authorization_reference):
            errors.append(
                'authorization_reference must be a non-secret identifier using letters, numbers, . _ : or -'
            )
        if not self.workspace_root.exists() or not self.workspace_root.is_dir():
            errors.append('workspace_root must be an existing directory')

        for name, default, maximum in (
            ('max_api_cases', 16, 32),
            ('max_concurrency', 2, 4),
            ('max_fuzz_cases', 50, 500),
            ('max_input_bytes', 1048576, 16777216),
            ('max_response_bytes', 262144, 1048576),
            ('process_timeout_seconds', 5, 30),
        ):
            try:
                value = int(self.config.get(name, default))
            except (TypeError, ValueError):
                errors.append(f'{name} must be an integer')
                continue
            if value < 1 or value > maximum:
                errors.append(f'{name} must be between 1 and {maximum}')

        return not errors, errors

    def require_valid(self):
        valid, errors = self.validate()
        if not valid:
            raise LocalLabError('; '.join(errors))

    def require_loopback_url(self, url: str) -> str:
        """Authorize only HTTP(S) services bound to explicit loopback hosts."""
        self.require_valid()
        parsed = urlparse(url)
        hostname = (parsed.hostname or '').lower().rstrip('.')
        if parsed.scheme not in {'http', 'https'} or hostname not in self.LOOPBACK_HOSTS:
            raise LocalLabError('Only explicit loopback HTTP(S) targets are allowed')
        try:
            port = parsed.port
        except ValueError as exc:
            raise LocalLabError('Invalid local target port') from exc
        if port is None or port < 1024 or port > 65535:
            raise LocalLabError('Local lab targets must use an explicit unprivileged port')
        if parsed.username is not None or parsed.password is not None:
            raise LocalLabError('Credentials are not allowed in local lab URLs')
        return url

    def require_workspace_file(self, path: str, must_exist: bool = True) -> Path:
        """Resolve a file and prove it remains inside the configured lab root."""
        self.require_valid()
        candidate = Path(path)
        if not candidate.is_absolute():
            candidate = self.workspace_root / candidate
        candidate = candidate.resolve()
        try:
            candidate.relative_to(self.workspace_root)
        except ValueError as exc:
            raise LocalLabError('Path escapes the configured workspace_root') from exc
        if must_exist and not candidate.is_file():
            raise LocalLabError(f'Lab file does not exist: {candidate}')
        return candidate
