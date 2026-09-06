"""Fail-closed HackerOne engagement and scope policy enforcement."""

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse


class EngagementError(ValueError):
    """Raised when a requested bug-bounty action is not authorized."""


class HackerOneEngagement:
    """Validate a HackerOne profile before any target-specific activity."""

    SAFE_ACTIONS = {
        'passive_recon',
        'http_get',
        'http_head',
        'manual_validation',
        'reporting',
    }

    FORBIDDEN_ACTIONS = {
        'account_takeover',
        'brute_force',
        'credential_stuffing',
        'data_exfiltration',
        'destructive_testing',
        'dos',
        'ddos',
        'phishing',
        'social_engineering',
        'spam',
    }

    def __init__(self, config: Dict[str, Any]):
        self.config = config.get('hackerone', {})
        self.assets: List[Dict[str, Any]] = self.config.get('scope_assets', [])

    @staticmethod
    def _parse_timestamp(value: str) -> Optional[datetime]:
        if not value:
            return None
        try:
            parsed = datetime.fromisoformat(value.replace('Z', '+00:00'))
        except (TypeError, ValueError):
            return None
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return parsed.astimezone(timezone.utc)

    def validate_profile(self, now: Optional[datetime] = None) -> Tuple[bool, List[str], List[str]]:
        """Return profile validity, errors and non-blocking warnings."""
        errors: List[str] = []
        warnings: List[str] = []

        if not self.config.get('enabled', False):
            errors.append('HackerOne mode is disabled')

        if self.config.get('program_handle') != 'playstation':
            errors.append('program_handle must be playstation')

        policy_url = self.config.get('policy_url', '')
        if not policy_url.startswith('https://hackerone.com/playstation'):
            errors.append('policy_url must point to the official PlayStation HackerOne program')

        if not self.config.get('researcher_handle'):
            errors.append('researcher_handle is required')

        if not self.config.get('acknowledged_current_policy', False):
            errors.append('The current program policy has not been acknowledged')

        if not self.config.get('human_in_the_loop', False):
            errors.append('human_in_the_loop must be enabled')

        if not isinstance(self.assets, list) or not self.assets:
            errors.append('At least one manually verified scope asset is required')

        reviewed_at = self._parse_timestamp(self.config.get('scope_reviewed_at', ''))
        if reviewed_at is None:
            errors.append('scope_reviewed_at must be a valid ISO-8601 timestamp')
        else:
            now = now or datetime.now(timezone.utc)
            if now.tzinfo is None:
                now = now.replace(tzinfo=timezone.utc)
            try:
                max_age_days = max(1, int(self.config.get('scope_max_age_days', 1)))
            except (TypeError, ValueError):
                errors.append('scope_max_age_days must be a positive integer')
                max_age_days = 1
            age_seconds = (now.astimezone(timezone.utc) - reviewed_at).total_seconds()
            if age_seconds < 0:
                errors.append('scope_reviewed_at cannot be in the future')
            elif age_seconds > max_age_days * 86400:
                errors.append('Scope snapshot is stale; re-check the HackerOne policy page')

        for index, asset in enumerate(self.assets):
            if not isinstance(asset, dict):
                errors.append(f'scope_assets[{index}] must be a mapping')
                continue
            if asset.get('type') not in {'domain', 'url', 'hardware'}:
                errors.append(f'scope_assets[{index}].type is unsupported')
            if not asset.get('identifier'):
                errors.append(f'scope_assets[{index}].identifier is required')
            if asset.get('eligible_for_submission') is False:
                warnings.append(f"{asset.get('identifier', index)} is not submission-eligible")

            allowed_actions = asset.get('allowed_actions', [])
            if not isinstance(allowed_actions, list):
                errors.append(f'scope_assets[{index}].allowed_actions must be a list')
            else:
                for action in allowed_actions:
                    if action in self.FORBIDDEN_ACTIONS:
                        errors.append(
                            f'scope_assets[{index}] includes a forbidden action: {action}'
                        )
                    elif action not in self.SAFE_ACTIONS:
                        errors.append(
                            f'scope_assets[{index}] includes an unknown action: {action}'
                        )

            identifier = str(asset.get('identifier', ''))
            if asset.get('type') == 'url':
                parsed_identifier = urlparse(identifier)
                if parsed_identifier.scheme not in {'http', 'https'} or not parsed_identifier.hostname:
                    errors.append(f'scope_assets[{index}] has an invalid HTTP(S) URL')
                if parsed_identifier.username is not None or parsed_identifier.password is not None:
                    errors.append(f'scope_assets[{index}] URL must not contain user information')
                if parsed_identifier.query or parsed_identifier.fragment:
                    errors.append(
                        f'scope_assets[{index}] URL queries/fragments are not supported'
                    )
            elif asset.get('type') == 'domain' and '://' in identifier:
                errors.append(f'scope_assets[{index}] domain must not include a URL scheme')
            elif asset.get('type') == 'domain':
                domain_value = identifier[2:] if identifier.startswith('*.') else identifier
                parsed_domain = urlparse(f'https://{domain_value}')
                try:
                    domain_port = parsed_domain.port
                except ValueError:
                    domain_port = -1
                if (
                    not parsed_domain.hostname
                    or parsed_domain.username is not None
                    or parsed_domain.password is not None
                    or domain_port is not None
                    or parsed_domain.path not in {'', '/'}
                    or parsed_domain.query
                    or parsed_domain.fragment
                ):
                    errors.append(f'scope_assets[{index}] has an invalid domain identifier')

        return not errors, errors, warnings

    @staticmethod
    def _domain_matches(hostname: str, pattern: str) -> bool:
        hostname = hostname.lower().rstrip('.')
        pattern = pattern.lower().rstrip('.')
        if pattern.startswith('*.'):
            base = pattern[2:]
            return hostname.endswith('.' + base)
        return hostname == pattern

    def find_scope_asset(self, target: str) -> Optional[Dict[str, Any]]:
        """Find the exact manually verified scope entry for a URL or hostname."""
        hardware_target = target.strip().casefold()
        for asset in self.assets:
            if (
                asset.get('type') == 'hardware'
                and asset.get('eligible_for_submission', True) is not False
                and str(asset.get('identifier', '')).strip().casefold() == hardware_target
            ):
                return asset

        parsed = urlparse(target if '://' in target else f'https://{target}')
        hostname = (parsed.hostname or '').lower().rstrip('.')
        if not hostname:
            return None

        for asset in self.assets:
            if asset.get('eligible_for_submission', True) is False:
                continue
            asset_type = asset.get('type')
            identifier = str(asset.get('identifier', '')).strip()

            if asset_type == 'domain' and self._domain_matches(hostname, identifier):
                return asset

            if asset_type == 'url':
                allowed = urlparse(identifier)
                if not allowed.hostname:
                    continue
                same_origin = (
                    parsed.scheme.lower() == allowed.scheme.lower()
                    and hostname == allowed.hostname.lower().rstrip('.')
                    and (parsed.port or self._default_port(parsed.scheme))
                    == (allowed.port or self._default_port(allowed.scheme))
                )
                allowed_path = allowed.path or '/'
                target_path = parsed.path or '/'
                if same_origin and (
                    target_path == allowed_path
                    or target_path.startswith(allowed_path.rstrip('/') + '/')
                ):
                    return asset

        return None

    @staticmethod
    def _default_port(scheme: str) -> Optional[int]:
        return {'http': 80, 'https': 443}.get(scheme.lower())

    def find_wildcard_base_asset(self, target: str) -> Optional[Dict[str, Any]]:
        """Return the eligible ``*.base`` asset whose base equals ``target``.

        Passive certificate-transparency discovery enumerates subdomains of a
        registrable domain. A wildcard such as ``*.playstation.net`` authorizes
        those subdomains, so discovery rooted at the base ``playstation.net`` is
        in bounds even though the apex itself is not a testable asset. This is
        used ONLY for passive recon (a lookup against the public crt.sh service
        that contacts no target); every discovered host is still filtered with
        the strict ``find_scope_asset``.
        """
        parsed = urlparse(target if '://' in target else f'https://{target}')
        hostname = (parsed.hostname or '').lower().rstrip('.')
        if not hostname:
            return None
        for asset in self.assets:
            if asset.get('eligible_for_submission', True) is False:
                continue
            if asset.get('type') != 'domain':
                continue
            identifier = str(asset.get('identifier', '')).strip().lower().rstrip('.')
            if identifier.startswith('*.') and hostname == identifier[2:]:
                return asset
        return None

    def authorize(self, action: str, target: str,
                  recon_root: bool = False) -> Dict[str, Any]:
        """Authorize one low-impact action against one current in-scope asset.

        With ``recon_root=True`` (passive recon only), the base domain of an
        eligible wildcard also authorizes, so subdomain discovery can be rooted
        at the registrable domain.
        """
        valid, errors, _ = self.validate_profile()
        if not valid:
            raise EngagementError('; '.join(errors))

        normalized_action = action.strip().lower()
        if normalized_action in self.FORBIDDEN_ACTIONS:
            raise EngagementError(f'Action is always forbidden: {normalized_action}')
        if normalized_action not in self.SAFE_ACTIONS:
            raise EngagementError(f'Action is not allowlisted: {normalized_action}')

        asset = self.find_scope_asset(target)
        if asset is None and recon_root and normalized_action == 'passive_recon':
            asset = self.find_wildcard_base_asset(target)
        if asset is None:
            raise EngagementError('Target is not in the manually verified scope')

        allowed_actions = asset.get('allowed_actions')
        if allowed_actions and normalized_action not in allowed_actions:
            raise EngagementError('Action is not permitted for this scope asset')

        return asset
