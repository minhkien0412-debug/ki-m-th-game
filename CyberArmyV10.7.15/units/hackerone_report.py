"""Build human-reviewed HackerOne report drafts without submitting them."""

import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Tuple

from .hackerone_engagement import EngagementError, HackerOneEngagement
from .secret_redactor import SecretRedactor


class HackerOneReportBuilder:
    """Quality gate and Markdown renderer for report drafts."""

    REQUIRED_TEXT_FIELDS = (
        'title',
        'asset',
        'weakness',
        'summary',
        'impact',
        'remediation',
    )

    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.engagement = HackerOneEngagement(config)
        self.redactor = SecretRedactor()
        output_dir = config.get('hackerone', {}).get(
            'report_output_dir', 'state/hackerone_drafts'
        )
        self.output_dir = Path(output_dir)

    def validate_finding(self, finding: Dict[str, Any]) -> Tuple[bool, List[str]]:
        errors: List[str] = []

        for field in self.REQUIRED_TEXT_FIELDS:
            if not isinstance(finding.get(field), str) or not finding[field].strip():
                errors.append(f'{field} is required')

        steps = finding.get('steps_to_reproduce')
        if not isinstance(steps, list) or len(steps) < 2:
            errors.append('steps_to_reproduce must contain at least two steps')
        elif any(not isinstance(step, str) or not step.strip() for step in steps):
            errors.append('Every reproduction step must be non-empty text')

        evidence = finding.get('evidence')
        if not isinstance(evidence, list) or not evidence:
            errors.append('At least one sanitized evidence reference is required')
        elif any(
            not isinstance(item, str)
            or not item.strip()
            or len(item) > 500
            or '\n' in item
            for item in evidence
        ):
            errors.append('Evidence items must be short, single-line sanitized references')

        if finding.get('manual_validation_confirmed') is not True:
            errors.append('manual_validation_confirmed must be true')

        if finding.get('contains_third_party_data') is not False:
            errors.append('contains_third_party_data must be explicitly false')

        asset = finding.get('asset', '')
        if asset:
            try:
                self.engagement.authorize('reporting', asset)
            except EngagementError as exc:
                errors.append(str(exc))

        return not errors, errors

    def build_markdown(self, finding: Dict[str, Any]) -> str:
        valid, errors = self.validate_finding(finding)
        if not valid:
            raise EngagementError('; '.join(errors))

        safe = self.redactor.redact_dict(finding)
        lines = [
            f"# {safe['title']}",
            '',
            f"- **Program:** {self.config['hackerone']['program_handle']}",
            f"- **Asset:** {safe['asset']}",
            f"- **Weakness:** {safe['weakness']}",
            f"- **Suggested severity:** {safe.get('suggested_severity', 'not assessed')}",
            f"- **Drafted:** {datetime.now(timezone.utc).isoformat()}",
            '',
            '## Summary',
            '',
            safe['summary'],
            '',
            '## Steps to reproduce',
            '',
        ]

        for index, step in enumerate(safe['steps_to_reproduce'], 1):
            lines.append(f'{index}. {step}')

        lines.extend([
            '',
            '## Observed result',
            '',
            safe.get('observed_result', 'See the reproduction steps and evidence.'),
            '',
            '## Expected result',
            '',
            safe.get('expected_result', 'The security boundary should remain enforced.'),
            '',
            '## Impact',
            '',
            safe['impact'],
            '',
            '## Evidence',
            '',
        ])

        for item in safe['evidence']:
            lines.append(f'- {item}')

        lines.extend([
            '',
            '## Suggested remediation',
            '',
            safe['remediation'],
            '',
            '---',
            '',
            'This is a local draft. A human must re-check scope, reproduce the issue, '
            'remove sensitive data, and submit it manually through HackerOne.',
        ])
        return '\n'.join(lines)

    def build_from_json_file(self, input_path: str) -> str:
        path = Path(input_path)
        with open(path, 'r', encoding='utf-8') as handle:
            finding = json.load(handle)

        content = self.build_markdown(finding)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        slug = re.sub(r'[^a-z0-9]+', '-', finding['title'].lower()).strip('-')[:60]
        output_path = self.output_dir / f'{slug or "finding"}.md'
        output_path.write_text(content, encoding='utf-8')
        return str(output_path)
