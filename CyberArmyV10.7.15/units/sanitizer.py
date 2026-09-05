"""Parse AddressSanitizer / UndefinedBehaviorSanitizer reports for triage.

Sanitizer-instrumented builds print a structured report to stderr when they
detect memory or undefined-behavior bugs. Parsing that report gives a far more
precise crash fingerprint than a bare exit code: the bug class (e.g.
heap-buffer-overflow) plus the faulting frame. This module only *reads* text; it
does nothing to a target.
"""

import re
from typing import Any, Dict, Optional

_ASAN_ERROR = re.compile(
    r'==\d+==\s*ERROR:\s*(?P<tool>AddressSanitizer|LeakSanitizer|'
    r'ThreadSanitizer|MemorySanitizer):\s*(?P<bug>[a-zA-Z0-9_\-]+)'
)
_UBSAN = re.compile(r'(?P<file>[^\s:]+):(?P<line>\d+):\d+:\s*runtime error:\s*(?P<msg>.+)')
# First stack frame, e.g. "    #0 0x... in do_thing /src/parse.c:42:7"
_FRAME = re.compile(
    r'#0\s+0x[0-9a-fA-F]+\s+in\s+(?P<func>[^\s]+)\s+(?P<loc>[^\s]+)'
)


def parse_sanitizer_report(text: str) -> Optional[Dict[str, Any]]:
    """Return {tool, bug, function, location} for the first report, or None."""
    if not text:
        return None

    frame = _FRAME.search(text)
    function = frame.group('func') if frame else None
    location = frame.group('loc') if frame else None

    match = _ASAN_ERROR.search(text)
    if match:
        return {
            'tool': match.group('tool'),
            'bug': match.group('bug'),
            'function': function,
            'location': location,
        }

    ubsan = _UBSAN.search(text)
    if ubsan:
        # Collapse the variable tail of the UBSan message to a stable class.
        message = ubsan.group('msg').strip()
        bug = message.split(' ')[0:4]
        return {
            'tool': 'UndefinedBehaviorSanitizer',
            'bug': ' '.join(bug),
            'function': function,
            'location': f"{ubsan.group('file')}:{ubsan.group('line')}",
        }

    return None


def sanitizer_signature(text: str) -> Optional[str]:
    """A stable one-line fingerprint from a sanitizer report, or None."""
    report = parse_sanitizer_report(text)
    if not report:
        return None
    return f"{report['tool']}|{report['bug']}|{report.get('location') or report.get('function') or ''}"
