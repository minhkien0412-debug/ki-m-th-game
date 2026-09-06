"""
CyberArmy V10.7.15 - Units Package
Core modules for game security testing system

Submodules are imported lazily (PEP 562): importing ``units`` or a single unit
does not drag in every other unit's third-party dependencies. This keeps the
fail-closed validate-only flows (``--console-validate``, ``--lab-validate``,
``--h1-validate-profile``) runnable without the heavier web-analysis stack
(e.g. beautifulsoup4, aiohttp) that only a couple of units actually need.
"""

import importlib

__version__ = "10.7.15"
__author__ = "CyberArmy Security Team"

__all__ = [
    'canonicalizer',
    'dns_ip_gate',
    'pinned_connection',
    'sanitizer',
    'secret_redactor',
    'config_validator',
    'scope_engine',
    'policy_engine',
    'program_policy',
    'mission_store',
    'evidence_store',
    'target_request_gate',
    'external_intel_client',
    'recon_engine',
    'web_analyzer',
    'api_analyzer',
    'code_analyst',
    'safe_validator',
    'finding_engine',
    'integrity_analyzer',
    'zap_import',
    'zap_orchestrator',
    'report_generator',
    'candidate_rules_engine',
    'validation_context',
    'hackerone_engagement',
    'hackerone_report',
    'hackerone_runner',
    'local_lab_policy',
    'api_boundary_lab',
    'protocol_corpus',
    'observation_instrumentation',
    'local_crash_fuzzer',
    'coverage_fuzzer',
    'anticheat_rules',
    'console_lab_policy',
    'console_kit_adapter',
    'console_artifacts',
]

_SUBMODULES = frozenset(__all__)


def __getattr__(name):
    """Import a submodule on first attribute access (PEP 562)."""
    if name in _SUBMODULES:
        module = importlib.import_module(f"{__name__}.{name}")
        globals()[name] = module
        return module
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


def __dir__():
    return sorted(set(globals()) | _SUBMODULES)
