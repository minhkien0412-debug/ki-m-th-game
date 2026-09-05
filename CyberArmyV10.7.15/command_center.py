#!/usr/bin/env python3
"""
CyberArmy V10.7.15 - Command Center
Main entry point for the game security testing system
"""

import argparse
import asyncio
import json
import sys
import yaml
from pathlib import Path


def load_config(config_path: str) -> dict:
    """Load configuration from YAML file"""
    with open(config_path, 'r') as f:
        return yaml.safe_load(f)


def main():
    parser = argparse.ArgumentParser(
        description='CyberArmy V10.7.15 - Game Security Testing System',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python command_center.py --config config.yaml --scan
  python command_center.py --config config.yaml --recon example.com
  python command_center.py --config config.yaml --h1-validate-profile
  python command_center.py --config config.yaml --h1-check-target https://example.com
  python command_center.py --version
        """
    )
    
    parser.add_argument('--config', '-c', default='config.yaml',
                       help='Path to configuration file (default: config.yaml)')
    parser.add_argument('--scan', action='store_true',
                       help='Run full security scan')
    parser.add_argument('--recon', metavar='DOMAIN',
                       help='Run reconnaissance on domain')
    parser.add_argument('--validate', action='store_true',
                       help='Validate configuration only')
    parser.add_argument('--version', action='version', version='CyberArmy V10.7.15')
    parser.add_argument('--verbose', '-v', action='store_true',
                       help='Verbose output')
    parser.add_argument('--h1-validate-profile', action='store_true',
                        help='Validate the local PlayStation HackerOne profile')
    parser.add_argument('--h1-check-target', metavar='TARGET',
                        help='Check a URL or hostname against the verified HackerOne scope')
    parser.add_argument('--h1-authorize', nargs=2, metavar=('ACTION', 'TARGET'),
                        help='Check whether a low-impact action is allowed for a target')
    parser.add_argument('--h1-draft-report', metavar='FINDING_JSON',
                        help='Create a local HackerOne Markdown report draft')
    parser.add_argument('--h1-passive-recon', metavar='TARGET',
                        help='Run scope-filtered passive certificate reconnaissance')
    parser.add_argument('--h1-observe-head', metavar='URL',
                        help='Make one authorized HEAD request and save redacted metadata')
    parser.add_argument('--lab-validate', action='store_true',
                        help='Validate the isolated self-hosted local lab policy')
    parser.add_argument('--lab-api-boundary', nargs=4,
                        metavar=('URL', 'PAYLOAD_JSON', 'FIELD', 'TYPE'),
                        help='Run bounded boundary cases against a loopback API')
    parser.add_argument('--lab-analyze-protocol', metavar='CORPUS_FILE',
                        help='Analyze an owned protocol corpus offline')
    parser.add_argument('--lab-build-trace', metavar='SYMBOL',
                        help='Generate an observation-only Frida symbol trace')
    parser.add_argument('--lab-fuzz', nargs=2, metavar=('EXECUTABLE', 'SEED_FILE'),
                        help='Run bounded mutation fuzzing against a self-hosted binary')
    parser.add_argument('--lab-fuzz-cases', type=int, default=25,
                        help='Number of local fuzz cases (default: 25)')
    parser.add_argument('--console-validate', action='store_true',
                        help='Validate the authorized dev/test-kit integration profile')
    parser.add_argument('--console-validate-capability',
                        choices=('run', 'workflow', 'symbolicate', 'import_crash',
                                 'corpus', 'telemetry'),
                        help='Validate only one console capability and its required tools')
    parser.add_argument('--console-plan', metavar='ARTIFACT',
                        help='Print the official-SDK argv for an owned console build')
    parser.add_argument('--console-run', metavar='ARTIFACT',
                        help='Run an owned build through the configured official SDK tool')
    parser.add_argument('--console-import-crash', metavar='CRASH_FILE',
                        help='Import a locally exported crash or log with hashes')
    parser.add_argument('--console-symbolicate', nargs=2,
                        metavar=('CRASH_FILE', 'SYMBOL_FILE'),
                        help='Run the configured offline symbolication tool')
    parser.add_argument('--console-index-corpus', metavar='CORPUS_DIRECTORY',
                        help='Create a deterministic manifest for an owned corpus')
    parser.add_argument('--console-workflow-plan', metavar='ARTIFACT',
                        help='Print preflight/deploy/launch/collect/stop SDK argv')
    parser.add_argument('--console-workflow', metavar='ARTIFACT',
                        help='Run the guarded multi-step dev/test-kit workflow')
    parser.add_argument('--console-analyze-telemetry', metavar='TELEMETRY_CSV',
                        help='Analyze an exported owned telemetry CSV offline')
    parser.add_argument('--analyze-integrity', metavar='TELEMETRY_CSV',
                        help='Offline anti-cheat/integrity anomaly analysis of an '
                             'owned telemetry CSV (no network)')

    args = parser.parse_args()
    
    # Load configuration
    config_path = Path(args.config)
    if not config_path.exists():
        print(f"[ERROR] Configuration file not found: {config_path}")
        sys.exit(1)
    
    try:
        config = load_config(str(config_path))
    except Exception as e:
        print(f"[ERROR] Failed to load configuration: {e}")
        sys.exit(1)
    
    print("=" * 60)
    print("CyberArmy V10.7.15 - Game Security Testing System")
    print("=" * 60)
    print()
    
    # Validate configuration
    from units.config_validator import ConfigValidator
    validator = ConfigValidator()
    is_valid, parsed_config = validator.validate_file(str(config_path))
    
    if args.validate or not is_valid:
        summary = validator.get_summary()
        print(f"Configuration Valid: {summary['valid']}")
        print(f"Errors: {summary['error_count']}")
        print(f"Warnings: {summary['warning_count']}")
        
        if summary['errors']:
            print("\nErrors:")
            for error in summary['errors']:
                print(f"  - {error}")
        
        if summary['warnings']:
            print("\nWarnings:")
            for warning in summary['warnings']:
                print(f"  - {warning}")
        
        if not is_valid:
            sys.exit(1)
        
        if args.validate:
            print("\nConfiguration is valid!")
            sys.exit(0)

    if args.analyze_integrity:
        from units.integrity_analyzer import IntegrityAnalyzer, IntegrityAnalyzerError

        try:
            result = IntegrityAnalyzer(config).analyze(args.analyze_integrity)
        except (IntegrityAnalyzerError, OSError) as exc:
            print(f"[BLOCKED] Integrity analysis failed: {exc}")
            sys.exit(1)
        print(json.dumps(result, indent=2))
        sys.exit(0 if result['finding_count'] == 0 else 2)

    h1_requested = any((
        args.h1_validate_profile,
        args.h1_check_target,
        args.h1_authorize,
        args.h1_draft_report,
        args.h1_passive_recon,
        args.h1_observe_head,
    ))
    if h1_requested:
        from units.hackerone_engagement import EngagementError, HackerOneEngagement

        engagement = HackerOneEngagement(config)
        valid, errors, warnings = engagement.validate_profile()
        print("\n[HackerOne PlayStation Profile]")
        print(f"Valid: {valid}")
        for warning in warnings:
            print(f"  WARNING: {warning}")
        for error in errors:
            print(f"  ERROR: {error}")

        if args.h1_validate_profile:
            sys.exit(0 if valid else 1)

        if not valid:
            print("[BLOCKED] Fix the HackerOne profile before continuing.")
            sys.exit(1)

        if args.h1_check_target:
            asset = engagement.find_scope_asset(args.h1_check_target)
            if asset is None:
                print("[BLOCKED] Target is not in the manually verified scope.")
                sys.exit(1)
            print(f"[IN SCOPE] {asset['type']}: {asset['identifier']}")
            sys.exit(0)

        if args.h1_authorize:
            action, target = args.h1_authorize
            try:
                asset = engagement.authorize(action, target)
            except EngagementError as exc:
                print(f"[BLOCKED] {exc}")
                sys.exit(1)
            print(f"[AUTHORIZED] {action} on {asset['identifier']}")
            sys.exit(0)

        if args.h1_draft_report:
            from units.hackerone_report import HackerOneReportBuilder

            try:
                output_path = HackerOneReportBuilder(config).build_from_json_file(
                    args.h1_draft_report
                )
            except (EngagementError, OSError, ValueError) as exc:
                print(f"[BLOCKED] Report draft failed: {exc}")
                sys.exit(1)
            print(f"Draft saved to: {output_path}")
            print("Review and submit it manually through HackerOne.")
            sys.exit(0)

        if args.h1_passive_recon:
            from units.hackerone_runner import HackerOneRunner

            try:
                result = HackerOneRunner(config).passive_recon(args.h1_passive_recon)
            except (EngagementError, OSError, RuntimeError, ValueError) as exc:
                print(f"[BLOCKED] Passive reconnaissance failed: {exc}")
                sys.exit(1)
            print(f"In-scope subdomains found: {len(result['in_scope_subdomains'])}")
            for hostname in result['in_scope_subdomains']:
                print(f"  - {hostname}")
            print(result['note'])
            sys.exit(0)

        if args.h1_observe_head:
            from units.hackerone_runner import HackerOneRunner

            try:
                result = HackerOneRunner(config).observe_head(args.h1_observe_head)
            except (EngagementError, OSError, RuntimeError, ValueError) as exc:
                print(f"[BLOCKED] HEAD observation failed: {exc}")
                sys.exit(1)
            print(f"Status: {result['status_code']}")
            print(f"Observation saved to: {result['saved_to']}")
            print(result['note'])
            sys.exit(0)

    lab_requested = any((
        args.lab_validate,
        args.lab_api_boundary,
        args.lab_analyze_protocol,
        args.lab_build_trace,
        args.lab_fuzz,
    ))
    if lab_requested:
        from units.local_lab_policy import LocalLabError, LocalLabPolicy

        lab_policy = LocalLabPolicy(config)
        valid, errors = lab_policy.validate()
        print("\n[Isolated Local Lab]")
        print(f"Valid: {valid}")
        for error in errors:
            print(f"  ERROR: {error}")

        if args.lab_validate:
            sys.exit(0 if valid else 1)
        if not valid:
            print("[BLOCKED] Fix and acknowledge the local_lab profile first.")
            sys.exit(1)

        try:
            if args.lab_api_boundary:
                from units.api_boundary_lab import LocalApiInvariantTester

                url, payload_path, field, value_type = args.lab_api_boundary
                result = asyncio.run(LocalApiInvariantTester(config).run(
                    url, payload_path, field, value_type
                ))
                print(json.dumps(result, indent=2))
                sys.exit(0)

            if args.lab_analyze_protocol:
                from units.protocol_corpus import ProtocolCorpusAnalyzer

                result = ProtocolCorpusAnalyzer(config).analyze(
                    args.lab_analyze_protocol
                )
                print(json.dumps(result, indent=2))
                sys.exit(0)

            if args.lab_build_trace:
                from units.observation_instrumentation import ObservationScriptBuilder

                output_path = ObservationScriptBuilder(config).build(
                    args.lab_build_trace
                )
                print(f"Observation-only trace saved to: {output_path}")
                sys.exit(0)

            if args.lab_fuzz:
                from units.local_crash_fuzzer import LocalCrashFuzzer

                executable, seed_path = args.lab_fuzz
                result = LocalCrashFuzzer(config).run(
                    executable, seed_path, args.lab_fuzz_cases
                )
                print(json.dumps(result, indent=2))
                sys.exit(0)
        except (LocalLabError, OSError, RuntimeError, ValueError, json.JSONDecodeError) as exc:
            print(f"[BLOCKED] Local lab operation failed: {exc}")
            sys.exit(1)

    console_requested = any((
        args.console_validate,
        args.console_validate_capability,
        args.console_plan,
        args.console_run,
        args.console_import_crash,
        args.console_symbolicate,
        args.console_index_corpus,
        args.console_workflow_plan,
        args.console_workflow,
        args.console_analyze_telemetry,
    ))
    if console_requested:
        from units.console_lab_policy import ConsoleLabPolicy
        from units.local_lab_policy import LocalLabError

        console_policy = ConsoleLabPolicy(config)
        if args.console_validate_capability:
            capability = args.console_validate_capability
        elif args.console_plan or args.console_run:
            capability = 'run'
        elif args.console_workflow_plan or args.console_workflow:
            capability = 'workflow'
        elif args.console_symbolicate:
            capability = 'symbolicate'
        elif args.console_import_crash:
            capability = 'import_crash'
        elif args.console_index_corpus:
            capability = 'corpus'
        elif args.console_analyze_telemetry:
            capability = 'telemetry'
        else:
            capability = 'base'
        require_execution = bool(args.console_run or args.console_workflow)
        valid, errors = console_policy.validate_capability(
            capability, require_execution=require_execution
        )
        print("\n[Authorized PlayStation Dev/Test-Kit Lab]")
        print(f"Valid: {valid}")
        for error in errors:
            print(f"  ERROR: {error}")

        if args.console_validate or args.console_validate_capability:
            sys.exit(0 if valid else 1)
        if not valid:
            print('[BLOCKED] Complete the console_lab profile before continuing.')
            sys.exit(1)

        try:
            if args.console_plan or args.console_run:
                from units.console_kit_adapter import ConsoleKitAdapter

                adapter = ConsoleKitAdapter(config)
                result = (
                    adapter.run_artifact(args.console_run)
                    if args.console_run
                    else adapter.plan_artifact(args.console_plan)
                )
                print(json.dumps(result, indent=2))
                sys.exit(0 if result.get('successful', True) else 1)

            if args.console_import_crash:
                from units.console_artifacts import ConsoleArtifactManager

                result = ConsoleArtifactManager(config).import_crash(
                    args.console_import_crash
                )
                print(json.dumps(result, indent=2))
                sys.exit(0)

            if args.console_symbolicate:
                from units.console_artifacts import ConsoleArtifactManager

                result = ConsoleArtifactManager(config).symbolicate(
                    *args.console_symbolicate
                )
                print(json.dumps(result, indent=2))
                sys.exit(0 if result['return_code'] == 0 else 1)

            if args.console_index_corpus:
                from units.console_artifacts import ConsoleCorpusIndexer

                result = ConsoleCorpusIndexer(config).index(
                    args.console_index_corpus
                )
                print(json.dumps(result, indent=2))
                sys.exit(0)

            if args.console_workflow_plan or args.console_workflow:
                from units.console_kit_adapter import ConsoleKitAdapter

                adapter = ConsoleKitAdapter(config)
                result = (
                    adapter.run_workflow(args.console_workflow)
                    if args.console_workflow
                    else adapter.plan_workflow(args.console_workflow_plan)
                )
                print(json.dumps(result, indent=2))
                sys.exit(0 if result.get('successful', True) else 1)

            if args.console_analyze_telemetry:
                from units.console_artifacts import ConsoleTelemetryAnalyzer

                result = ConsoleTelemetryAnalyzer(config).analyze(
                    args.console_analyze_telemetry
                )
                print(json.dumps(result, indent=2))
                sys.exit(0)
        except (LocalLabError, OSError, RuntimeError, ValueError) as exc:
            print(f"[BLOCKED] Console lab operation failed: {exc}")
            sys.exit(1)

    # Check authorization gate
    from units.program_policy import ProgramPolicy
    policy_gate = ProgramPolicy(config)
    authorized, auth_details = policy_gate.check_authorization()
    
    print("\n[Authorization Gate]")
    if not authorized:
        print("WARNING: Not authorized - active operations are blocked")
        for error in auth_details.get('errors', []):
            print(f"  - {error}")
        print("\nTo enable full functionality:")
        print("  1. Set acknowledged: true in config.yaml")
        print("  2. Set kill_switch_enabled: false when ready")
        print("  3. Ensure policy files exist and hash matches")

        if args.recon or args.scan:
            print("\n[BLOCKED] Authorization is required for reconnaissance or scanning.")
            sys.exit(1)
    else:
        print("Authorization: GRANTED")
    
    # Run requested operation
    if args.recon:
        from units.scope_engine import ScopeEngine
        recon_target = args.recon.lower().rstrip('.')
        if not ScopeEngine(config).is_host_in_scope(recon_target):
            print(f"\n[BLOCKED] Reconnaissance target is outside the allowed host scope: {args.recon}")
            sys.exit(1)

        print(f"\n[Reconnaissance] Target: {args.recon}")
        from units.recon_engine import ReconEngine
        recon = ReconEngine(config)
        results = recon.run_passive_recon(args.recon)
        
        print(f"Subdomains found: {len(results['subdomains'])}")
        for subdomain in results['subdomains'][:10]:  # Show first 10
            print(f"  - {subdomain}")
        
        recon.close()
    
    elif args.scan:
        print("\n[Security Scan] Starting...")
        print("NOTE: Full scan requires proper authorization.")
        print("Running in SAFE/PASSIVE mode only.")
        print("This build performs passive/safe analysis only: it never")
        print("generates active or exploit traffic and never fabricates findings.")

        # Import and run scan components
        from units.mission_store import MissionStore
        from units.finding_engine import FindingEngine
        from units.safe_validator import SafeValidator
        from units.validation_context import ValidationContext
        from units.evidence_store import EvidenceStore
        from units.validators.reflection import ReflectionValidator
        from units.validators.authorization_boundary import (
            AuthorizationBoundaryValidator,
        )
        from units.validators.security_headers import SecurityHeadersValidator

        mission_store = MissionStore()
        finding_engine = FindingEngine(config)

        target_name = config.get('target', {}).get('name', 'Unknown')
        base_url = config.get('target', {}).get('base_url', '')

        mission_id = mission_store.create_mission(target_name, base_url)
        print(f"Mission ID: {mission_id}")

        # Run only the registered SAFE (passive) validators. They analyze data
        # already collected and report real findings; none are simulated.
        registry = SafeValidator(config)
        registry.register_validator('reflection', ReflectionValidator(config))
        registry.register_validator(
            'authorization_boundary', AuthorizationBoundaryValidator(config)
        )
        registry.register_validator(
            'security_headers', SecurityHeadersValidator(config)
        )

        context = ValidationContext(mission_id, config)
        # Feed any previously collected traffic to the passive validators so they
        # analyze real evidence. With no stored traffic there is simply nothing
        # to find — the scan never invents a result.
        evidence_dir = config.get('evidence', {}).get('evidence_dir', 'state/evidence')
        collected = EvidenceStore(evidence_dir).get_traffic(mission_id)
        for entry in collected:
            request = entry.get('request', {}) or {}
            response = entry.get('response', {}) or {}
            context.add_response({
                'url': request.get('url') or entry.get('url', ''),
                'method': request.get('method', 'GET'),
                'status': response.get('status') or response.get('status_code'),
                'request_headers': request.get('headers', {}),
                'response_headers': response.get('headers', {}),
                'body': response.get('body', ''),
            })

        for result in registry.run_all_validators(context):
            finding_engine.add_findings(result.get('findings', []))

        summary = finding_engine.get_summary()
        print(f"\nSafe validators run: {len(registry.get_all_validators())}")
        print(f"Findings Summary:")
        print(f"  Total: {summary['total']}")
        print(f"  By Severity: {summary['by_severity']}")
        if summary['total'] == 0:
            print("  No findings from passive analysis. Active vulnerability")
            print("  testing is out of scope for this build; use the isolated")
            print("  lab or HackerOne safe-mode tools for hands-on validation.")

        # Generate report
        from units.report_generator import ReportGenerator
        report_gen = ReportGenerator(config)
        
        findings_data = finding_engine.export_findings()
        report_content = report_gen.generate_report({'mission_id': mission_id}, findings_data)
        
        report_path = report_gen.save_report(report_content, f"mission_{mission_id}.md")
        print(f"\nReport saved to: {report_path}")
    
    else:
        parser.print_help()
    
    print("\n" + "=" * 60)
    print("Scan complete. Stay safe and ethical!")
    print("=" * 60)


if __name__ == '__main__':
    main()
