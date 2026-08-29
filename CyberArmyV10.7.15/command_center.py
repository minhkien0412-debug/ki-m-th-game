#!/usr/bin/env python3
"""
CyberArmy V10.7.15 - Command Center
Main entry point for the game security testing system
"""

import argparse
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
    
    # Check authorization gate
    from units.program_policy import ProgramPolicy
    policy_gate = ProgramPolicy(config)
    authorized, auth_details = policy_gate.check_authorization()
    
    print("\n[Authorization Gate]")
    if not authorized:
        print("WARNING: Not fully authorized - running in limited mode")
        for error in auth_details.get('errors', []):
            print(f"  - {error}")
        print("\nTo enable full functionality:")
        print("  1. Set acknowledged: true in config.yaml")
        print("  2. Set kill_switch_enabled: false when ready")
        print("  3. Ensure policy files exist and hash matches")
    else:
        print("Authorization: GRANTED")
    
    # Run requested operation
    if args.recon:
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
        
        # Import and run scan components
        from units.mission_store import MissionStore
        from units.finding_engine import FindingEngine
        
        mission_store = MissionStore()
        finding_engine = FindingEngine(config)
        
        target_name = config.get('target', {}).get('name', 'Unknown')
        base_url = config.get('target', {}).get('base_url', '')
        
        mission_id = mission_store.create_mission(target_name, base_url)
        print(f"Mission ID: {mission_id}")
        
        # Simulate findings for demo
        finding_engine.create_finding(
            finding_type='info_disclosure',
            title='Information Disclosure Test',
            severity='info',
            description='This is a test finding demonstrating the system.'
        )
        
        summary = finding_engine.get_summary()
        print(f"\nFindings Summary:")
        print(f"  Total: {summary['total']}")
        print(f"  By Severity: {summary['by_severity']}")
        
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
