#!/usr/bin/env python3
"""
ADBasher - Automated Active Directory Penetration Testing Framework
A comprehensive framework for AD security assessments.
"""
import argparse
import sys
from core.orchestrator import Orchestrator

__version__ = "2.0.0"

def main():
    parser = argparse.ArgumentParser(
        description="ADBasher - Automated Active Directory Penetration Testing Framework",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s -t corp.local                     # Scan single domain
  %(prog)s -t 192.168.1.0/24                 # Scan network range
  %(prog)s -t dc01.corp.local dc02.corp.local # Multiple targets
  %(prog)s -t corp.local --opsec stealth     # Stealth mode
  %(prog)s --dry-run -t corp.local           # Validate without execution
        """
    )
    
    # Version
    parser.add_argument(
        "-v", "--version",
        action="version",
        version=f"%(prog)s {__version__}"
    )
    
    # Target Specification
    parser.add_argument(
        "-t", "--target", 
        nargs="+", 
        metavar="TARGET",
        help="Target IP(s), CIDR(s), or Domain(s)"
    )
    
    # Operational Modes
    parser.add_argument(
        "--opsec",
        choices=["standard", "stealth", "aggressive"],
        default="standard",
        help="Operational Security / Evasion level (default: standard)"
    )
    
    # Execution Control
    parser.add_argument(
        "--resume",
        metavar="SESSION_ID",
        help="Resume a previous session by ID"
    )
    
    # Dry Run Mode
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Validate configuration and targets without executing attacks"
    )
    
    # Verbosity
    parser.add_argument(
        "-q", "--quiet",
        action="store_true",
        help="Suppress non-essential output"
    )

    args = parser.parse_args()

    # Basic Validation
    if not args.target and not args.resume:
        parser.print_help()
        print("\n[!] Error: No target specified. Use -t/--target or --resume.")
        sys.exit(1)

    # Dry Run Mode
    if args.dry_run:
        print(f"[*] ADBasher v{__version__} - Dry Run Mode")
        print(f"[*] Targets: {', '.join(args.target) if args.target else 'N/A (resuming session)'}")
        print(f"[*] OpSec Level: {args.opsec}")
        print(f"[*] Configuration valid. Ready for execution.")
        sys.exit(0)

    # Initialize and Run
    engine = Orchestrator(args)
    engine.run()

if __name__ == "__main__":
    main()

