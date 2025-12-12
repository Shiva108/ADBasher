#!/usr/bin/env python3
import argparse
import sys
from core.orchestrator import Orchestrator

def main():
    parser = argparse.ArgumentParser(
        description="ADBasher - Automated Active Directory Penetration Testing Framework"
    )
    
    # Target Specification
    parser.add_argument(
        "-t", "--target", 
        nargs="+", 
        help="Target IP(s), CIDR(s), or Domain(s)"
    )
    
    # Operational Modes
    parser.add_argument(
        "--opsec",
        choices=["standard", "stealth", "aggressive"],
        default="standard",
        help="Operational Security / Evasion level"
    )
    
    # Execution Control
    parser.add_argument(
        "--resume",
        help="Resume a previous session by ID"
    )
    
    # Add more args as needed (e.g. --exclude, --phases)

    args = parser.parse_args()

    # Basic Validation
    if not args.target and not args.resume:
        parser.print_help()
        print("\nError: No target specified.")
        sys.exit(1)

    # Initialize and Run
    engine = Orchestrator(args)
    engine.run()

if __name__ == "__main__":
    main()
