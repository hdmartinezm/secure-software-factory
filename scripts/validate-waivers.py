#!/usr/bin/env python3
"""
EFEX Security Waiver Validator
==============================
Validates security waivers and checks for expiration.

Usage:
    python validate-waivers.py [--check-finding FINDING_ID] [--strict]

Exit codes:
    0 - All waivers valid (or finding is waived)
    1 - Expired waivers found
    2 - Invalid waiver format
    3 - Finding not waived (when --check-finding used)
"""

import os
import sys
import yaml
import argparse
from datetime import datetime, date
from pathlib import Path
from typing import List, Dict, Any, Optional

# Security team members authorized to approve waivers
SECURITY_APPROVERS = [
    "ciso@efex.com",
    "security@efex.com",
    "platform-security@efex.com",
]

# Maximum waiver duration (days)
MAX_WAIVER_DURATION = 90

# Colors for terminal output
RED = "\033[91m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
BLUE = "\033[94m"
RESET = "\033[0m"
BOLD = "\033[1m"


def load_waiver(filepath: Path) -> Optional[Dict[str, Any]]:
    """Load and parse a waiver YAML file."""
    try:
        with open(filepath, 'r') as f:
            return yaml.safe_load(f)
    except yaml.YAMLError as e:
        print(f"{RED}Error parsing {filepath}: {e}{RESET}")
        return None
    except Exception as e:
        print(f"{RED}Error reading {filepath}: {e}{RESET}")
        return None


def validate_waiver(waiver: Dict[str, Any], filepath: Path) -> List[str]:
    """Validate a single waiver and return list of errors."""
    errors = []

    # Required fields
    required_fields = ['id', 'finding_id', 'owner', 'approved_by', 'ticket',
                       'reason', 'risk_accepted', 'expiration', 'created']

    for field in required_fields:
        if field not in waiver or waiver[field] is None:
            errors.append(f"Missing required field: {field}")

    if errors:
        return errors

    # Validate expiration date
    try:
        if isinstance(waiver['expiration'], date):
            expiration = waiver['expiration']
        else:
            expiration = datetime.strptime(str(waiver['expiration']), '%Y-%m-%d').date()

        if expiration < date.today():
            days_expired = (date.today() - expiration).days
            errors.append(f"EXPIRED: Waiver expired {days_expired} days ago (on {expiration})")
    except ValueError as e:
        errors.append(f"Invalid expiration date format: {waiver['expiration']} (use YYYY-MM-DD)")

    # Validate created date
    try:
        if isinstance(waiver['created'], date):
            created = waiver['created']
        else:
            created = datetime.strptime(str(waiver['created']), '%Y-%m-%d').date()
    except ValueError:
        errors.append(f"Invalid created date format: {waiver['created']} (use YYYY-MM-DD)")

    # Validate approver
    if waiver['approved_by'] not in SECURITY_APPROVERS:
        errors.append(f"Invalid approver: {waiver['approved_by']} (not in authorized approvers list)")

    # Validate risk_accepted is explicitly true
    if waiver['risk_accepted'] is not True:
        errors.append("risk_accepted must be explicitly set to true")

    # Validate ticket format (basic check)
    if not waiver['ticket'] or len(str(waiver['ticket'])) < 3:
        errors.append("ticket must reference a valid tracking issue")

    # Validate reason is not empty
    if not waiver['reason'] or len(str(waiver['reason']).strip()) < 10:
        errors.append("reason must provide a detailed justification")

    return errors


def check_waiver_for_finding(waivers_dir: Path, finding_id: str) -> Dict[str, Any]:
    """Check if a specific finding has a valid waiver."""
    result = {
        'waived': False,
        'waiver': None,
        'errors': [],
        'expired': False
    }

    for filepath in waivers_dir.glob('*.yaml'):
        if filepath.name.startswith('_'):
            continue

        waiver = load_waiver(filepath)
        if not waiver:
            continue

        if waiver.get('finding_id') == finding_id:
            errors = validate_waiver(waiver, filepath)

            if not errors:
                result['waived'] = True
                result['waiver'] = waiver
                return result
            else:
                # Check if it's just expired vs other errors
                expired_errors = [e for e in errors if 'EXPIRED' in e]
                other_errors = [e for e in errors if 'EXPIRED' not in e]

                if expired_errors and not other_errors:
                    result['expired'] = True
                    result['waiver'] = waiver
                    result['errors'] = expired_errors
                else:
                    result['errors'] = errors

                return result

    return result


def validate_all_waivers(waivers_dir: Path, strict: bool = False) -> int:
    """Validate all waivers in directory."""
    print(f"\n{BOLD}EFEX Security Waiver Validation{RESET}")
    print("=" * 50)

    total = 0
    valid = 0
    expired = 0
    invalid = 0

    for filepath in sorted(waivers_dir.glob('*.yaml')):
        # Skip template and README
        if filepath.name.startswith('_') or filepath.name == 'README.md':
            continue

        total += 1
        waiver = load_waiver(filepath)

        if not waiver:
            invalid += 1
            continue

        errors = validate_waiver(waiver, filepath)
        waiver_id = waiver.get('id', 'UNKNOWN')
        finding_id = waiver.get('finding_id', 'UNKNOWN')

        if errors:
            is_expired = any('EXPIRED' in e for e in errors)

            if is_expired:
                expired += 1
                print(f"\n{YELLOW}[EXPIRED]{RESET} {filepath.name}")
                print(f"  Waiver ID: {waiver_id}")
                print(f"  Finding:   {finding_id}")
                print(f"  Owner:     {waiver.get('owner', 'N/A')}")
                for error in errors:
                    print(f"  {RED}! {error}{RESET}")
            else:
                invalid += 1
                print(f"\n{RED}[INVALID]{RESET} {filepath.name}")
                print(f"  Waiver ID: {waiver_id}")
                for error in errors:
                    print(f"  {RED}! {error}{RESET}")
        else:
            valid += 1
            expiration = waiver.get('expiration', 'N/A')
            days_left = (datetime.strptime(str(expiration), '%Y-%m-%d').date() - date.today()).days

            print(f"\n{GREEN}[VALID]{RESET} {filepath.name}")
            print(f"  Waiver ID: {waiver_id}")
            print(f"  Finding:   {finding_id}")
            print(f"  Owner:     {waiver.get('owner', 'N/A')}")
            print(f"  Expires:   {expiration} ({days_left} days remaining)")

            # Warn if expiring soon
            if days_left <= 14:
                print(f"  {YELLOW}! Expires in {days_left} days - consider renewal{RESET}")

    # Summary
    print("\n" + "=" * 50)
    print(f"{BOLD}Summary:{RESET}")
    print(f"  Total waivers:   {total}")
    print(f"  {GREEN}Valid:           {valid}{RESET}")
    print(f"  {YELLOW}Expired:         {expired}{RESET}")
    print(f"  {RED}Invalid:         {invalid}{RESET}")

    # Determine exit code
    if invalid > 0:
        print(f"\n{RED}{BOLD}FAILED: {invalid} invalid waiver(s) found{RESET}")
        return 2
    elif expired > 0:
        if strict:
            print(f"\n{RED}{BOLD}FAILED: {expired} expired waiver(s) found (strict mode){RESET}")
            return 1
        else:
            print(f"\n{YELLOW}{BOLD}WARNING: {expired} expired waiver(s) found{RESET}")
            return 0
    else:
        print(f"\n{GREEN}{BOLD}PASSED: All waivers valid{RESET}")
        return 0


def main():
    parser = argparse.ArgumentParser(
        description='EFEX Security Waiver Validator',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Validate all waivers
  python validate-waivers.py

  # Check if a specific finding is waived
  python validate-waivers.py --check-finding CKV_AWS_144

  # Strict mode (fail on expired waivers)
  python validate-waivers.py --strict

  # Custom waivers directory
  python validate-waivers.py --waivers-dir /path/to/waivers
        """
    )

    parser.add_argument(
        '--waivers-dir',
        type=Path,
        default=Path(__file__).parent.parent / 'waivers',
        help='Directory containing waiver YAML files'
    )

    parser.add_argument(
        '--check-finding',
        type=str,
        help='Check if a specific finding ID is waived'
    )

    parser.add_argument(
        '--strict',
        action='store_true',
        help='Fail on expired waivers (not just invalid)'
    )

    parser.add_argument(
        '--output-json',
        action='store_true',
        help='Output results as JSON'
    )

    args = parser.parse_args()

    if not args.waivers_dir.exists():
        print(f"{RED}Error: Waivers directory not found: {args.waivers_dir}{RESET}")
        sys.exit(2)

    if args.check_finding:
        # Check specific finding
        result = check_waiver_for_finding(args.waivers_dir, args.check_finding)

        if args.output_json:
            import json
            print(json.dumps(result, default=str))
        else:
            if result['waived']:
                waiver = result['waiver']
                print(f"{GREEN}[WAIVED]{RESET} {args.check_finding}")
                print(f"  Waiver ID: {waiver['id']}")
                print(f"  Owner:     {waiver['owner']}")
                print(f"  Reason:    {waiver['reason'][:100]}...")
                print(f"  Expires:   {waiver['expiration']}")
                sys.exit(0)
            elif result['expired']:
                print(f"{YELLOW}[EXPIRED]{RESET} Waiver for {args.check_finding} has expired")
                for error in result['errors']:
                    print(f"  {RED}! {error}{RESET}")
                sys.exit(1)
            else:
                print(f"{RED}[NOT WAIVED]{RESET} No valid waiver found for {args.check_finding}")
                if result['errors']:
                    for error in result['errors']:
                        print(f"  {RED}! {error}{RESET}")
                sys.exit(3)
    else:
        # Validate all waivers
        exit_code = validate_all_waivers(args.waivers_dir, args.strict)
        sys.exit(exit_code)


if __name__ == '__main__':
    main()
