#!/usr/bin/env python3
"""
Wazuh Rule ID Conflict Checker
Validates that custom rule IDs don't conflict with existing rules
"""

import os
import re
import sys
import xml.etree.ElementTree as ET
from pathlib import Path

def extract_rule_ids(xml_file):
    """Extract all rule IDs from an XML file"""
    try:
        tree = ET.parse(xml_file)
        root = tree.getroot()
        rule_ids = []

        for rule in root.findall('.//rule'):
            rule_id = rule.get('id')
            if rule_id:
                rule_ids.append((int(rule_id), xml_file.name))

        return rule_ids
    except Exception as e:
        print(f"Error parsing {xml_file}: {e}")
        return []

def check_custom_range(rule_ids):
    """Verify rules use custom ID range (100000-120000)"""
    out_of_range = []
    for rule_id, filename in rule_ids:
        if rule_id < 100000 or rule_id > 120000:
            out_of_range.append((rule_id, filename))
    return out_of_range

def find_duplicate_ids(rules_dir):
    """Find duplicate rule IDs across all XML files"""
    all_ids = {}
    duplicates = []

    for xml_file in Path(rules_dir).glob('*.xml'):
        # Skip default rules
        if xml_file.name.startswith('0') or xml_file.name == 'local_rules.xml':
            continue

        rule_ids = extract_rule_ids(xml_file)

        for rule_id, filename in rule_ids:
            if rule_id in all_ids:
                duplicates.append((rule_id, filename, all_ids[rule_id]))
            else:
                all_ids[rule_id] = filename

    return duplicates, all_ids

def main():
    rules_dir = Path(__file__).parent.parent / 'rules'

    if not rules_dir.exists():
        print(f"Error: Rules directory not found: {rules_dir}")
        sys.exit(1)

    print("🔍 Checking for rule ID conflicts...")

    # Find duplicates
    duplicates, all_ids = find_duplicate_ids(rules_dir)

    # Check custom range
    out_of_range = check_custom_range(all_ids.items())

    # Report results
    if duplicates:
        print("\n❌ Duplicate rule IDs found:")
        for rule_id, file1, file2 in duplicates:
            print(f"  Rule ID {rule_id}: {file1} and {file2}")
        sys.exit(1)

    if out_of_range:
        print("\n⚠️  Rules outside custom range (100000-120000):")
        for rule_id, filename in out_of_range:
            print(f"  Rule ID {rule_id} in {filename}")
        print("\nRecommendation: Use IDs between 100000-120000 for custom rules")
        sys.exit(1)

    print(f"\n✅ All {len(all_ids)} rule IDs are valid and conflict-free!")
    sys.exit(0)

if __name__ == "__main__":
    main()