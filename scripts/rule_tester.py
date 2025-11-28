#!/usr/bin/env python3
"""
Wazuh Rule Tester - Tests XML rules against synthetic logs
Simulates Wazuh rule matching logic to validate detection rules
"""

import json
import re
import xml.etree.ElementTree as ET
from typing import List, Dict, Any, Optional, Tuple
from dataclasses import dataclass


@dataclass
class TestResult:
    """Result of a single rule test"""
    log_id: str
    rule_id: str
    expected: bool
    matched: bool
    passed: bool
    reason: str


class RuleParser:
    """Parse Wazuh XML rules"""

    def __init__(self, rule_file: str):
        self.rule_file = rule_file
        self.rules: Dict[str, Dict[str, Any]] = {}
        self.parse_rules()

    def parse_rules(self):
        """Parse all rules from XML file"""
        try:
            tree = ET.parse(self.rule_file)
            root = tree.getroot()

            for group in root.findall(".//group"):
                for rule in group.findall("rule"):
                    rule_id = rule.get("id")
                    if rule_id:
                        self.rules[rule_id] = self._extract_rule_details(rule)
        except Exception as e:
            raise ValueError(f"Failed to parse rule file {self.rule_file}: {e}")

    def _extract_rule_details(self, rule_elem: ET.Element) -> Dict[str, Any]:
        """Extract rule matching criteria from XML element"""
        details = {
            "id": rule_elem.get("id"),
            "level": rule_elem.get("level"),
            "description": rule_elem.findtext("description", ""),
            "conditions": []
        }

        # Extract match conditions
        for match in rule_elem.findall("match"):
            details["conditions"].append({
                "type": "match",
                "value": match.text,
                "pattern": match.text
            })

        # Extract field conditions
        for field in rule_elem.findall("field"):
            field_type = field.get("type", "literal")
            details["conditions"].append({
                "type": "field",
                "name": field.get("name"),
                "value": field.text,
                "field_type": field_type
            })

        # Extract if_sid (parent rule dependency)
        if_sid = rule_elem.findtext("if_sid")
        if if_sid:
            details["if_sid"] = if_sid.split(",")

        # Extract group info
        if_group = rule_elem.findtext("if_group")
        if if_group:
            details["if_group"] = if_group

        return details

    def get_rule(self, rule_id: str) -> Optional[Dict[str, Any]]:
        """Get rule details by ID"""
        return self.rules.get(rule_id)

    def list_rules(self) -> List[str]:
        """List all rule IDs"""
        return list(self.rules.keys())


class RuleMatcher:
    """Matches logs against Wazuh rules"""

    def __init__(self, parser: RuleParser):
        self.parser = parser

    def match_log(self, log: Dict[str, Any], rule_id: str) -> Tuple[bool, str]:
        """Check if a log matches a specific rule"""
        rule = self.parser.get_rule(rule_id)
        if not rule:
            return False, f"Rule {rule_id} not found"

        # Check parent rule dependencies
        if "if_sid" in rule:
            for parent_id in rule["if_sid"]:
                parent_rule = self.parser.get_rule(parent_id.strip())
                if not parent_rule:
                    return False, f"Parent rule {parent_id} not found"

        # Check all conditions
        for condition in rule.get("conditions", []):
            matched = self._check_condition(log, condition)
            if not matched:
                return False, f"Condition failed: {condition}"

        return True, "All conditions matched"

    def _check_condition(self, log: Dict[str, Any], condition: Dict[str, Any]) -> bool:
        """Check a single condition against log"""
        if condition["type"] == "match":
            # Simple string match in message/program fields
            message = log.get("message", "") or log.get("fields", {}).get("message", "")
            pattern = condition["pattern"]

            # Support OR conditions (|)
            if "|" in pattern:
                patterns = [p.strip() for p in pattern.split("|")]
                return any(p.lower() in message.lower() for p in patterns)
            else:
                return pattern.lower() in message.lower()

        elif condition["type"] == "field":
            field_name = condition["name"]
            field_value = condition["value"]
            field_type = condition.get("field_type", "literal")

            # Get field value from log
            log_value = self._get_field_value(log, field_name)
            if log_value is None:
                return False

            if field_type == "pcre2":
                # PCRE2 regex matching
                try:
                    # Unescape backslashes for regex
                    pattern = field_value.replace("\\\\", "\\")
                    return bool(re.search(pattern, str(log_value), re.IGNORECASE))
                except re.error:
                    return False
            else:
                # Literal string matching
                return field_value.lower() in str(log_value).lower()

        return False

    def _get_field_value(self, log: Dict[str, Any], field_name: str) -> Optional[str]:
        """Get field value from log using dot notation"""
        fields = log.get("fields", {})

        # Support dot notation for nested fields
        if "." in field_name:
            parts = field_name.split(".")
            current = fields
            for part in parts:
                if isinstance(current, dict):
                    current = current.get(part)
                else:
                    return None
            return current

        return fields.get(field_name)


class RuleTester:
    """Main test runner"""

    def __init__(self, rule_file: str):
        self.parser = RuleParser(rule_file)
        self.matcher = RuleMatcher(self.parser)
        self.results: List[TestResult] = []

    def test_logs(self, logs: List[Dict[str, Any]]) -> List[TestResult]:
        """Test a set of logs against rules"""
        self.results = []

        for log_idx, log in enumerate(logs):
            expected_rule_id = log.get("expected_rule_id")
            if not expected_rule_id:
                continue

            matched, reason = self.matcher.match_log(log, expected_rule_id)

            result = TestResult(
                log_id=f"log_{log_idx}",
                rule_id=expected_rule_id,
                expected=True,
                matched=matched,
                passed=matched,
                reason=reason
            )
            self.results.append(result)

        return self.results

    def print_results(self):
        """Print test results in human-readable format"""
        passed = sum(1 for r in self.results if r.passed)
        failed = len(self.results) - passed

        print(f"\n{'='*80}")
        print(f"RULE TEST RESULTS")
        print(f"{'='*80}")
        print(f"Total Tests: {len(self.results)}")
        print(f"Passed: {passed}")
        print(f"Failed: {failed}")
        print(f"Pass Rate: {100 * passed / len(self.results):.1f}%" if self.results else "N/A")

        if failed > 0:
            print(f"\n{'FAILURES':^80}")
            print(f"{'-'*80}")
            for result in self.results:
                if not result.passed:
                    print(f"Log: {result.log_id}")
                    print(f"  Rule ID: {result.rule_id}")
                    print(f"  Expected: {result.expected}")
                    print(f"  Matched: {result.matched}")
                    print(f"  Reason: {result.reason}")
                    print()

        print(f"\n{'PASSED TESTS':^80}")
        print(f"{'-'*80}")
        for result in self.results:
            if result.passed:
                print(f"✓ Log {result.log_id} -> Rule {result.rule_id}")

    def export_results(self, filename: str):
        """Export test results to JSON"""
        results_data = [
            {
                "log_id": r.log_id,
                "rule_id": r.rule_id,
                "expected": r.expected,
                "matched": r.matched,
                "passed": r.passed,
                "reason": r.reason
            }
            for r in self.results
        ]

        with open(filename, 'w') as f:
            json.dump(results_data, f, indent=2)

        print(f"Results exported to {filename}")


if __name__ == "__main__":
    import sys

    if len(sys.argv) < 3:
        print("Usage: python rule_tester.py <rule_file> <log_file>")
        sys.exit(1)

    rule_file = sys.argv[1]
    log_file = sys.argv[2]

    # Load logs
    with open(log_file, 'r') as f:
        logs = json.load(f)

    # Run tests
    tester = RuleTester(rule_file)
    tester.test_logs(logs)
    tester.print_results()

    # Export results
    output_file = log_file.replace('.json', '_results.json')
    tester.export_results(output_file)
