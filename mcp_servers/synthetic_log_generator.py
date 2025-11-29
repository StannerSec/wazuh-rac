#!/usr/bin/env python3
"""
Synthetic Log Generator MCP Server

Generates synthetic logs for Wazuh rule testing based on:
- Dynamic threat intelligence from other MCP servers
- Wazuh rule definitions
- Custom field specifications

This server enables automated rule testing and validation by creating
realistic log data that should (or should not) trigger specific rules.
"""

import json
import re
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple
import sys

# MCP SDK imports
try:
    from mcp.server.fastmcp import FastMCP
except ImportError as e:
    print(f"Error: MCP SDK not installed. Install with: pip install mcp", file=sys.stderr)
    print(f"Details: {str(e)}", file=sys.stderr)
    sys.exit(1)


class RuleParser:
    """Parse and extract information from Wazuh XML rules"""

    @staticmethod
    def parse_rule_xml(rule_xml: str) -> Dict[str, Any]:
        """Parse a Wazuh rule XML string and extract key information"""
        try:
            root = ET.fromstring(rule_xml)

            # Extract rule elements
            rule_id = root.get("id")
            level = root.get("level")
            description = root.findtext("description", "")

            # Extract conditions
            conditions = []
            for match in root.findall("match"):
                conditions.append({
                    "type": "match",
                    "value": match.text,
                })

            for field in root.findall("field"):
                conditions.append({
                    "type": "field",
                    "name": field.get("name"),
                    "value": field.text,
                    "field_type": field.get("type", "literal"),
                })

            # Extract parent rule dependencies
            if_sid = root.findtext("if_sid")
            if_group = root.findtext("if_group")

            return {
                "rule_id": rule_id,
                "level": level,
                "description": description,
                "conditions": conditions,
                "if_sid": if_sid,
                "if_group": if_group,
            }
        except Exception as e:
            return {"error": f"Failed to parse rule XML: {str(e)}"}

    @staticmethod
    def generate_logs_from_rule(rule_info: Dict[str, Any], count: int = 1) -> List[Dict[str, Any]]:
        """Generate synthetic logs that would match a rule"""
        if "error" in rule_info:
            return []

        logs = []
        for _ in range(count):
            log = {
                "timestamp": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
                "expected_rule_id": rule_info.get("rule_id"),
                "description": rule_info.get("description"),
                "type": "generated_from_rule",
                "fields": RuleParser._generate_fields_from_conditions(
                    rule_info.get("conditions", [])
                ),
            }
            logs.append(log)

        return logs

    @staticmethod
    def _generate_fields_from_conditions(conditions: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Generate field values that would match rule conditions"""
        fields = {"program": "generated"}

        for condition in conditions:
            if condition["type"] == "match":
                # For match conditions, put the pattern in a generic message field
                fields["message"] = condition.get("value", "")

            elif condition["type"] == "field":
                # For field conditions, use the field name and value
                field_name = condition.get("name", "unknown")
                field_value = condition.get("value", "")

                # Handle regex patterns - use a simplified version
                if condition.get("field_type") == "pcre2":
                    # Extract a simple pattern that might match the regex
                    field_value = RuleParser._simplify_regex(field_value)

                fields[field_name] = field_value

        return fields

    @staticmethod
    def _simplify_regex(pattern: str) -> str:
        """Simplify a PCRE2 regex to a sample matching string"""
        # Remove common regex patterns to get a sample string
        sample = pattern
        sample = re.sub(r"\\\\", "\\", sample)  # Unescape backslashes
        sample = re.sub(r"\([^)]*\|[^)]*\)", "sample", sample)  # Handle alternation
        sample = re.sub(r"[+*?{}()\[\]^$|]", "", sample)  # Remove regex operators
        return sample.strip() or "sample_match"


class SyntheticLogGenerator:
    """Main log generation engine"""

    def __init__(self):
        self.threat_cache: Dict[str, Dict[str, Any]] = {}

    def generate_from_threat_intel(self, threat_intel: Dict[str, Any], count: int = 1) -> Tuple[List[Dict[str, Any]], str]:
        """Generate logs based on threat intelligence data

        Args:
            threat_intel: Dictionary containing threat information with keys:
                - name: Threat/malware name
                - techniques: List of MITRE ATT&CK technique IDs
                - iocs: Dict of IOC types and values
                - description: Threat description
                - log_patterns: Optional list of log templates
            count: Number of log sets to generate

        Returns:
            Tuple of (logs list, status message)
        """
        if not threat_intel or "name" not in threat_intel:
            return [], "Invalid threat intelligence data"

        threat_name = threat_intel.get("name")
        logs = []

        # Generate logs based on threat intel
        log_patterns = threat_intel.get("log_patterns", [])

        if log_patterns:
            # Use provided patterns
            for pattern in log_patterns:
                for _ in range(count):
                    log = {
                        "timestamp": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
                        "threat": threat_name,
                        "technique": pattern.get("technique"),
                        "expected_rule_id": pattern.get("rule_id"),
                        "type": pattern.get("type", "unknown"),
                        "fields": pattern.get("fields", {}).copy(),
                    }
                    logs.append(log)
        else:
            # Generate generic logs from threat intel
            for _ in range(count):
                log = {
                    "timestamp": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
                    "threat": threat_name,
                    "techniques": threat_intel.get("techniques", []),
                    "type": "threat_based",
                    "description": threat_intel.get("description"),
                    "fields": {
                        "program": "generated",
                        "threat_name": threat_name,
                        "threat_description": threat_intel.get("description", ""),
                    }
                }
                logs.append(log)

        return logs, f"Generated {len(logs)} logs for threat: {threat_name}"

    def generate_from_rule(self, rule_xml: str, count: int = 1) -> Tuple[List[Dict[str, Any]], str]:
        """Generate logs that would match a Wazuh rule"""
        rule_info = RuleParser.parse_rule_xml(rule_xml)

        if "error" in rule_info:
            return [], rule_info["error"]

        logs = RuleParser.generate_logs_from_rule(rule_info, count)
        return logs, f"Generated {len(logs)} logs matching rule {rule_info.get('rule_id')}"

    def generate_custom(self, fields: Dict[str, str], rule_id: Optional[str] = None,
                       count: int = 1) -> Tuple[List[Dict[str, Any]], str]:
        """Generate custom logs with specified fields"""
        logs = []
        for _ in range(count):
            log = {
                "timestamp": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
                "expected_rule_id": rule_id,
                "type": "custom",
                "fields": fields.copy(),
            }
            logs.append(log)

        return logs, f"Generated {len(logs)} custom logs"

    def validate_logs_against_rule(self, logs: List[Dict[str, Any]], rule_xml: str) -> Tuple[Dict[str, Any], str]:
        """Validate if logs would match a rule"""
        rule_info = RuleParser.parse_rule_xml(rule_xml)

        if "error" in rule_info:
            return {}, rule_info["error"]

        results = {
            "rule_id": rule_info.get("rule_id"),
            "rule_description": rule_info.get("description"),
            "total_logs": len(logs),
            "matched": 0,
            "failed": 0,
            "details": [],
        }

        for log_idx, log in enumerate(logs):
            # Simple matching: check if expected_rule_id matches
            if log.get("expected_rule_id") == rule_info.get("rule_id"):
                results["matched"] += 1
                results["details"].append({
                    "log_id": log_idx,
                    "status": "matched",
                    "rule_id": rule_info.get("rule_id"),
                })
            else:
                results["failed"] += 1
                results["details"].append({
                    "log_id": log_idx,
                    "status": "not_matched",
                    "expected": log.get("expected_rule_id"),
                    "actual": rule_info.get("rule_id"),
                })

        results["match_rate"] = (results["matched"] / results["total_logs"] * 100) if results["total_logs"] > 0 else 0

        return results, f"Validation complete: {results['matched']}/{results['total_logs']} logs matched"


# Initialize MCP Server
mcp = FastMCP("synthetic-log-generator")
generator = SyntheticLogGenerator()


# MCP Tool Definitions
@mcp.tool()
def generate_logs_from_threat_intel(
    threat_intel: dict,
    count: int = 1,
) -> dict:
    """Generate synthetic logs based on threat intelligence data (from MCP servers like threat-intel-researcher)"""
    try:
        logs, message = generator.generate_from_threat_intel(threat_intel, count)
        return {
            "message": message,
            "logs_count": len(logs),
            "logs": logs,
        }
    except Exception as e:
        return {"error": f"Error: {str(e)}"}


@mcp.tool()
def generate_logs_from_rule(
    rule_xml: str,
    count: int = 1,
) -> dict:
    """Generate synthetic logs that would match a Wazuh detection rule"""
    try:
        logs, message = generator.generate_from_rule(rule_xml, count)
        return {
            "message": message,
            "logs_count": len(logs),
            "logs": logs,
        }
    except Exception as e:
        return {"error": f"Error: {str(e)}"}


@mcp.tool()
def generate_custom_logs(
    fields: dict,
    rule_id: str = None,
    count: int = 1,
) -> dict:
    """Generate custom synthetic logs with specified field values"""
    try:
        logs, message = generator.generate_custom(fields, rule_id, count)
        return {
            "message": message,
            "logs_count": len(logs),
            "logs": logs,
        }
    except Exception as e:
        return {"error": f"Error: {str(e)}"}


@mcp.tool()
def validate_logs_against_rule(
    logs: list,
    rule_xml: str,
) -> dict:
    """Validate whether generated logs match a Wazuh rule"""
    try:
        results, message = generator.validate_logs_against_rule(logs, rule_xml)
        return {
            "message": message,
            "results": results,
        }
    except Exception as e:
        return {"error": f"Error: {str(e)}"}


if __name__ == "__main__":
    # Run the MCP server
    mcp.run(transport='stdio')
