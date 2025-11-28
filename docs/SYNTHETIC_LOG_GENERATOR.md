# Synthetic Log Generator MCP Server

## Overview

The `synthetic-log-generator` is an MCP server that generates synthetic logs for testing Wazuh detection rules. It integrates with other MCP servers (like threat intelligence providers) to create realistic test data based on actual threat intelligence.

## Architecture

```
Detection Engineer Agent
        ↓
Calls MCP Tools on synthetic-log-generator
        ↓
[Generate from threat intel] ← Fetches from threat-intel-researcher MCP
[Generate from rule]         ← Parses Wazuh XML rules
[Generate custom logs]       ← Custom field specifications
[Validate against rules]     ← Tests log/rule matching
```

## Installation

### 1. Ensure MCP SDK is installed

```bash
pip install mcp
```

### 2. Make the server executable

```bash
chmod +x /home/stanner/wazuh-rac/mcp_servers/synthetic_log_generator.py
```

### 3. Register with Claude Code

In your Claude Code configuration file (`~/.claude/claude.json` or project `.claude/claude.json`):

```json
{
  "mcpServers": {
    "synthetic-log-generator": {
      "command": "python3",
      "args": ["/home/stanner/wazuh-rac/mcp_servers/synthetic_log_generator.py"]
    }
  }
}
```

## Tools

### 1. `generate_logs_from_threat_intel`

Generate synthetic logs based on threat intelligence data.

**Input:**
```json
{
  "threat_intel": {
    "name": "DeerStealer",
    "description": "Malware that steals credentials",
    "techniques": ["T1543", "T1105", "T1059"],
    "iocs": {
      "filenames": ["skotes.exe"],
      "paths": ["AppData\\Local\\Temp"]
    },
    "log_patterns": [
      {
        "rule_id": "111203",
        "type": "process_creation",
        "technique": "T1543",
        "fields": {
          "program": "WinEventLog",
          "win.eventdata.commandLine": "C:\\Users\\admin\\AppData\\Local\\Temp\\skotes.exe"
        }
      }
    ]
  },
  "count": 1
}
```

**Output:**
```json
{
  "message": "Generated 1 logs for threat: DeerStealer",
  "logs_count": 1,
  "logs": [
    {
      "timestamp": "2024-11-28T10:30:45Z",
      "threat": "DeerStealer",
      "technique": "T1543",
      "expected_rule_id": "111203",
      "type": "process_creation",
      "fields": {
        "program": "WinEventLog",
        "win.eventdata.commandLine": "C:\\Users\\admin\\AppData\\Local\\Temp\\skotes.exe"
      }
    }
  ]
}
```

### 2. `generate_logs_from_rule`

Parse a Wazuh rule and generate logs that would match it.

**Input:**
```json
{
  "rule_xml": "<rule id=\"100100\" level=\"10\"><match>Failed password</match><description>SSH brute force</description></rule>",
  "count": 1
}
```

**Output:**
```json
{
  "message": "Generated 1 logs matching rule 100100",
  "logs_count": 1,
  "logs": [
    {
      "timestamp": "2024-11-28T10:30:45Z",
      "expected_rule_id": "100100",
      "description": "SSH brute force",
      "type": "generated_from_rule",
      "fields": {
        "program": "generated",
        "message": "Failed password"
      }
    }
  ]
}
```

### 3. `generate_custom_logs`

Generate logs with custom field values.

**Input:**
```json
{
  "fields": {
    "program": "sshd",
    "srcip": "203.0.113.100",
    "message": "Failed password for invalid user admin"
  },
  "rule_id": "100100",
  "count": 1
}
```

**Output:**
```json
{
  "message": "Generated 1 custom logs",
  "logs_count": 1,
  "logs": [
    {
      "timestamp": "2024-11-28T10:30:45Z",
      "expected_rule_id": "100100",
      "type": "custom",
      "fields": {
        "program": "sshd",
        "srcip": "203.0.113.100",
        "message": "Failed password for invalid user admin"
      }
    }
  ]
}
```

### 4. `validate_logs_against_rule`

Test if generated logs match a Wazuh rule.

**Input:**
```json
{
  "logs": [
    {
      "expected_rule_id": "100100",
      "fields": {
        "program": "sshd",
        "message": "Failed password for invalid user admin"
      }
    }
  ],
  "rule_xml": "<rule id=\"100100\" level=\"10\"><match>Failed password</match></rule>"
}
```

**Output:**
```json
{
  "message": "Validation complete: 1/1 logs matched",
  "results": {
    "rule_id": "100100",
    "rule_description": "SSH brute force",
    "total_logs": 1,
    "matched": 1,
    "failed": 0,
    "match_rate": 100.0,
    "details": [
      {
        "log_id": 0,
        "status": "matched",
        "rule_id": "100100"
      }
    ]
  }
}
```

## Workflow Example

### Detection Engineer Agent Workflow

1. **Research threat intelligence**
   - Agent uses threat-intel-researcher MCP to fetch information about DeerStealer malware
   - Gets IOCs, techniques, and behavior information

2. **Create detection rules**
   - Agent writes Wazuh XML detection rules based on threat intel
   - Rules target specific behaviors from the threat intel

3. **Generate test data**
   - Agent calls `generate_logs_from_threat_intel` with fetched threat intel
   - Server generates synthetic logs matching the threat's behavior

4. **Validate rules**
   - Agent calls `validate_logs_against_rule` with generated logs
   - Tests whether rules fire correctly on the synthetic data

5. **Iterate**
   - If validation fails, agent refines rules and repeats
   - Once validation passes, rules are ready for deployment

## Integration with Other MCP Servers

The synthetic-log-generator is designed to work with:

- **threat-intel-researcher**: Fetches threat intelligence data
- **wazuh-rule-validator**: Validates rule syntax and structure
- **detection-rule-deployer**: Deploys tested rules to Wazuh

## Running Tests

To manually test the server:

```bash
# Test with sample threat intel
python3 /home/stanner/wazuh-rac/mcp_servers/synthetic_log_generator.py
```

## Log Format

Generated logs follow this structure:

```python
{
    "timestamp": "ISO8601 UTC timestamp",
    "threat": "threat name (if from threat intel)",
    "technique": "MITRE ATT&CK technique ID",
    "expected_rule_id": "Wazuh rule ID that should match",
    "type": "log type (process_creation, file_creation, etc)",
    "description": "Human readable description",
    "fields": {
        "field_name": "field_value",
        # ... other fields
    }
}
```

## Field Mapping

The server translates between different log types:

- **Windows Event Logs**: `win.eventdata.* ` fields
- **Syslog**: `program`, `message`, `srcip`, `dstip` fields
- **Custom**: Any arbitrary key-value pairs

## Future Enhancements

- [ ] Integration with actual Wazuh API for live rule testing
- [ ] Support for more complex rule matching logic (parent rules, correlations)
- [ ] Persistence of generated logs to disk for analysis
- [ ] Log replay capability for performance testing
- [ ] Statistics and coverage reporting for rule sets
