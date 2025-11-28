# MCP Server Setup Guide

## Overview

This project uses MCP (Model Context Protocol) servers to provide specialized capabilities:

- **synthetic-log-generator**: Generates test logs for rule validation
- **threat-intel-researcher**: (External) Fetches threat intelligence from web sources
- **wazuh-threat-detection-engineer**: (Custom Agent) Creates and tests detection rules

## Setting Up the Synthetic Log Generator

### Step 1: Install Dependencies

```bash
cd /home/stanner/wazuh-rac
pip install mcp
```

### Step 2: Register the MCP Server

You have two options:

#### Option A: Global Configuration (Home Directory)

Create or edit `~/.claude/claude.json`:

```json
{
  "mcpServers": {
    "synthetic-log-generator": {
      "command": "python3",
      "args": ["/home/stanner/wazuh-rac/mcp_servers/synthetic_log_generator.py"],
      "disabled": false
    }
  }
}
```

#### Option B: Project Configuration (Recommended)

Create `.claude/claude.json` in the project root:

```json
{
  "mcpServers": {
    "synthetic-log-generator": {
      "command": "python3",
      "args": ["/home/stanner/wazuh-rac/mcp_servers/synthetic_log_generator.py"],
      "disabled": false
    }
  }
}
```

### Step 3: Verify Installation

Reload Claude Code or restart your terminal:

```bash
cd /home/stanner/wazuh-rac
```

The `synthetic-log-generator` MCP server should now be available to agents and Claude Code.

## Creating a Detection Engineer Agent

The detection engineer agent is an autonomous AI agent that:

1. Researches threat intelligence
2. Creates Wazuh detection rules
3. Generates test logs using the synthetic-log-generator
4. Validates rules against logs
5. Iterates until rules are optimal

### Using the Task Tool

```bash
# Create a new detection engineer agent
claude-code --task "Create detection rules for DeerStealer malware"
```

This will spawn an agent with access to:
- `threat-intel-researcher`: Research threats and techniques
- `synthetic-log-generator`: Generate test logs
- `wazuh-rule-validator`: Validate XML syntax
- File tools: Create and edit rule files

## Architecture Diagram

```
┌─────────────────────────────────────────┐
│  Detection Engineer Agent (AI)          │
│  - Research threats                     │
│  - Create/edit rules                    │
│  - Test and validate                    │
│  - Iterate until passing                │
└──────────┬──────────────────────────────┘
           │
     ┌─────┴──────────────────────┬───────────────┐
     │                            │               │
     ▼                            ▼               ▼
┌──────────────────────┐  ┌──────────────────┐  ┌─────────────────┐
│ threat-intel-        │  │ synthetic-log-   │  │ wazuh-rule-     │
│ researcher MCP       │  │ generator MCP    │  │ validator MCP   │
│                      │  │                  │  │                 │
│ - Fetch threat info  │  │ - Generate logs  │  │ - Validate XML  │
│ - Get IOCs           │  │ - From threat    │  │ - Check syntax  │
│ - Get techniques     │  │ - From rules     │  │ - Lint rules    │
│ - Search web         │  │ - From custom    │  │                 │
│                      │  │ - Validate match │  │                 │
└──────────────────────┘  └──────────────────┘  └─────────────────┘
     │                            │
     └────────────────┬───────────┘
                      │
                      ▼
            ┌──────────────────────┐
            │  Wazuh Rules         │
            │  (XML Files)         │
            │  - rules/            │
            │  - decoders/         │
            └──────────────────────┘
```

## Workflow: Rule Development

### 1. Start the Detection Engineer

```bash
cd /home/stanner/wazuh-rac
claude-code --task "Create and test detection rules for DeerStealer malware"
```

### 2. The Agent Will:

**Phase 1: Research**
- Calls `threat-intel-researcher` to fetch info about DeerStealer
- Identifies techniques, IOCs, and behaviors

**Phase 2: Rule Creation**
- Writes Wazuh XML rules based on threat intel
- Places rules in `rules/` directory

**Phase 3: Test Data Generation**
- Calls `synthetic-log-generator:generate_logs_from_threat_intel`
- Passes the threat intel from phase 1
- Receives synthetic logs matching the threat

**Phase 4: Validation**
- Calls `synthetic-log-generator:validate_logs_against_rule`
- Tests if generated logs match the rules
- Reports pass/fail status

**Phase 5: Iteration**
- If validation fails:
  - Agent refines the rule XML
  - Regenerates logs
  - Re-validates
  - Repeats until passing
- Once passing: Rules are ready for deployment

### 3. Manual Verification

After the agent completes:

```bash
# View created rules
cat rules/your_rule_name.xml

# View test logs
cat /tmp/logs_*.json

# View test results
cat /tmp/logs_*_results.json
```

## Testing the MCP Server Manually

### Test Threat Intel Log Generation

```bash
python3 << 'EOF'
import json
import sys
sys.path.insert(0, '/home/stanner/wazuh-rac/mcp_servers')
from synthetic_log_generator import generator

threat_intel = {
    "name": "TestMalware",
    "description": "Test malware",
    "techniques": ["T1543"],
    "iocs": {"filenames": ["test.exe"]},
    "log_patterns": [
        {
            "rule_id": "999999",
            "type": "process_creation",
            "technique": "T1543",
            "fields": {"program": "test", "message": "test execution"}
        }
    ]
}

logs, message = generator.generate_from_threat_intel(threat_intel, 1)
print(json.dumps(logs, indent=2))
EOF
```

### Test Rule-Based Log Generation

```bash
python3 << 'EOF'
import json
import sys
sys.path.insert(0, '/home/stanner/wazuh-rac/mcp_servers')
from synthetic_log_generator import generator

rule_xml = '<rule id="100100" level="5"><match>test pattern</match></rule>'
logs, message = generator.generate_from_rule(rule_xml, 1)
print(json.dumps(logs, indent=2))
EOF
```

## Troubleshooting

### MCP Server Not Found

**Problem**: "synthetic-log-generator MCP server not found"

**Solution**:
1. Verify `~/.claude/claude.json` exists and contains the server config
2. Check file path is correct: `/home/stanner/wazuh-rac/mcp_servers/synthetic_log_generator.py`
3. Verify Python 3 is installed: `python3 --version`
4. Verify MCP SDK is installed: `pip list | grep mcp`
5. Restart Claude Code completely

### Import Errors

**Problem**: "ModuleNotFoundError: No module named 'mcp'"

**Solution**:
```bash
pip install --upgrade mcp
```

### Permission Denied

**Problem**: "Permission denied: synthetic_log_generator.py"

**Solution**:
```bash
chmod +x /home/stanner/wazuh-rac/mcp_servers/synthetic_log_generator.py
```

## Next Steps

1. ✅ Set up synthetic-log-generator MCP server
2. ⏳ Create detection engineer agent prompt
3. ⏳ Integrate with threat intelligence sources
4. ⏳ Develop and test detection rules
5. ⏳ Deploy rules to Wazuh

## References

- [MCP Protocol Documentation](https://github.com/anthropics/model-context-protocol)
- [Wazuh Detection Rules Guide](https://documentation.wazuh.com/current/user-manual/ruleset/)
- [MITRE ATT&CK Framework](https://attack.mitre.org/)
