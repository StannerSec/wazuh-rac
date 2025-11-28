# Wazuh Detection Rule Development Architecture

## Overview

This document describes the architecture for automated detection rule development, testing, and deployment using AI agents and MCP servers.

## System Components

### 1. Synthetic Log Generator MCP Server
**File**: `/home/stanner/wazuh-rac/mcp_servers/synthetic_log_generator.py`

**Purpose**: Generate realistic synthetic logs for testing detection rules

**Tools Provided**:
- `generate_logs_from_threat_intel` - Create logs based on threat intelligence
- `generate_logs_from_rule` - Generate logs that match a specific rule
- `generate_custom_logs` - Generate arbitrary logs with custom fields
- `validate_logs_against_rule` - Test if logs match a rule

**Inputs**:
- Threat intelligence data (from threat-intel-researcher MCP)
- Wazuh rule XML
- Custom field specifications

**Outputs**:
- Synthetic log data in JSON format
- Validation results showing pass/fail status

### 2. Detection Engineer Agent
**Type**: AI Agent spawned with `claude-code --task "..."`

**Capabilities**:
- Research threat intelligence (via threat-intel-researcher MCP)
- Create Wazuh detection rules (XML files)
- Generate test logs (via synthetic-log-generator MCP)
- Validate rules (via wazuh-rule-validator MCP)
- Iterate and refine rules
- Deploy validated rules

**Workflow**:
```
Research Threat → Create Rule → Generate Logs → Validate → Deploy
                                      ↑
                                   Iterate if failed
```

### 3. Wazuh Rules
**Location**: `/home/stanner/wazuh-rac/rules/`

**Types**:
- Custom SSH rules (`100000_custom_ssh_rules.xml`)
- DeerStealer malware rules (`deerstealer.xml`)
- Test rules (`test-rules.xml`)

**Structure**:
- Rule ID (unique identifier)
- Level (severity)
- Conditions (match, field-based)
- Description
- MITRE ATT&CK mapping
- Groups and classifications

## Data Flow

```
┌─────────────────────────────────────────────────────┐
│ Detection Engineer Agent                            │
│ (AI - Autonomous or Human-Guided)                   │
└──────────────┬──────────────────────────────────────┘
               │
               ├─→ threat-intel-researcher MCP
               │   ├─ Research malware/IOCs
               │   └─ Get techniques, behaviors
               │
               ├─→ synthetic-log-generator MCP
               │   ├─ Generate test logs
               │   ├─ Validate against rules
               │   └─ Return test results
               │
               └─→ File Operations
                   ├─ Create rule files
                   ├─ Store generated logs
                   └─ Document results
```

## Process Steps

### Step 1: Threat Intelligence Research
```
Input: Malware name (e.g., "DeerStealer")
│
├─ Call: threat-intel-researcher MCP
├─ Research: Behaviors, IOCs, techniques
└─ Output: Structured threat intelligence
   {
     "name": "DeerStealer",
     "description": "...",
     "techniques": ["T1543", "T1105", ...],
     "iocs": {"filenames": [...], "paths": [...]},
     "log_patterns": [...]
   }
```

### Step 2: Rule Creation
```
Input: Threat intelligence
│
├─ Create XML rule file
│  └─ Define conditions to detect threat
├─ Assign rule ID (100000+ range)
├─ Map to MITRE ATT&CK techniques
└─ Output: Wazuh rule XML file
```

### Step 3: Test Log Generation
```
Input: Threat intelligence + Rule XML
│
├─ Call: synthetic-log-generator MCP
│  ├─ Parse rule conditions
│  ├─ Generate matching logs
│  └─ Return synthetic logs
└─ Output: JSON logs that should trigger rule
```

### Step 4: Rule Validation
```
Input: Generated logs + Rule XML
│
├─ Call: synthetic-log-generator MCP
│  ├─ validate_logs_against_rule
│  ├─ Test matching logic
│  └─ Report results
│
├─ If Pass:
│  └─ Mark rule as validated
│
└─ If Fail:
   ├─ Analyze failure
   ├─ Refine rule
   ├─ Regenerate logs
   └─ Revalidate
```

### Step 5: Deployment
```
Input: Validated rules
│
├─ Run: ./scripts/validate.sh
│  ├─ XML syntax check
│  └─ Rule ID uniqueness
├─ Run: ./scripts/deploy.sh
│  └─ Deploy to Wazuh
└─ Output: Rules active in Wazuh
```

## Rule Development Workflow Examples

### Example 1: Create DeerStealer Rules

```bash
claude-code --task "Create and test Wazuh detection rules for DeerStealer malware. Research the malware, identify attack techniques, create rules to detect each technique, generate synthetic logs, and validate the rules work correctly."
```

**Agent actions**:
1. Calls threat-intel-researcher to research DeerStealer
2. Identifies techniques: T1543, T1105, T1059, T1547
3. Creates rule files for each technique
4. For each rule:
   - Generates synthetic logs via synthetic-log-generator
   - Validates logs match the rule
   - Refines rule if validation fails
5. Once all rules pass validation, prepares for deployment

### Example 2: Create SSH Brute Force Rules

```bash
claude-code --task "Create detection rules for SSH brute force attacks. Define rules for failed login attempts, multiple failures from same source, and successful login after failures."
```

**Agent actions**:
1. Researches SSH brute force (T1110.001, T1078)
2. Creates rules in `rules/100000_custom_ssh_rules.xml`
3. Generates synthetic logs with:
   - Multiple failed SSH login attempts
   - Successful login after failures
4. Validates rules catch the attack pattern
5. Iterates until all patterns detected

## MCP Server Integration

### Accessing the Synthetic Log Generator

From any agent or Claude Code task:

```python
# Generate logs from threat intel
response = mcp.call_tool("synthetic-log-generator", "generate_logs_from_threat_intel", {
    "threat_intel": {
        "name": "DeerStealer",
        "description": "...",
        "techniques": ["T1543"],
        "iocs": {...}
    },
    "count": 5
})

# Validate logs against rule
response = mcp.call_tool("synthetic-log-generator", "validate_logs_against_rule", {
    "logs": generated_logs,
    "rule_xml": rule_xml_string
})
```

## Key Files

```
/home/stanner/wazuh-rac/
├── mcp_servers/
│   └── synthetic_log_generator.py    ← MCP Server (log generation)
├── rules/
│   ├── 100000_custom_ssh_rules.xml
│   ├── deerstealer.xml
│   └── test-rules.xml
├── decoders/
│   └── [custom decoders]
├── scripts/
│   ├── validate.sh                    ← Validate rule syntax
│   ├── deploy.sh                      ← Deploy to Wazuh
│   └── check_rule_ids.py
├── docs/
│   ├── ARCHITECTURE.md               ← This file
│   ├── SYNTHETIC_LOG_GENERATOR.md    ← MCP server docs
│   └── MCP_SETUP.md                  ← Setup guide
└── README.md                          ← Project overview
```

## Validation Steps

### 1. XML Syntax Validation
```bash
./scripts/validate.sh
```
Checks:
- Valid XML structure
- Required fields present
- Rule IDs are unique
- No syntax errors

### 2. Rule Matching Validation
Via synthetic-log-generator:
- Generate logs matching rule conditions
- Verify rule fires correctly
- Check for false positives
- Validate edge cases

### 3. Deployment Validation
```bash
./scripts/deploy.sh
```
Checks:
- Rules load without errors
- No conflicts with existing rules
- Proper rule hierarchy (if_sid dependencies)

## Benefits of This Architecture

### For Detection Engineers
- Automated rule testing without manual log creation
- Quick iteration and refinement cycles
- Validation before deployment
- Reduced testing time and human error

### For the Organization
- Consistent rule development process
- Evidence-based rule creation (threat intel driven)
- Reduced false positives through validation
- Faster rule deployment to production
- Better coverage of attack techniques

### For AI Agents
- Access to specialized tools (threat intel, log generation)
- Autonomous rule development capability
- Structured feedback (validation results)
- Ability to iterate and improve

## Future Enhancements

- [ ] Real log replay from actual security incidents
- [ ] Correlation rule testing (multiple events)
- [ ] Performance testing (rule efficiency)
- [ ] False positive analysis
- [ ] Coverage reporting (% of attack techniques covered)
- [ ] Automated rule optimization
- [ ] Integration with Wazuh live API
- [ ] Dashboard for rule metrics and stats

## References

- [Wazuh Rules Syntax](https://documentation.wazuh.com/current/user-manual/ruleset/rules-syntax-structure/)
- [MITRE ATT&CK Framework](https://attack.mitre.org/)
- [MCP Protocol](https://github.com/anthropics/model-context-protocol)
- [Detection Engineering Resources](https://docs.splunk.com/Documentation/Splunk/latest/Security/Overviewofdetectionengineering)
