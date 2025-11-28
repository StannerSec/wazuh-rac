# Quick Start Guide

## ⚠️ CRITICAL: For Detection Engineer Agent

**BEFORE creating ANY rules**, you MUST read [`RULE_SYNTAX_LESSONS_LEARNED.md`](./RULE_SYNTAX_LESSONS_LEARNED.md) - all of it.

This document contains production failure lessons. Real rules failed because of:
- ❌ Trailing commas in `<group>` tags → XML parse failure
- ❌ Missing `frequency`/`timeframe` on correlation rules → Rule load failure
- ❌ Mixing `<if_sid>` + `<if_matched_sid>` → Syntax error
- ❌ No `type="pcre2"` on regex → Pattern matching broken
- ❌ Skipping synthetic log tests → Broken rules deployed

**These mistakes WILL happen again if you don't understand why they happened before.**

Read the lessons doc now. Seriously. Right now. Before writing any rule XML.

---

## Setup (5 minutes)

### 1. Install MCP SDK
```bash
pip install mcp
```

### 2. Configure MCP Server

Create `.claude/claude.json` in your project:

```bash
mkdir -p .claude
cat > .claude/claude.json << 'EOF'
{
  "mcpServers": {
    "synthetic-log-generator": {
      "command": "python3",
      "args": ["/home/stanner/wazuh-rac/mcp_servers/synthetic_log_generator.py"],
      "disabled": false
    }
  }
}
EOF
```

### 3. Verify Setup
```bash
# Test the MCP server is accessible
python3 /home/stanner/wazuh-rac/mcp_servers/synthetic_log_generator.py --help
```

## Usage Examples

### Option 1: Have an AI Agent Create Rules (Recommended)

```bash
cd /home/stanner/wazuh-rac
claude-code --task "Create and test Wazuh detection rules for DeerStealer malware"
```

The agent will:
1. Research DeerStealer (threat intelligence)
2. Create detection rules (XML)
3. Generate test logs
4. Validate rules work
5. Prepare for deployment

### Option 2: Manually Create Rules and Test

#### Step 1: Create a Wazuh Rule

Create file `rules/my_custom_rule.xml`:

```xml
<group name="custom,">
  <rule id="100200" level="12">
    <match>malicious pattern</match>
    <description>My Custom Detection Rule</description>
    <mitre>
      <id>T1234</id>
    </mitre>
  </rule>
</group>
```

#### Step 2: Test with Synthetic Logs

```bash
python3 << 'EOF'
import json
import sys
sys.path.insert(0, '/home/stanner/wazuh-rac/mcp_servers')
from synthetic_log_generator import SyntheticLogGenerator

# Read your rule
with open('rules/my_custom_rule.xml', 'r') as f:
    rule_xml = f.read()

# Initialize generator
gen = SyntheticLogGenerator()

# Generate logs
logs, msg = gen.generate_from_rule(rule_xml, count=5)
print(f"Generated: {msg}")
print(json.dumps(logs[:2], indent=2))

# Validate
results, msg = gen.validate_logs_against_rule(logs, rule_xml)
print(f"\nValidation: {msg}")
print(f"Match Rate: {results.get('match_rate')}%")
EOF
```

#### Step 3: Deploy

```bash
./scripts/validate.sh
./scripts/deploy.sh
```

## Common Tasks

### Create Rules for a Specific Threat

```bash
claude-code --task "Create Wazuh rules for detecting [THREAT_NAME]. Research the threat, identify MITRE techniques, create detection rules for each technique, generate synthetic test logs, and validate rules."
```

Examples:
- `--task "Create Wazuh rules for detecting DeerStealer malware"`
- `--task "Create Wazuh rules for detecting SSH brute force attacks"`
- `--task "Create Wazuh rules for detecting privilege escalation attempts"`

### Validate Existing Rules

```bash
claude-code --task "Validate my Wazuh rules in /home/stanner/wazuh-rac/rules/. For each rule, generate synthetic logs that should match it, then validate the logs trigger the correct rules. Report any rules that fail validation."
```

### Test a Specific Rule

```python
import json
import sys
sys.path.insert(0, '/home/stanner/wazuh-rac/mcp_servers')
from synthetic_log_generator import SyntheticLogGenerator

gen = SyntheticLogGenerator()

# Your rule
rule_xml = '''
<rule id="100100" level="10">
  <match>Failed password</match>
  <description>SSH brute force attempt</description>
</rule>
'''

# Generate logs
logs, msg = gen.generate_from_rule(rule_xml, count=3)

# Validate
results, validation_msg = gen.validate_logs_against_rule(logs, rule_xml)

print(f"Generated: {msg}")
print(f"Validation: {validation_msg}")
print(f"Results: {json.dumps(results, indent=2)}")
```

## Workflow Overview

```
Step 1: Research Threat
  ├─ Use threat-intel-researcher MCP
  └─ Get: Name, techniques, IOCs, behaviors

Step 2: Create Rules
  ├─ Write Wazuh XML rules
  ├─ One rule per technique
  └─ Place in rules/ directory

Step 3: Generate Test Logs
  ├─ Call synthetic-log-generator MCP
  ├─ Generate logs matching threat behavior
  └─ Get: Synthetic log data

Step 4: Validate Rules
  ├─ Test: Do generated logs trigger rules?
  ├─ Pass: Rules work correctly
  └─ Fail: Refine and retry

Step 5: Deploy
  ├─ Run: ./scripts/validate.sh
  ├─ Run: ./scripts/deploy.sh
  └─ Rules now active in Wazuh
```

## File Locations

- **Rules**: `/home/stanner/wazuh-rac/rules/*.xml`
- **Decoders**: `/home/stanner/wazuh-rac/decoders/*.xml`
- **MCP Server**: `/home/stanner/wazuh-rac/mcp_servers/synthetic_log_generator.py`
- **Documentation**: `/home/stanner/wazuh-rac/docs/`
- **Scripts**: `/home/stanner/wazuh-rac/scripts/`

## Troubleshooting

### MCP Server Not Found
```bash
# Verify config exists
cat .claude/claude.json

# Verify file path is correct
ls -l /home/stanner/wazuh-rac/mcp_servers/synthetic_log_generator.py

# Verify Python path
which python3
python3 --version
```

### Import Error
```bash
pip install --upgrade mcp
```

### Rules Not Validating
1. Check rule XML syntax: `./scripts/validate.sh`
2. Verify rule IDs are unique: `python3 scripts/check_rule_ids.py`
3. Check log format matches rule expectations

## Next Steps

1. ✅ Setup MCP server
2. → Run first agent task
3. → Create detection rules
4. → Validate rules
5. → Deploy to Wazuh

## Examples

### Example 1: SSH Brute Force Detection

```bash
claude-code --task "Create Wazuh rules to detect SSH brute force attacks. Create rules for: 1) Multiple failed login attempts, 2) Login attempt with common credentials, 3) Successful login after failures. Generate synthetic logs for each scenario and validate the rules work correctly."
```

### Example 2: Malware Detection

```bash
claude-code --task "Research DeerStealer malware and create Wazuh detection rules. For each MITRE technique associated with DeerStealer, create a rule that would detect that behavior. Generate synthetic logs based on the threat intelligence and validate each rule."
```

### Example 3: Rule Validation

```bash
claude-code --task "Review all rules in /home/stanner/wazuh-rac/rules/ and validate they work correctly. For each rule: 1) Generate synthetic logs that should match, 2) Test the rule against those logs, 3) Report pass/fail for each rule, 4) Suggest improvements for failing rules."
```

## Learn More

- [Architecture Overview](./ARCHITECTURE.md)
- [MCP Server Documentation](./SYNTHETIC_LOG_GENERATOR.md)
- [Setup Guide](./MCP_SETUP.md)
- [Wazuh Official Docs](https://documentation.wazuh.com/)
- [MITRE ATT&CK Framework](https://attack.mitre.org/)
