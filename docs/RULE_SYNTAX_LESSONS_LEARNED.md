# Wazuh Rule Syntax: Lessons Learned

## ⚠️ DETECTION ENGINEER AGENT: READ THIS FIRST

This document is required reading for any Wazuh detection engineer agent before creating or modifying rules. The lessons below document REAL production failures that WILL happen again if ignored.

**The 5 Critical Rules (read them now):**
1. ✅ No trailing commas in `<group>` tags
2. ✅ Frequency rules MUST have `frequency` and `timeframe` attributes
3. ✅ Use `<if_matched_sid>` for correlation, `<if_sid>` for parent references
4. ✅ Always add `type="pcre2"` to regex patterns
5. ✅ Test with synthetic logs before declaring "ready for deployment"

**If you ignore these, your rules WILL FAIL deployment.**

---

## Overview
This document captures critical lessons learned from debugging Wazuh rule deployment failures. These insights are essential for the Wazuh detection engineer agent to understand before creating or modifying rules.

---

## 1. XML Syntax Errors (CRITICAL)

### Issue: Trailing Commas in Group Tags
**Problem**: Trailing commas in `<group>` tag values cause XML parsing failures
```xml
<!-- ❌ WRONG - Trailing comma -->
<group>pci_dss_11.4,gdpr_IV_35.7.d,nist_800_53_SI.4,tsc_CC7.2,</group>

<!-- ✅ CORRECT - No trailing comma -->
<group>pci_dss_11.4,gdpr_IV_35.7.d,nist_800_53_SI.4,tsc_CC7.2</group>
```

**Impact**: Rules fail to load with XML parsing errors
**Prevention**: Always validate XML syntax with `xmllint` before deployment

---

## 2. Frequency Rule Syntax (CRITICAL)

### Issue: Missing Required Frequency Attributes
**Problem**: Correlation rules using `<same_source_ip/>` MUST include `frequency` and `timeframe` attributes

```xml
<!-- ❌ WRONG - Missing frequency/timeframe on correlation rule -->
<rule id="110900" level="13">
  <if_matched_sid>110001,110002,110013,110014</if_matched_sid>
  <same_source_ip/>
  <description>Multiple threats from same source</description>
</rule>

<!-- ✅ CORRECT - Has frequency and timeframe -->
<rule id="110900" level="13" frequency="2" timeframe="300">
  <if_matched_sid>110001,110002,110013,110014</if_matched_sid>
  <same_source_ip/>
  <description>Multiple threats from same source</description>
</rule>
```

**Error Message**: `Invalid use of frequency/context options. Missing if_matched on rule 'XXXX'`
**Impact**: Rules fail to load during Wazuh startup
**Prevention**: Always include `frequency` and `timeframe` when using correlation conditions

### Frequency Rule Attributes
```xml
frequency="N"      <!-- Trigger after N matching events -->
timeframe="SECS"   <!-- Within this many seconds -->
```

**Common Values**:
- `frequency="2" timeframe="300"` - 2 events in 5 minutes
- `frequency="3" timeframe="120"` - 3 events in 2 minutes
- `frequency="5" timeframe="60"` - 5 events in 1 minute

---

## 3. Correlation Rule Logic (CRITICAL)

### Issue: Incorrect Use of `<if_sid>` vs `<if_matched_sid>`

#### `<if_sid>` - Parent Rule References (Non-Frequency)
Used when you want to match events from a parent rule (one-time, not frequency-based)

```xml
<!-- ✅ CORRECT - Simple parent rule reference -->
<rule id="110001" level="14">
  <if_sid>87101</if_sid>  <!-- Single parent rule -->
  <field name="win.eventdata.destinationIp">^188\.127\.227\.226$</field>
  <description>C2 connection detected</description>
</rule>
```

#### `<if_matched_sid>` - Frequency/Correlation Rules (Required for correlation)
Used when creating correlation or frequency-based rules that need to match multiple events

```xml
<!-- ✅ CORRECT - Frequency rule uses if_matched_sid -->
<rule id="110005" level="12" frequency="3" timeframe="120">
  <if_matched_sid>110004</if_matched_sid>  <!-- Frequency rule -->
  <same_source_ip/>
  <description>Multiple executions detected</description>
</rule>

<!-- ✅ CORRECT - Correlation rule uses if_matched_sid with multiple IDs -->
<rule id="110902" level="15" frequency="2" timeframe="300">
  <if_matched_sid>110006,110007</if_matched_sid>  <!-- Correlation across 2 rules -->
  <same_source_ip/>
  <description>Credential dumping + tunneling detected</description>
</rule>
```

### Key Rule
- **`<if_sid>`** = Parent rule filter (single event matching)
- **`<if_matched_sid>`** = Frequency/Correlation filter (requires `frequency` + `timeframe`)

**Never Mix**: Don't use both `<if_sid>` and `<if_matched_sid>` in the same rule

---

## 4. Rule ID Management (IMPORTANT)

### Custom Rule ID Range
- **Range**: 100000 - 120000
- **Wazuh Built-in**: 1 - 99999
- **Never conflict** with built-in rule IDs

### Validation
Use the provided Python script to check for conflicts:
```bash
python3 scripts/check_rule_ids.py
```

---

## 5. File Permissions (IMPORTANT)

### Permission Requirements
Rules must be readable by the Wazuh user:

```bash
# ❌ WRONG - Only owner can read
-rw------- 1 root root

# ✅ CORRECT - Owner and Wazuh group can read
-rw-r--r-- 1 root root
# Or after deployment on Wazuh server:
-rw-rw---- 1 root wazuh
```

### Deployment Permissions
After copying to Wazuh server, set:
```bash
chown root:wazuh /var/ossec/etc/rules/*.xml
chmod 660 /var/ossec/etc/rules/*.xml
```

The deployment script (`deploy.sh`) handles this automatically.

---

## 6. Field Type Specifications (IMPORTANT)

### `type="pcre2"` for Pattern Matching
Always specify `type="pcre2"` for regex patterns:

```xml
<!-- ❌ WRONG - No type specified -->
<field name="win.eventdata.image">\\bcp\.exe$</field>

<!-- ✅ CORRECT - Regex type specified -->
<field name="win.eventdata.image" type="pcre2">(?i)\\bcp\.exe$</field>
```

### Supported Field Types
- `type="pcre2"` - PCRE2 regular expressions (recommended for complex patterns)
- No type - Literal string match (fastest but limited)
- `type="regex"` - POSIX regex (legacy, use pcre2 instead)

---

## 7. Common Wazuh Parent Rule IDs (REFERENCE)

### Windows Event Rules
- `61603` - Process execution (Event ID 1 from Sysmon)
- `61604` - Network connection (Sysmon Event ID 3)
- `87101` - Network connection outbound (default Windows events)

### File Integrity Monitoring
- `syscheck` group - Use with `<if_group>syscheck</if_group>`

### Web/HTTP Rules
- `31101` - HTTP requests (access logs)

**Note**: Verify these exist in your Wazuh installation before using them as parent rules.

---

## 8. Deployment Validation Checklist

Before deploying rules, verify:

- [ ] XML syntax is valid: `xmllint --noout rule_file.xml`
- [ ] No trailing commas in `<group>` tags
- [ ] All `<if_matched_sid>` rules have `frequency` and `timeframe` attributes
- [ ] Rule IDs are unique (100000-120000 range)
- [ ] Never mixing `<if_sid>` and `<if_matched_sid>` in same rule
- [ ] All regex patterns use `type="pcre2"`
- [ ] Parent rule IDs exist (e.g., 61603, 87101)
- [ ] File permissions allow Wazuh user to read (644 or better)

---

## 9. Deployment Process

### Local Deployment
```bash
cd /home/stanner/wazuh-rac
./scripts/deploy.sh
```

### What the Script Does
1. ✓ Validates XML syntax
2. ✓ Checks rule ID uniqueness
3. ✓ Tests SSH connectivity (remote)
4. ✓ Copies files to `/var/ossec/etc/rules/`
5. ✓ Sets permissions (`root:wazuh`, `660`)
6. ✓ Restarts Wazuh manager
7. ✓ Verifies service started

### Manual Deployment (if needed)
```bash
# Copy to server
scp rules/*.xml wazuh-user@192.168.0.141:/var/ossec/etc/rules/

# SSH to server
ssh wazuh-user@192.168.0.141

# Set permissions
sudo chown root:wazuh /var/ossec/etc/rules/*.xml
sudo chmod 660 /var/ossec/etc/rules/*.xml

# Restart Wazuh
sudo systemctl restart wazuh-manager
```

---

## 10. Debugging Rule Failures

### Check Wazuh Logs
```bash
tail -f /var/ossec/logs/ossec.log | grep -i error
```

### Common Error Messages and Fixes

#### "Permission denied" on rule files
```
wazuh-analysisd: WARNING: (1103): Could not open file 'etc/rules/threat_detection_akira_ransomware.xml' due to [(13)-(Permission denied)]
```
**Fix**: Change file permissions to allow Wazuh user to read: `chmod 644` (local) or `chmod 660` (on server)

#### "Invalid if_matched_sid value"
```
wazuh-analysisd: WARNING: (7615): Invalid 'if_matched_sid' value: '110001,110002,110013,110014'. Rule '110900' will be ignored.
```
**Fix**: `<if_matched_sid>` doesn't accept comma-separated values directly. Use the rule as-is; Wazuh will match if ANY of those rules trigger.

#### "Missing if_matched on rule"
```
wazuh-analysisd: ERROR: Invalid use of frequency/context options. Missing if_matched on rule '110900'
```
**Fix**: Add `frequency` and `timeframe` attributes to the rule tag

#### "Error loading the rules"
```
wazuh-testrule: CRITICAL: (1220): Error loading the rules: 'etc/rules/threat_detection_correlation.xml'
```
**Fix**: Check XML syntax with `xmllint`, verify no trailing commas in group tags

---

## 11. Rule Creation Best Practices

### 1. Start Simple
Begin with single-condition rules before creating complex correlations:
```xml
<!-- Good starting point -->
<rule id="110001" level="14">
  <if_sid>61603</if_sid>
  <field name="win.eventdata.image" type="pcre2">(?i)ngrok\.exe$</field>
  <description>Ngrok tunneling tool execution detected</description>
</rule>
```

### 2. Test With Synthetic Logs
Use the synthetic log generator MCP before deploying:
```bash
# Generate logs that should match the rule
# Validate the rule against the logs
# Adjust the rule if needed
```

### 3. Correlation Rules
Correlation rules should aggregate behavior across multiple events:
- 2+ events from same source within timeframe = suspicious
- Example: Multiple failed login attempts = brute force

```xml
<!-- Good correlation rule -->
<rule id="110015" level="12" frequency="5" timeframe="60">
  <if_matched_sid>110013</if_matched_sid>
  <same_source_ip/>
  <description>5+ connection attempts in 60 seconds from same source</description>
</rule>
```

### 4. Use MITRE ATT&CK Mapping
Always include MITRE framework IDs for context:
```xml
<mitre>
  <id>T1571</id>  <!-- Command and Control: Non-Standard Port -->
  <id>T1572</id>  <!-- Proxy: Protocol Tunneling -->
</mitre>
```

---

## 12. Agent Instructions for Rule Development

When the Wazuh detection engineer agent creates rules, it MUST:

1. ✓ Validate XML syntax with `xmllint` before any deployment
2. ✓ Check for trailing commas in `<group>` tags - REMOVE THEM
3. ✓ For frequency rules: Include both `frequency` and `timeframe` attributes
4. ✓ Use `<if_matched_sid>` with `frequency`/`timeframe` for correlation rules
5. ✓ Use `<if_sid>` for simple parent rule references (non-frequency)
6. ✓ Never mix `<if_sid>` and `<if_matched_sid>` in the same rule
7. ✓ Use `type="pcre2"` for all regex patterns
8. ✓ Verify parent rule IDs exist (61603, 87101, etc.)
9. ✓ Keep rule IDs in 100000-120000 range
10. ✓ Test with synthetic logs before deployment
11. ✓ Run `scripts/check_rule_ids.py` to verify uniqueness
12. ✓ Set file permissions to 644 (local) or request 660 (server)

---

## 13. Quick Reference: Rule Templates

### Template 1: Simple Detection Rule
```xml
<rule id="110001" level="14">
  <if_sid>61603</if_sid>
  <field name="win.eventdata.image" type="pcre2">(?i)malware\.exe$</field>
  <description>Malicious process execution detected</description>
  <mitre>
    <id>T1059</id>
  </mitre>
  <group>malware_detection</group>
</rule>
```

### Template 2: Frequency Rule (Aggregation)
```xml
<rule id="110015" level="12" frequency="5" timeframe="60">
  <if_matched_sid>110013</if_matched_sid>
  <same_source_ip/>
  <description>Multiple suspicious events from same source</description>
  <mitre>
    <id>T1110</id>
  </mitre>
  <group>attack_pattern</group>
</rule>
```

### Template 3: Correlation Rule (Multi-Indicator)
```xml
<rule id="110902" level="15" frequency="2" timeframe="300">
  <if_matched_sid>110006,110007</if_matched_sid>
  <same_source_ip/>
  <description>Credential dumping + tunneling detected (attack infrastructure setup)</description>
  <mitre>
    <id>T1003.001</id>
    <id>T1572</id>
  </mitre>
  <group>advanced_threat</group>
</rule>
```

---

## 14. Summary of Fixes Applied

| Issue | Root Cause | Fix | Impact |
|-------|-----------|-----|--------|
| Trailing commas in `<group>` | Copy-paste error | Remove trailing commas | XML syntax errors |
| Missing `frequency`/`timeframe` | Incomplete rule syntax | Add to correlation rules | Rules fail to load |
| Mixed `<if_sid>` + `<if_matched_sid>` | Misunderstanding rule types | Use only `<if_matched_sid>` with frequency | Rule syntax errors |
| File permissions | Deployment script issue | chmod 644 local, 660 on server | Permission denied errors |
| Invalid parent rule IDs | Reference to non-existent rules | Verify parent rule IDs exist | Rules trigger incorrectly |

---

## Document Version
- **Created**: 2025-11-28
- **Purpose**: Capture critical lessons from rule deployment debugging
- **Audience**: Wazuh Detection Engineer Agent + Development Team

---

## Related Documentation
- [ARCHITECTURE.md](./ARCHITECTURE.md) - System design overview
- [README_DEPLOYMENT.md](./README_DEPLOYMENT.md) - Threat detection deployment guide
- [SYNTHETIC_LOG_GENERATOR.md](./SYNTHETIC_LOG_GENERATOR.md) - Test log generation API
