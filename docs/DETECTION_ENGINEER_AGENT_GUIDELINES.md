# Wazuh Detection Engineer Agent: Strict Guidelines

This document is for the Wazuh detection engineer AI agent. Follow these guidelines EXACTLY when creating or modifying rules.

---

## PRE-CREATION CHECKLIST

Before writing ANY rule XML, you MUST:

- [ ] Read `RULE_SYNTAX_LESSONS_LEARNED.md` (all 14 sections)
- [ ] Review the rule templates section
- [ ] Understand `<if_sid>` vs `<if_matched_sid>` distinction
- [ ] Know the custom rule ID range (100000-120000)
- [ ] Understand frequency rule requirements (frequency + timeframe)

---

## MANDATORY VALIDATION STEPS

After creating a rule file, you MUST perform these validations IN THIS ORDER:

### Step 1: XML Syntax Validation
```bash
xmllint --noout /path/to/rule_file.xml
```
**If this fails**, the rule is broken. Fix immediately. DO NOT proceed.

### Step 2: Manual Inspection
Read through the rule XML and verify:
- [ ] No trailing commas in any `<group>` tags (e.g., `...tsc_CC7.2,</group>` is WRONG)
- [ ] All `<if_matched_sid>` rules have `frequency` and `timeframe` attributes
- [ ] No mixing of `<if_sid>` and `<if_matched_sid>` in the same rule
- [ ] All regex patterns use `type="pcre2"`
- [ ] Rule ID is in range 100000-120000
- [ ] Parent rule IDs exist (61603, 87101, syscheck, etc.)

### Step 3: Rule ID Uniqueness Check
```bash
python3 /home/stanner/wazuh-rac/scripts/check_rule_ids.py
```
**If conflicts exist**, rename your rule IDs. DO NOT deploy with conflicts.

### Step 4: Synthetic Log Testing
Use the synthetic-log-generator MCP server to:
1. Generate synthetic logs that should match the rule
2. Validate the rule against those logs
3. Verify the rule triggers correctly
4. Report any failures

**If synthetic logs don't trigger the rule**, the rule logic is wrong. Debug and fix.

### Step 5: Permission Check
```bash
ls -la /path/to/rule_file.xml
```
**If permissions are** `-rw-------`, change to `-rw-r--r--`:
```bash
chmod 644 /path/to/rule_file.xml
```

---

## RULE CREATION RULES

### Rule 1: XML Structure
Every rule MUST be valid XML. Test immediately with `xmllint`:
```xml
<?xml version="1.0" encoding="UTF-8"?>
<group name="...">
  <rule id="..." level="...">
    <!-- Rule content -->
  </rule>
</group>
```

### Rule 2: Group Tags (CRITICAL)
`<group>` tags MUST NOT have trailing commas:
```xml
<!-- ❌ WRONG -->
<group>pci_dss_11.4,gdpr_IV_35.7.d,nist_800_53_SI.4,</group>

<!-- ✅ CORRECT -->
<group>pci_dss_11.4,gdpr_IV_35.7.d,nist_800_53_SI.4</group>
```

### Rule 3: Parent Rule References
Use `<if_sid>` for single parent rule reference (non-frequency):
```xml
<rule id="110001" level="14">
  <if_sid>61603</if_sid>
  <field name="..." type="pcre2">...</field>
</rule>
```

### Rule 4: Frequency Rules (CRITICAL)
ALL frequency/correlation rules MUST have both attributes:
```xml
<!-- ❌ WRONG - Missing frequency/timeframe -->
<rule id="110900" level="13">
  <if_matched_sid>110001,110002</if_matched_sid>
  <same_source_ip/>
</rule>

<!-- ✅ CORRECT -->
<rule id="110900" level="13" frequency="2" timeframe="300">
  <if_matched_sid>110001,110002</if_matched_sid>
  <same_source_ip/>
</rule>
```

### Rule 5: Correlation Logic
When correlating multiple rules:
```xml
<!-- ✅ CORRECT - Multiple rule IDs with if_matched_sid + frequency -->
<rule id="110902" level="15" frequency="2" timeframe="300">
  <if_matched_sid>110006,110007</if_matched_sid>
  <same_source_ip/>
  <description>Rule 110006 AND Rule 110007 from same source within 5 minutes</description>
</rule>
```

### Rule 6: Field Type Specification
ALWAYS use `type="pcre2"` for regex patterns:
```xml
<!-- ✅ CORRECT -->
<field name="win.eventdata.image" type="pcre2">(?i)\\bcp\.exe$</field>

<!-- ❌ WRONG - No type specified -->
<field name="win.eventdata.image">\\bcp\.exe$</field>
```

### Rule 7: Rule ID Assignment
Custom rules MUST use IDs in range 100000-120000:
```xml
<!-- ✅ CORRECT -->
<rule id="110001" level="14">...</rule>
<rule id="110902" level="15">...</rule>

<!-- ❌ WRONG - Outside range -->
<rule id="87102" level="14">...</rule>  <!-- Conflicts with Wazuh built-in -->
```

### Rule 8: MITRE Framework Mapping
ALWAYS include relevant MITRE ATT&CK IDs:
```xml
<mitre>
  <id>T1059</id>      <!-- Command and Scripting Interpreter -->
  <id>T1105</id>      <!-- Ingress Tool Transfer -->
</mitre>
```

---

## DEPLOYMENT CHECKLIST

Before running `./scripts/deploy.sh`, verify:

- [ ] All rule files pass `xmllint` validation
- [ ] No trailing commas in any `<group>` tags
- [ ] All frequency rules have `frequency` and `timeframe`
- [ ] No mixing of `<if_sid>` and `<if_matched_sid>`
- [ ] All regex use `type="pcre2"`
- [ ] Rule ID uniqueness check passes
- [ ] Synthetic log tests pass
- [ ] File permissions are 644
- [ ] Parent rule IDs verified to exist

---

## COMMON MISTAKES TO AVOID

### Mistake 1: Trailing Commas
```xml
<!-- ❌ COMMON MISTAKE -->
<group>pci_dss_11.4,gdpr_IV_35.7.d,nist_800_53_SI.4,tsc_CC7.2,</group>
```
**Fix**: Remove the trailing comma after `tsc_CC7.2`

### Mistake 2: Missing frequency on correlation rules
```xml
<!-- ❌ COMMON MISTAKE -->
<rule id="110900" level="13">
  <if_matched_sid>110001,110002</if_matched_sid>
  <same_source_ip/>
</rule>
```
**Fix**: Add `frequency="2" timeframe="300"` to rule tag

### Mistake 3: Mixing if_sid and if_matched_sid
```xml
<!-- ❌ COMMON MISTAKE -->
<rule id="110902" level="15">
  <if_sid>110006</if_sid>
  <if_matched_sid>110007</if_matched_sid>
  <same_source_ip/>
</rule>
```
**Fix**: Use only `<if_matched_sid>110006,110007</if_matched_sid>` with frequency

### Mistake 4: No type="pcre2" on regex
```xml
<!-- ❌ COMMON MISTAKE -->
<field name="win.eventdata.commandLine">(vssadmin|wmic).*delete.*shadow</field>
```
**Fix**: Add `type="pcre2"` to field tag

### Mistake 5: Referencing non-existent parent rules
```xml
<!-- ❌ POTENTIAL MISTAKE -->
<if_sid>12345</if_sid>  <!-- Does this rule ID exist? -->
```
**Fix**: Verify parent rule ID exists in Wazuh. Common IDs: 61603, 87101, etc.

---

## ERROR MESSAGES & FIXES

### Error: "Could not open file due to Permission denied"
```
wazuh-analysisd: WARNING: (1103): Could not open file 'etc/rules/threat_detection_akira_ransomware.xml' due to [(13)-(Permission denied)]
```
**Fix**: `chmod 644 threat_detection_akira_ransomware.xml`

### Error: "Invalid if_matched_sid value"
```
wazuh-analysisd: WARNING: (7615): Invalid 'if_matched_sid' value: '110001,110002,110013,110014'
```
**Fix**: This warning is normal for multi-ID correlation. Ensure rule has `frequency` and `timeframe`.

### Error: "Missing if_matched on rule"
```
wazuh-analysisd: ERROR: Invalid use of frequency/context options. Missing if_matched on rule '110900'
```
**Fix**: Add `frequency` and `timeframe` attributes to the rule tag

### Error: "Error loading the rules"
```
wazuh-testrule: CRITICAL: (1220): Error loading the rules: 'etc/rules/threat_detection_correlation.xml'
```
**Fix**: Run `xmllint` to find the exact XML error

---

## WORKFLOW: Create → Validate → Test → Deploy

### Step 1: Create Rule
Write the rule XML file in the `rules/` directory.

### Step 2: Validate XML
```bash
xmllint --noout rules/your_rule_name.xml
```
Must pass with no output.

### Step 3: Manual Review
Read the rule and verify against the "MANDATORY VALIDATION STEPS" section above.

### Step 4: Test with Synthetic Logs
```python
# Use synthetic-log-generator MCP to:
# 1. Generate logs that match the rule
# 2. Validate the rule triggers
# 3. Report success/failure
```

### Step 5: Check for Conflicts
```bash
python3 scripts/check_rule_ids.py
```
Must report no conflicts.

### Step 6: Deploy
```bash
./scripts/deploy.sh
```

### Step 7: Verify Deployment
```bash
# Check Wazuh logs for errors
tail -f /var/ossec/logs/ossec.log | grep -i error
```

---

## REFERENCE: Valid Parent Rule IDs

These are common Wazuh parent rule IDs. Verify they exist before using:

| Rule ID | Description | Use Case |
|---------|-------------|----------|
| 61603 | Sysmon Event ID 1 (Process Creation) | Process execution rules |
| 61604 | Sysmon Event ID 3 (Network Connection) | Network connection rules |
| 87101 | Windows Network Event | Connection to IP rules |
| (syscheck) | File Integrity Monitoring | File change rules |
| 31101 | HTTP Request | Web access rules |

**IMPORTANT**: If using a parent rule ID not in this list, verify it exists:
```bash
grep -r "<rule id=\"XXXX\"" /var/ossec/ruleset/rules/
```

---

## RULE TESTING TEMPLATE

When testing rules with synthetic logs:

```python
# 1. Generate logs for the rule
logs = generate_logs_from_rule(rule_xml)

# 2. Validate the logs
result = validate_logs_against_rule(logs, rule_xml)

# 3. Check result
if result['matches'] == result['expected']:
    print("✓ Rule test PASSED")
else:
    print("✗ Rule test FAILED")
    print(f"  Expected: {result['expected']}")
    print(f"  Got: {result['matches']}")
```

---

## AGENT BEHAVIOR EXPECTATIONS

When you (the detection engineer agent) create rules:

1. **Read this document** - Don't skip any sections
2. **Validate every rule** - Use the mandatory validation steps
3. **Test with synthetic logs** - Before reporting "ready for deployment"
4. **Report problems clearly** - If a rule fails, explain why
5. **Follow templates** - Use the provided rule templates as examples
6. **Ask for clarification** - If you're unsure about rule logic
7. **Never deploy broken rules** - Better to report and ask for help

---

## SUMMARY

**The 5 Most Critical Rules:**

1. ✓ Remove trailing commas from `<group>` tags
2. ✓ Add `frequency` and `timeframe` to correlation rules
3. ✓ Use `<if_matched_sid>` with frequency, not `<if_sid>`
4. ✓ Always add `type="pcre2"` to regex patterns
5. ✓ Test with synthetic logs before deployment

**If you follow these guidelines, your rules will deploy successfully.**

---

## Related Documentation
- `RULE_SYNTAX_LESSONS_LEARNED.md` - Detailed lessons (read first!)
- `QUICK_START.md` - Setup and usage
- `SYNTHETIC_LOG_GENERATOR.md` - Testing API
- `ARCHITECTURE.md` - System design
