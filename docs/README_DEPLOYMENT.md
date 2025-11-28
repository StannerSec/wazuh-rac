# Wazuh Detection Rules - Threat Intelligence Deployment Guide

## Overview

This repository contains comprehensive Wazuh detection rules for five major threat categories identified through threat intelligence research:

1. **Tomiris APT** - Advanced Persistent Threat with multi-language reverse shells
2. **Trigona Ransomware** - SQL database targeting ransomware
3. **Akira Ransomware** - Ngrok-based ransomware with credential dumping
4. **LummaC2 Stealer** - Browser credential and cryptocurrency wallet theft
5. **Mirai/Gafgyt Botnets** - IoT device compromise and DDoS attacks

## Rule Files

| File | Rule IDs | Threat Category | Alert Levels |
|------|----------|----------------|--------------|
| `tomiris_apt_rules.xml` | 100001-100010 | Tomiris APT | 10-15 |
| `trigona_ransomware_rules.xml` | 100011-100023 | Trigona Ransomware | 5-15 |
| `akira_ransomware_rules.xml` | 100024-100041 | Akira Ransomware | 12-15 |
| `lummac2_stealer_rules.xml` | 100042-100059 | LummaC2 Stealer | 9-15 |
| `mirai_gafgyt_botnet_rules.xml` | 100060-100079 | Mirai/Gafgyt Botnets | 6-15 |

## Total Rules: 79 Detection Rules

## Prerequisites

### Required Wazuh Agent Configuration

#### Windows Endpoints (Tomiris, Trigona, Akira, LummaC2)

**Sysmon Installation Required:**
```xml
<!-- ossec.conf - Sysmon Integration -->
<localfile>
  <location>Microsoft-Windows-Sysmon/Operational</location>
  <log_format>eventchannel</log_format>
</localfile>
```

**Required Sysmon Events:**
- Event ID 1: Process Creation
- Event ID 3: Network Connection
- Event ID 10: Process Access (LSASS monitoring)
- Event ID 11: File Creation

**File Integrity Monitoring (FIM):**
```xml
<!-- ossec.conf - FIM Configuration -->
<syscheck>
  <directories check_all="yes" realtime="yes">C:\Users</directories>
  <directories check_all="yes" realtime="yes">C:\Program Files</directories>
  <directories check_all="yes" realtime="yes">C:\Windows\Temp</directories>

  <!-- Browser credential directories -->
  <directories check_all="yes" realtime="yes">%LOCALAPPDATA%\Google\Chrome\User Data</directories>
  <directories check_all="yes" realtime="yes">%LOCALAPPDATA%\Microsoft\Edge\User Data</directories>
  <directories check_all="yes" realtime="yes">%APPDATA%\Mozilla\Firefox\Profiles</directories>
</syscheck>
```

#### Linux/IoT Devices (Mirai/Gafgyt)

**Network Monitoring:**
```xml
<!-- ossec.conf - Linux Configuration -->
<localfile>
  <log_format>syslog</log_format>
  <location>/var/log/auth.log</location>
</localfile>

<localfile>
  <log_format>syslog</log_format>
  <location>/var/log/secure</location>
</localfile>
```

**Process Monitoring:**
```xml
<localfile>
  <log_format>command</log_format>
  <command>netstat -tulpn</command>
  <frequency>120</frequency>
</localfile>
```

### Required Wazuh Decoders

Ensure these base decoders are present:
- `0015-sysmon_decoder.xml` (Sysmon events)
- `0016-wineventlog_decoder.xml` (Windows Event Logs)
- `0025-ssh_decoder.xml` (SSH authentication)
- `0055-sshd_decoder.xml` (SSHD logs)
- `0125-mysql_decoder.xml` (MS-SQL logs)

## Installation Instructions

### Step 1: Backup Existing Rules

```bash
# On Wazuh Manager
sudo cp -r /var/ossec/etc/rules /var/ossec/etc/rules.backup.$(date +%Y%m%d)
```

### Step 2: Deploy Rule Files

```bash
# Copy all rule files to Wazuh manager
sudo cp tomiris_apt_rules.xml /var/ossec/etc/rules/
sudo cp trigona_ransomware_rules.xml /var/ossec/etc/rules/
sudo cp akira_ransomware_rules.xml /var/ossec/etc/rules/
sudo cp lummac2_stealer_rules.xml /var/ossec/etc/rules/
sudo cp mirai_gafgyt_botnet_rules.xml /var/ossec/etc/rules/

# Set proper permissions
sudo chown wazuh:wazuh /var/ossec/etc/rules/*.xml
sudo chmod 640 /var/ossec/etc/rules/*.xml
```

### Step 3: Validate Rule Syntax

```bash
# Test configuration
sudo /var/ossec/bin/wazuh-logtest

# Check for rule syntax errors
sudo /var/ossec/bin/wazuh-analysisd -t
```

### Step 4: Enable Rules in ossec.conf

```xml
<!-- /var/ossec/etc/ossec.conf -->
<ruleset>
  <!-- Include custom threat intelligence rules -->
  <include>tomiris_apt_rules.xml</include>
  <include>trigona_ransomware_rules.xml</include>
  <include>akira_ransomware_rules.xml</include>
  <include>lummac2_stealer_rules.xml</include>
  <include>mirai_gafgyt_botnet_rules.xml</include>
</ruleset>
```

### Step 5: Restart Wazuh Manager

```bash
# Restart Wazuh manager to load new rules
sudo systemctl restart wazuh-manager

# Verify service started successfully
sudo systemctl status wazuh-manager
```

### Step 6: Verify Rules Loaded

```bash
# Check rule compilation
sudo tail -f /var/ossec/logs/ossec.log | grep -i "rules"

# Verify specific rule IDs loaded
sudo /var/ossec/bin/wazuh-logtest -l 100001
```

## Detection Coverage by MITRE ATT&CK

### Initial Access
- **T1566.001** - Phishing: Spearphishing Attachment (Tomiris)

### Execution
- **T1059** - Command and Scripting Interpreter (Tomiris, Trigona, Akira)
- **T1059.003** - Windows Command Shell (Trigona)
- **T1204.002** - User Execution: Malicious File (LummaC2, Mirai)

### Persistence
- **T1547** - Boot or Logon Autostart Execution (Mirai)
- **T1053.003** - Scheduled Task/Job (Mirai)

### Privilege Escalation
- **T1078** - Valid Accounts (Mirai)

### Defense Evasion
- **T1027** - Obfuscated Files or Information (Tomiris)
- **T1562.001** - Impair Defenses (Mirai)

### Credential Access
- **T1003.001** - LSASS Memory Dumping (Akira)
- **T1003.002** - Security Account Manager (Akira)
- **T1110.001** - Brute Force: Password Guessing (Trigona, Mirai)
- **T1555.003** - Credentials from Web Browsers (LummaC2)

### Discovery
- **T1046** - Network Service Discovery (Mirai)
- **T1083** - File and Directory Discovery (LummaC2)

### Collection
- **T1005** - Data from Local System (LummaC2)
- **T1539** - Steal Web Session Cookie (LummaC2)
- **T1560** - Archive Collected Data (Trigona)

### Command and Control
- **T1071** - Application Layer Protocol (Tomiris, Akira, Mirai)
- **T1071.001** - Web Protocols (All threats)
- **T1572** - Protocol Tunneling (Akira)
- **T1573** - Encrypted Channel (Tomiris)

### Exfiltration
- **T1020** - Automated Exfiltration (Trigona)
- **T1041** - Exfiltration Over C2 Channel (Akira, LummaC2)

### Impact
- **T1486** - Data Encrypted for Impact (Trigona, Akira)
- **T1490** - Inhibit System Recovery (Akira)
- **T1498** - Network Denial of Service (Mirai)
- **T1499** - Endpoint Denial of Service (Mirai)

### Remote Services
- **T1219** - Remote Access Software (Trigona)
- **T1021.004** - SSH (Mirai)
- **T1021.006** - Windows Remote Management (Mirai)

## Rule Testing and Validation

### Test Case 1: Tomiris APT - Telegram C2 Detection

**Simulated Log:**
```xml
<Event>
  <System>
    <EventID>3</EventID>
    <Channel>Microsoft-Windows-Sysmon/Operational</Channel>
  </System>
  <EventData>
    <Data Name="DestinationHostname">api.telegram.org</Data>
    <Data Name="DestinationPort">443</Data>
    <Data Name="Image">C:\Users\victim\suspicious.exe</Data>
  </EventData>
</Event>
```

**Expected Alert:** Rule 100002 (Level 12) - Tomiris APT: Suspicious connection to Telegram API

### Test Case 2: Akira Ransomware - Ngrok Execution

**Simulated Log:**
```xml
<Event>
  <System>
    <EventID>1</EventID>
    <Channel>Microsoft-Windows-Sysmon/Operational</Channel>
  </System>
  <EventData>
    <Data Name="Image">C:\Temp\ngrok.exe</Data>
    <Data Name="CommandLine">ngrok tcp 3389</Data>
  </EventData>
</Event>
```

**Expected Alert:** Rule 100026 (Level 13) - Akira Ransomware: Ngrok tunnel creation command detected

### Test Case 3: Trigona Ransomware - MS-SQL Brute Force

**Simulated Logs (10+ failed logins within 120 seconds):**
```
Login failed for user 'sa'. Reason: Password did not match.
Login failed for user 'admin'. Reason: Password did not match.
[... 8 more similar entries ...]
```

**Expected Alert:** Rule 100013 (Level 12) - Trigona Ransomware: MS-SQL brute force attack detected

### Test Case 4: LummaC2 - Chrome Credential File Access

**Simulated Log:**
```xml
<syscheck>
  <path>C:\Users\victim\AppData\Local\Google\Chrome\User Data\Default\Login Data</path>
  <size>262144</size>
  <mode>realtime</mode>
</syscheck>
```

**Expected Alert:** Rule 100042 (Level 12) - LummaC2 Stealer: Suspicious access to Chrome Login Data file

### Test Case 5: Mirai Botnet - Telnet Brute Force

**Simulated Logs (10+ telnet attempts within 60 seconds from same IP):**
```
telnet connection attempt from 203.0.113.100 to port 23
telnet connection attempt from 203.0.113.100 to port 23
[... 8 more similar entries ...]
```

**Expected Alert:** Rule 100066 (Level 12) - Mirai/Gafgyt Botnet: Telnet brute force attack detected

## Alert Severity Levels

| Level | Severity | Description | Response Time |
|-------|----------|-------------|---------------|
| 15 | Critical | Active infection/ransomware encryption | Immediate (< 5 min) |
| 14 | High | Confirmed malicious activity | Urgent (< 15 min) |
| 13 | High | Suspicious tool execution | High (< 30 min) |
| 12 | Medium-High | C2 communication detected | Medium (< 1 hour) |
| 10-11 | Medium | Suspicious behavior pattern | Normal (< 4 hours) |
| 5-9 | Low-Medium | Reconnaissance/failed attempts | Low (< 24 hours) |

## Integration with SIEM/SOAR

### Elastic Stack Integration

```json
{
  "rule_id": "100002",
  "threat_name": "Tomiris APT",
  "mitre_technique": "T1071.001",
  "severity": "high",
  "action": "alert",
  "destination": "api.telegram.org"
}
```

### Splunk Integration

```spl
index=wazuh rule.id=100002 OR rule.id=100003
| stats count by rule.description, agent.name, data.win.eventdata.destinationHostname
| where count > 1
```

### TheHive Case Creation

Alerts with severity level 14+ should automatically create incidents in TheHive with:
- Threat category
- MITRE ATT&CK techniques
- IOCs extracted from alert
- Recommended response actions

## Tuning and False Positive Mitigation

### Common False Positives

**Rule 100002 (Telegram API):**
- Legitimate Telegram Desktop application
- **Mitigation:** Add exclusion for official Telegram installation path
  ```xml
  <rule id="100002" level="0">
    <if_sid>100002</if_sid>
    <field name="win.eventdata.image">C:\\Program Files\\Telegram Desktop\\Telegram.exe</field>
    <description>Legitimate Telegram Desktop - excluded</description>
  </rule>
  ```

**Rule 100024 (Ngrok):**
- Developers using Ngrok for legitimate testing
- **Mitigation:** Whitelist known developer workstations or require Ngrok registration

**Rule 100042 (Chrome Login Data):**
- Password managers accessing browser credentials
- **Mitigation:** Whitelist known password manager processes (1Password, LastPass, Bitwarden)

**Rule 100065 (Telnet):**
- Legacy network equipment requiring Telnet management
- **Mitigation:** Whitelist specific management IP ranges

### Tuning Recommendations

1. **Environment Baseline:** Run rules in monitoring mode for 7-14 days to establish baseline
2. **Frequency Thresholds:** Adjust frequency-based rules based on environment size:
   - Small environment (< 100 hosts): Use default thresholds
   - Medium environment (100-1000 hosts): Increase thresholds by 25%
   - Large environment (> 1000 hosts): Increase thresholds by 50%

3. **Business-Specific Exclusions:**
   - Add whitelists for approved remote access tools
   - Exclude service accounts from brute force detection
   - Whitelist approved network scanning tools

## Performance Considerations

### Resource Impact

**CPU Impact:**
- Regex-heavy rules (100006, 100028, 100071): ~2-5% CPU increase per 1000 EPS
- Frequency-based rules (100013, 100066): ~1-2% CPU increase per 1000 EPS

**Memory Impact:**
- Each rule requires ~50-100KB memory
- Total ruleset: ~4-8MB memory footprint

**Recommendations:**
- Deploy incrementally (one threat category at a time)
- Monitor Wazuh manager performance after each deployment
- Consider rule consolidation if performance issues arise

## Monitoring and Maintenance

### Weekly Tasks
- Review alert volumes by rule ID
- Identify false positive patterns
- Update exclusion lists

### Monthly Tasks
- Review IOC lists and update hash/IP/domain indicators
- Analyze detection effectiveness metrics
- Tune frequency thresholds based on alert patterns

### Quarterly Tasks
- Review MITRE ATT&CK mappings against latest framework
- Update rules based on new threat intelligence
- Conduct purple team exercises to validate detection coverage

## Incident Response Playbooks

### Tomiris APT Detection (Rules 100001-100010)

**Immediate Actions:**
1. Isolate affected endpoint from network
2. Capture memory dump for forensic analysis
3. Block communication to identified C2 IPs/domains at firewall
4. Dump active network connections
5. Collect Sysmon and Windows Event logs

**Investigation:**
1. Identify initial access vector (email, download, etc.)
2. Review process tree for malicious process
3. Extract and analyze suspicious binaries
4. Search for lateral movement indicators
5. Identify compromised credentials

**Containment:**
1. Reset credentials for affected users
2. Apply network segmentation
3. Deploy endpoint isolation
4. Block C2 infrastructure globally

**Remediation:**
1. Remove malicious files and registry keys
2. Restore from clean backup if necessary
3. Patch vulnerabilities exploited for initial access
4. Deploy enhanced monitoring

### Trigona Ransomware Detection (Rules 100011-100023)

**Immediate Actions:**
1. Immediately isolate database servers
2. Kill active BCP.exe processes
3. Disconnect remote access tools (AnyDesk, ScreenConnect)
4. Enable database transaction log backups
5. Block MS-SQL port 1433 at perimeter firewall

**Investigation:**
1. Review SQL Server authentication logs
2. Identify compromised SQL accounts
3. Check for data exfiltration via BCP
4. Analyze remote access tool deployment timeline
5. Identify patient zero for brute force attacks

**Containment:**
1. Disable compromised SQL accounts
2. Remove unauthorized remote access tools
3. Implement IP allowlisting for SQL Server access
4. Deploy MFA for database authentication

**Remediation:**
1. Restore encrypted databases from backups
2. Harden SQL Server configuration
3. Implement principle of least privilege
4. Deploy database activity monitoring

### Akira Ransomware Detection (Rules 100024-100041)

**Immediate Actions:**
1. Terminate Ngrok processes immediately
2. Kill Mimikatz/LaZagne processes
3. Block Ngrok domains at DNS/firewall
4. Isolate affected systems
5. Preserve shadow copies if not yet deleted

**Investigation:**
1. Review credential dumping artifacts
2. Identify exfiltrated data via Ngrok tunnels
3. Check for lateral movement using dumped credentials
4. Analyze file encryption timeline
5. Identify ransom note contents and payment demands

**Containment:**
1. Reset all domain credentials
2. Revoke Kerberos tickets
3. Disable compromised accounts
4. Block Ngrok at network perimeter permanently
5. Implement application whitelisting

**Remediation:**
1. Restore encrypted files from backup
2. Rebuild compromised systems
3. Implement credential protection (Credential Guard)
4. Deploy LSASS protection mechanisms
5. Enable shadow copy deletion alerts

### LummaC2 Stealer Detection (Rules 100042-100059)

**Immediate Actions:**
1. Isolate infected endpoint
2. Block C2 communication at firewall
3. Capture browser profile directories
4. Dump active processes
5. Collect network traffic captures

**Investigation:**
1. Identify stolen credentials from browser databases
2. Review cryptocurrency wallet access
3. Analyze C2 exfiltration POST requests
4. Determine infection vector
5. Check for credential reuse across systems

**Containment:**
1. Force password reset for all browser-saved accounts
2. Revoke browser session tokens
3. Freeze cryptocurrency accounts if possible
4. Monitor for unauthorized access attempts
5. Deploy browser credential encryption

**Remediation:**
1. Remove stealer malware
2. Clear browser credential stores
3. Migrate to password manager
4. Enable 2FA on all accounts
5. Monitor dark web for credential leaks

### Mirai/Gafgyt Botnet Detection (Rules 100060-100079)

**Immediate Actions:**
1. Disconnect infected IoT devices from network
2. Block C2 IPs at perimeter firewall
3. Disable Telnet service on all devices
4. Kill malicious processes
5. Reset device to factory defaults if possible

**Investigation:**
1. Identify vulnerable devices via network scan
2. Review authentication logs for brute force sources
3. Analyze botnet binary samples
4. Determine DDoS targets
5. Identify propagation vectors

**Containment:**
1. Change default credentials on all IoT devices
2. Implement network segmentation for IoT VLAN
3. Block unnecessary outbound connections
4. Deploy rate limiting for authentication attempts
5. Disable unnecessary services (Telnet, TR-069)

**Remediation:**
1. Firmware update all IoT devices
2. Implement strong password policies
3. Deploy network-based intrusion prevention
4. Enable device hardening
5. Monitor for reinfection attempts

## Compliance Mapping

### PCI DSS v4.0
- Requirement 10.6.1: Review logs daily
- Requirement 11.4: Use intrusion detection systems
- All rules tagged with relevant PCI DSS requirements

### GDPR
- Article 32: Security of processing
- Article 35.7.d: Measures to protect personal data
- All rules tagged with GDPR compliance references

### NIST 800-53
- SI-4: System Monitoring
- AU-6: Audit Review, Analysis, and Reporting
- All rules mapped to NIST controls

## Support and Contact

For rule issues, false positives, or enhancement requests:
- Create GitHub issue with rule ID and log sample
- Include environment details (Wazuh version, OS, agent config)
- Provide alert output and expected behavior

## Version History

**Version 1.0** (2025-11-28)
- Initial release with 79 detection rules
- Coverage for 5 major threat categories
- MITRE ATT&CK framework alignment
- Compliance mapping (PCI DSS, GDPR, NIST)

## License

These detection rules are provided for use in production Wazuh environments. Modification and redistribution permitted with attribution.

---

**Last Updated:** 2025-11-28
**Author:** Wazuh Detection Engineering Team
**Threat Intelligence Source:** Multi-source threat research compilation
