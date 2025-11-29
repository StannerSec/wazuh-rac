# Wazuh Ruleset As Code

This repository contains my **Ruleset-as-Code** implementation for Wazuh. I wanted to run detection-as-code locally instead of through GitHub (which would require opening a port for remote access). The scripts use the Wazuh API to deploy rules and also call the API to verify whether alerts appear for those rules.

The **rules** repository contains custom rules developed through threat research. I use LLMs to support this process and make my rule development more agile.

The **scripts** repository includes two scripts: one to deploy rules via the API and another to query the Wazuh indexer. The deployment script checks the XML file for duplicate rule IDs, confirms that the template is functioning correctly, and then deploys the rules via the API. The query script uses the appropriate API endpoint to retrieve alerts.

---

## Usage

### Query the Wazuh Indexer

```bash
/your-directory/query_wazuh_indexer.sh [rule SID]
```

### Deploy a Rule via API

```bash
/your-directory/deploy_rule_via_api.sh /your/rule/file.xml
```

<img width="953" height="1012" alt="Screenshot from 2025-11-29 07-37-54" src="https://github.com/user-attachments/assets/d7431703-b6f0-43a4-8dce-ac27c79f312e" />
